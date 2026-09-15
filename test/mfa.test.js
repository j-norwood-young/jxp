process.env.NODE_ENV = "test";

const chai = require("chai");
const chaiHttp = require("chai-http");
const { expect } = chai;
const { generate } = require("otplib");
const init = require("./init");
const server = require("../dist/bin/server");
const mfaChallenge = require("../dist/libs/mfa_challenge");
const webauthn = require("../dist/libs/webauthn");

chai.use(chaiHttp);

describe("MFA TOTP + WebAuthn challenges", function () {
	this.timeout(15000);

	let token = null;
	let userId = null;
	let backupCodes = null;
	let totpSecret = null;

	before(async function () {
		await init.empty_user_collections();
		await new Promise((resolve, reject) => {
			chai
				.request(server)
				.post("/setup")
				.send({ email: init.email, password: init.password })
				.end((err, res) => {
					if (err) return reject(err);
					expect(res).to.have.status(200);
					resolve();
				});
		});
		const loginRes = await chai
			.request(server)
			.post("/login")
			.send({ email: init.email, password: init.password });
		expect(loginRes).to.have.status(200);
		token = loginRes.body.token;
		userId = loginRes.body.user_id;
	});

	it("enrolls and confirms TOTP", async () => {
		const setupRes = await chai
			.request(server)
			.post("/login/totp/setup")
			.set("Authorization", `Bearer ${token}`);
		expect(setupRes).to.have.status(200);
		expect(setupRes.body).to.have.property("otpauth_url");
		expect(setupRes.body).to.have.property("secret");
		expect(setupRes.body).to.have.property("qr_data_url");
		expect(setupRes.body.qr_data_url).to.match(/^data:image\/png;base64,/);
		expect(setupRes.body.backup_codes).to.be.an("array").with.lengthOf(10);
		totpSecret = setupRes.body.secret;
		backupCodes = setupRes.body.backup_codes;

		const code = await generate({ secret: totpSecret });
		const confirmRes = await chai
			.request(server)
			.post("/login/totp/confirm")
			.set("Authorization", `Bearer ${token}`)
			.send({ code });
		expect(confirmRes).to.have.status(200);
		expect(confirmRes.body.enabled).to.equal(true);

		const statusRes = await chai
			.request(server)
			.get("/login/totp/status")
			.set("Authorization", `Bearer ${token}`);
		expect(statusRes.body.enabled).to.equal(true);
	});

	it("password login returns mfa_required then completes with code", async () => {
		const loginRes = await chai
			.request(server)
			.post("/login")
			.send({ email: init.email, password: init.password });
		expect(loginRes).to.have.status(200);
		expect(loginRes.body.status).to.equal("mfa_required");
		expect(loginRes.body.challenge).to.be.a("string");
		expect(loginRes.body.methods).to.deep.equal(["totp"]);
		expect(loginRes.body.methods).to.not.include("webauthn");
		expect(loginRes.body).to.not.have.property("token");

		const bad = await chai
			.request(server)
			.post("/login/mfa")
			.send({ challenge: loginRes.body.challenge, code: "000000" });
		expect(bad).to.have.status(401);

		const code = await generate({ secret: totpSecret });
		const ok = await chai
			.request(server)
			.post("/login/mfa")
			.send({
				method: "totp",
				challenge: loginRes.body.challenge,
				code,
			});
		expect(ok).to.have.status(200);
		expect(ok.body).to.have.property("token");
		expect(ok.body).to.have.property("refresh_token");
		token = ok.body.token;
	});

	it("rejects replay of a consumed MFA challenge", async () => {
		const loginRes = await chai
			.request(server)
			.post("/login")
			.send({ email: init.email, password: init.password });
		expect(loginRes.body.status).to.equal("mfa_required");
		const code = await generate({ secret: totpSecret });
		const first = await chai
			.request(server)
			.post("/login/mfa")
			.send({ challenge: loginRes.body.challenge, code });
		expect(first).to.have.status(200);
		token = first.body.token;

		const replay = await chai
			.request(server)
			.post("/login/mfa")
			.send({ challenge: loginRes.body.challenge, code });
		expect(replay).to.have.status(401);
	});

	it("refresh still works after MFA login", async () => {
		const loginRes = await chai
			.request(server)
			.post("/login")
			.send({ email: init.email, password: init.password });
		const code = await generate({ secret: totpSecret });
		const mfa = await chai
			.request(server)
			.post("/login/mfa")
			.send({ challenge: loginRes.body.challenge, code });
		expect(mfa.body.refresh_token).to.be.a("string");

		const refreshed = await chai
			.request(server)
			.post("/refresh")
			.set("Authorization", `Bearer ${mfa.body.refresh_token}`);
		expect(refreshed).to.have.status(200);
		expect(refreshed.body.token).to.be.a("string");
		token = refreshed.body.token;
	});

	it("issues webauthn registration options for authenticated user", async () => {
		const res = await chai
			.request(server)
			.post("/login/webauthn/register/options")
			.set("Authorization", `Bearer ${token}`);
		expect(res).to.have.status(200);
		expect(res.body.options).to.have.property("challenge");
		expect(res.body.challenge_token).to.be.a("string");
	});

	it("issues passwordless webauthn options", async () => {
		const res = await chai
			.request(server)
			.post("/login/webauthn/options")
			.send({ email: init.email });
		expect(res).to.have.status(200);
		expect(res.body.options).to.have.property("challenge");
		expect(res.body.challenge_token).to.be.a("string");
	});

	it("disables TOTP with a backup code", async () => {
		const code = backupCodes[0];
		const res = await chai
			.request(server)
			.post("/login/totp/disable")
			.set("Authorization", `Bearer ${token}`)
			.send({ code });
		expect(res).to.have.status(200);
		expect(res.body.enabled).to.equal(false);

		const loginRes = await chai
			.request(server)
			.post("/login")
			.send({ email: init.email, password: init.password });
		expect(loginRes.body).to.have.property("token");
		expect(loginRes.body).to.not.have.property("status");
	});

	it("mfa challenge helpers reject bad tokens", async () => {
		try {
			mfaChallenge.peekMfaChallenge("not-a-jwt");
			expect.fail("should throw");
		} catch (err) {
			expect(err.message).to.match(/Invalid|expired/i);
		}
	});

	it("webauthn count starts at zero", async () => {
		const n = await webauthn.countForUser(userId);
		expect(n).to.equal(0);
	});
});
