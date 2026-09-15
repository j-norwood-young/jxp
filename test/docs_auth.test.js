const { expect } = require("chai");
const errors = require("restify-errors");
const jwt = require("jsonwebtoken");
const chai = require("chai");
const chaiHttp = require("chai-http");
const should = chai.should();

const docsAuth = require("../dist/libs/docs-auth");
const { DOCS_SESSION_COOKIE } = docsAuth;
const init = require("./init");

chai.use(chaiHttp);

const server = require("../dist/bin/server");

function mockReq(overrides = {}) {
	return {
		path: () => "/docs/api",
		method: "GET",
		headers: {},
		config: {
			shared_secret: process.env.SHARED_SECRET || "change-me",
			docs: { access: "protected" },
		},
		...overrides,
	};
}

/** Establish a docs session using the docs login flow. */
function docsLogin(agent, done) {
	agent
		.post("/docs/session")
		.send({ email: init.email, password: init.password })
		.end((err, loginRes) => {
			loginRes.should.have.status(200);
			loginRes.body.should.have.property("console_key");
			loginRes.body.should.have.property("csrf_token");
			done();
		});
}

describe("docs_auth", () => {
	describe("parseDocsAccess", () => {
		it("defaults to protected", () => {
			expect(docsAuth.parseDocsAccess()).to.equal("protected");
		});

		it("parses disabled and public", () => {
			expect(docsAuth.parseDocsAccess("disabled")).to.equal("disabled");
			expect(docsAuth.parseDocsAccess("public")).to.equal("public");
		});
	});

	describe("isProtectedDocsPath", () => {
		it("gates model metadata and account routes", () => {
			expect(docsAuth.isProtectedDocsPath("/docs/api")).to.be.true;
			expect(docsAuth.isProtectedDocsPath("/docs/mcp")).to.be.true;
			expect(docsAuth.isProtectedDocsPath("/docs/mcp/call")).to.be.true;
			expect(docsAuth.isProtectedDocsPath("/docs/model/user")).to.be.true;
			expect(docsAuth.isProtectedDocsPath("/model")).to.be.true;
			expect(docsAuth.isProtectedDocsPath("/model/user")).to.be.true;
			expect(docsAuth.isProtectedDocsPath("/docs/account/keys")).to.be.true;
			expect(docsAuth.isProtectedDocsPath("/")).to.be.false;
			expect(docsAuth.isProtectedDocsPath("/docs/md/api.md")).to.be.false;
			expect(docsAuth.isProtectedDocsPath("/docs/login")).to.be.false;
		});
	});

	describe("docsAccessMiddleware", () => {
		it("passes through non-protected paths", (done) => {
			const req = mockReq({ path: () => "/" });
			docsAuth.docsAccessMiddleware(req, {}, (err) => {
				expect(err).to.be.undefined;
				done();
			});
		});

		it("returns 404 when disabled", (done) => {
			const req = mockReq({ config: { docs: { access: "disabled" } } });
			docsAuth.docsAccessMiddleware(req, {}, (err) => {
				err.should.be.instanceof(errors.NotFoundError);
				done();
			});
		});

		it("redirects unauthenticated GET on /docs/api", (done) => {
			const req = mockReq();
			const res = {
				redirect(code, url, next) {
					code.should.equal(302);
					url.should.include("/docs/login");
					url.should.include("next=%2Fdocs%2Fapi");
					next();
				},
			};
			docsAuth.docsAccessMiddleware(req, res, (err) => {
				expect(err).to.be.undefined;
				done();
			});
		});
	});

	describe("verifyDocsSession", () => {
		before(() => {
			docsAuth.init({ shared_secret: process.env.SHARED_SECRET || "change-me" });
		});

		it("returns payload for a valid session cookie", () => {
			const secret = process.env.SHARED_SECRET || "change-me";
			const token = jwt.sign(
				{ user_id: "abc", email: init.email, console_key_id: "key-123" },
				secret,
				{ expiresIn: 3600 },
			);
			const req = mockReq({
				headers: { cookie: `${DOCS_SESSION_COOKIE}=${encodeURIComponent(token)}` },
			});
			const session = docsAuth.verifyDocsSession(req);
			session.should.have.property("console_key_id", "key-123");
		});
	});

	describe("HTTP integration", () => {
		before(async function () {
			this.timeout(10000);
			await init.init();
		});

		it("serves home and guides without a session", (done) => {
			chai.request(server)
				.get("/")
				.end((err, home) => {
					home.should.have.status(200);
					chai.request(server)
						.get("/docs/md/api.md")
						.end((err2, guide) => {
							guide.should.have.status(200);
							done();
						});
				});
		});

		it("redirects /docs/api to login without a session", (done) => {
			chai.request(server)
				.get("/docs/api")
				.redirects(0)
				.end((err, res) => {
					res.should.have.status(302);
					res.header.location.should.include("/docs/login");
					done();
				});
		});

		it("logs in via /docs/session and reaches /docs/api", (done) => {
			const agent = chai.request.agent(server);
			docsLogin(agent, () => {
				agent
					.get("/docs/session")
					.end((err, sess) => {
						sess.should.have.status(200);
						sess.body.should.have.property("authenticated", true);
						agent
							.get("/docs/api")
							.end((err2, page) => {
								page.should.have.status(200);
								page.text.should.include("API reference");
								done();
							});
					});
			});
		});

		it("serves account settings and changes password via console key", (done) => {
			const agent = chai.request.agent(server);
			const security = require("../dist/libs/security");
			const path = require("path");
			const User = require(path.join(__dirname, "../dist/models/user_model.js")).default
				|| require(path.join(__dirname, "../dist/models/user_model.js"));
			agent
				.post("/docs/session")
				.send({ email: init.email, password: init.password })
				.end((err, loginRes) => {
					if (err) return done(err);
					loginRes.should.have.status(200);
					const consoleKey = loginRes.body.console_key;
					agent
						.get("/docs/account/settings")
						.end((err2, page) => {
							if (err2) return done(err2);
							page.should.have.status(200);
							page.text.should.include("Account settings");
							page.text.should.include("Authenticator app");
							page.text.should.include("Passkeys");
							chai
								.request(server)
								.post("/login/password")
								.set("X-API-Key", consoleKey)
								.send({
									current_password: init.password,
									new_password: "test-password-2",
								})
								.end(async (err3, changed) => {
									try {
										if (err3) return done(err3);
										changed.should.have.status(200);
										// Restore short test password directly (endpoint requires 8+ chars).
										await User.updateOne(
											{ email: init.email },
											{ $set: { password: security.encPassword(init.password) } },
										);
										done();
									} catch (e) {
										done(e);
									}
								});
						});
				});
		});

		it("rejects /docs/session without a cookie", (done) => {
			chai.request(server)
				.get("/docs/session")
				.end((err, res) => {
					res.should.have.status(401);
					done();
				});
		});

		it("rejects establishSession with invalid credentials", (done) => {
			chai.request(server)
				.post("/docs/session")
				.send({ email: init.email, password: "not-a-real-password" })
				.end((err, res) => {
					res.should.have.status(401);
					done();
				});
		});

		it("issues docs passkey login options without a session", (done) => {
			chai.request(server)
				.post("/docs/session/webauthn/options")
				.send({ email: init.email })
				.end((err, res) => {
					try {
						if (err) return done(err);
						res.should.have.status(200);
						res.body.should.have.property("options");
						res.body.options.should.have.property("challenge");
						res.body.should.have.property("challenge_token");
						done();
					} catch (e) {
						done(e);
					}
				});
		});

		it("returns console_key_id from session and invalidates when the key is revoked", (done) => {
			const agent = chai.request.agent(server);
			const apikeys = require("../dist/libs/apikeys");
			agent
				.post("/docs/session")
				.send({ email: init.email, password: init.password })
				.end((err, loginRes) => {
					if (err) return done(err);
					loginRes.should.have.status(200);
					loginRes.body.should.have.property("console_key_id");
					const keyId = loginRes.body.console_key_id;
					agent
						.get("/docs/session")
						.end(async (err2, sess) => {
							try {
								if (err2) return done(err2);
								sess.should.have.status(200);
								sess.body.should.have.property("authenticated", true);
								sess.body.should.have.property("console_key_id", keyId);

								const cookieHeader = loginRes.headers["set-cookie"];
								should.exist(cookieHeader);
								const raw = [].concat(cookieHeader).find((c) =>
									c.startsWith(`${DOCS_SESSION_COOKIE}=`),
								);
								const token = decodeURIComponent(raw.split("=")[1].split(";")[0]);
								const payload = jwt.verify(
									token,
									process.env.SHARED_SECRET || "change-me",
								);
								await apikeys.revokeApiKey(payload.user_id, keyId);

								agent
									.get("/docs/session")
									.end((err3, dead) => {
										if (err3) return done(err3);
										dead.should.have.status(401);
										done();
									});
							} catch (e) {
								done(e);
							}
						});
				});
		});

		it("allows concurrent docs sessions in separate browsers", (done) => {
			const browserA = chai.request.agent(server);
			const browserB = chai.request.agent(server);
			browserA
				.post("/docs/session")
				.send({ email: init.email, password: init.password })
				.end((err, loginA) => {
					if (err) return done(err);
					loginA.should.have.status(200);
					const keyA = loginA.body.console_key_id;
					browserB
						.post("/docs/session")
						.send({ email: init.email, password: init.password })
						.end((err2, loginB) => {
							if (err2) return done(err2);
							loginB.should.have.status(200);
							loginB.body.console_key_id.should.not.equal(keyA);
							browserA
								.get("/docs/session")
								.end((err3, sessA) => {
									if (err3) return done(err3);
									sessA.should.have.status(200);
									sessA.body.should.have.property("authenticated", true);
									sessA.body.should.have.property("console_key_id", keyA);
									browserB
										.get("/docs/session")
										.end((err4, sessB) => {
											if (err4) return done(err4);
											sessB.should.have.status(200);
											sessB.body.should.have.property("authenticated", true);
											sessB.body.should.have.property(
												"console_key_id",
												loginB.body.console_key_id,
											);
											done();
										});
								});
						});
				});
		});
	});
});
