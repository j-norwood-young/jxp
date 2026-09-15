const { expect } = require("chai");
const { generate, generateSecret } = require("otplib");
const totp = require("../dist/libs/totp");
const { DEFAULT_STRIP_FIELDS } = require("../dist/libs/response_sanitize");

describe("totp crypto", () => {
	const pepper = "unit-test-pepper-shared-secret";

	it("round-trips encrypted secrets", () => {
		const secret = generateSecret();
		const enc = totp.encryptSecret(secret, pepper);
		expect(enc).to.be.a("string");
		expect(enc).to.not.equal(secret);
		expect(totp.decryptSecret(enc, pepper)).to.equal(secret);
	});

	it("strips TOTP secret fields from default sanitize list", () => {
		expect(DEFAULT_STRIP_FIELDS).to.include("totp_secret_enc");
		expect(DEFAULT_STRIP_FIELDS).to.include("totp_pending_secret_enc");
		expect(DEFAULT_STRIP_FIELDS).to.include("totp_backup_hashes");
	});

	it("generates and verifies a live TOTP code", async () => {
		const secret = generateSecret();
		const token = await generate({ secret });
		const { verify } = require("otplib");
		const result = await verify({ token, secret, epochTolerance: 30 });
		expect(result.valid).to.equal(true);
	});
});
