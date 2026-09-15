import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import { getModelFromRegistry } from "./builtin_models";
import type { JXPConfig } from "../types/jxp-config";
import type { Model } from "mongoose";

let AuthChallenge: Model<unknown> | null = null;
let sharedSecret = "";

const PURPOSE_MFA = "mfa-challenge";
const PURPOSE_WEBAUTHN_REG = "webauthn-register";
const PURPOSE_WEBAUTHN_AUTH = "webauthn-auth";

export const MFA_PURPOSES = {
	mfa: PURPOSE_MFA,
	webauthnRegister: PURPOSE_WEBAUTHN_REG,
	webauthnAuth: PURPOSE_WEBAUTHN_AUTH,
} as const;

function hashJti(jti: string): string {
	return crypto.createHmac("sha256", sharedSecret || "jxp").update(jti).digest("hex");
}

function challengeTtl(config: JXPConfig): string {
	return config.mfa?.challenge_ttl || "5m";
}

function ttlToMs(ttl: string): number {
	const m = /^(\d+)([smhd])$/i.exec(ttl.trim());
	if (!m) return 5 * 60 * 1000;
	const n = parseInt(m[1], 10);
	const unit = m[2].toLowerCase();
	const mult = unit === "s" ? 1000 : unit === "m" ? 60_000 : unit === "h" ? 3_600_000 : 86_400_000;
	return n * mult;
}

export function init(models: Record<string, Model<unknown>>, config: JXPConfig): void {
	AuthChallenge = getModelFromRegistry(models, "authchallenge") as Model<unknown>;
	sharedSecret = config.shared_secret || process.env.SHARED_SECRET || "";
}

async function storeChallenge(opts: {
	jti: string;
	user_id?: unknown;
	purpose: string;
	payload?: string;
	ttlMs: number;
}): Promise<void> {
	if (!AuthChallenge) throw new Error("mfa_challenge not initialized");
	await AuthChallenge.create({
		jti_hash: hashJti(opts.jti),
		user_id: opts.user_id,
		purpose: opts.purpose,
		payload: opts.payload,
		expire_at: new Date(Date.now() + opts.ttlMs),
	});
}

export async function issueMfaChallenge(
	user_id: unknown,
	config: JXPConfig
): Promise<string> {
	if (!sharedSecret) throw new Error("shared_secret is required for MFA challenges");
	const jti = crypto.randomBytes(24).toString("base64url");
	const ttl = challengeTtl(config);
	await storeChallenge({
		jti,
		user_id,
		purpose: PURPOSE_MFA,
		ttlMs: ttlToMs(ttl),
	});
	return jwt.sign(
		{ purpose: PURPOSE_MFA, user_id: String(user_id), jti },
		sharedSecret,
		{ expiresIn: ttl as jwt.SignOptions["expiresIn"] }
	);
}

export async function consumeMfaChallenge(
	token: string,
	config: JXPConfig
): Promise<{ user_id: string }> {
	if (!AuthChallenge) throw new Error("mfa_challenge not initialized");
	if (!sharedSecret) throw new Error("shared_secret is required for MFA challenges");
	let payload: { purpose?: string; user_id?: string; jti?: string };
	try {
		payload = jwt.verify(token, sharedSecret) as typeof payload;
	} catch {
		throw new Error("Invalid or expired MFA challenge");
	}
	if (payload.purpose !== PURPOSE_MFA || !payload.user_id || !payload.jti) {
		throw new Error("Invalid MFA challenge");
	}
	const deleted = await AuthChallenge.findOneAndDelete({
		jti_hash: hashJti(payload.jti),
		purpose: PURPOSE_MFA,
	}).exec();
	if (!deleted) {
		throw new Error("MFA challenge already used or expired");
	}
	return { user_id: payload.user_id };
}

/** Peek MFA challenge without consuming (for building WebAuthn options during MFA). */
export function peekMfaChallenge(token: string): { user_id: string; jti: string } {
	if (!sharedSecret) throw new Error("shared_secret is required for MFA challenges");
	let payload: { purpose?: string; user_id?: string; jti?: string };
	try {
		payload = jwt.verify(token, sharedSecret) as typeof payload;
	} catch {
		throw new Error("Invalid or expired MFA challenge");
	}
	if (payload.purpose !== PURPOSE_MFA || !payload.user_id || !payload.jti) {
		throw new Error("Invalid MFA challenge");
	}
	return { user_id: payload.user_id, jti: payload.jti };
}

export async function issueWebAuthnChallenge(opts: {
	user_id?: unknown;
	purpose: typeof PURPOSE_WEBAUTHN_REG | typeof PURPOSE_WEBAUTHN_AUTH;
	webauthnChallenge: string;
	config: JXPConfig;
}): Promise<string> {
	if (!sharedSecret) throw new Error("shared_secret is required for WebAuthn challenges");
	const jti = crypto.randomBytes(24).toString("base64url");
	const ttl = challengeTtl(opts.config);
	await storeChallenge({
		jti,
		user_id: opts.user_id,
		purpose: opts.purpose,
		payload: opts.webauthnChallenge,
		ttlMs: ttlToMs(ttl),
	});
	return jwt.sign(
		{
			purpose: opts.purpose,
			user_id: opts.user_id ? String(opts.user_id) : undefined,
			jti,
		},
		sharedSecret,
		{ expiresIn: ttl as jwt.SignOptions["expiresIn"] }
	);
}

export async function consumeWebAuthnChallenge(
	token: string,
	expectedPurpose: typeof PURPOSE_WEBAUTHN_REG | typeof PURPOSE_WEBAUTHN_AUTH
): Promise<{ user_id?: string; webauthnChallenge: string }> {
	if (!AuthChallenge) throw new Error("mfa_challenge not initialized");
	if (!sharedSecret) throw new Error("shared_secret is required for WebAuthn challenges");
	let payload: { purpose?: string; user_id?: string; jti?: string };
	try {
		payload = jwt.verify(token, sharedSecret) as typeof payload;
	} catch {
		throw new Error("Invalid or expired WebAuthn challenge");
	}
	if (payload.purpose !== expectedPurpose || !payload.jti) {
		throw new Error("Invalid WebAuthn challenge");
	}
	const deleted = await AuthChallenge.findOneAndDelete({
		jti_hash: hashJti(payload.jti),
		purpose: expectedPurpose,
	}).exec();
	if (!deleted || !(deleted as unknown as { payload?: string }).payload) {
		throw new Error("WebAuthn challenge already used or expired");
	}
	return {
		user_id: payload.user_id,
		webauthnChallenge: (deleted as unknown as { payload: string }).payload,
	};
}

module.exports = {
	init,
	issueMfaChallenge,
	consumeMfaChallenge,
	peekMfaChallenge,
	issueWebAuthnChallenge,
	consumeWebAuthnChallenge,
	MFA_PURPOSES,
};
