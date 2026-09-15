import type {
	RegistrationResponseJSON,
	AuthenticationResponseJSON,
} from "@simplewebauthn/server";
import { getModelFromRegistry } from "./builtin_models";
import type { JXPConfig } from "../types/jxp-config";
import type { Model } from "mongoose";

const {
	generateRegistrationOptions,
	verifyRegistrationResponse,
	generateAuthenticationOptions,
	verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const mfaChallenge = require("./mfa_challenge");

let WebAuthnCredential: Model<unknown> | null = null;
let User: Model<unknown> | null = null;

type RequestLike = {
	headers?: Record<string, string | string[] | undefined>;
	isSecure?: () => boolean;
};

function headerValue(
	headers: RequestLike["headers"],
	name: string
): string | undefined {
	const raw = headers?.[name] ?? headers?.[name.toLowerCase()];
	if (Array.isArray(raw)) return raw[0];
	return typeof raw === "string" ? raw : undefined;
}

/** Resolve RP ID + allowed origins; optionally widen origins from the current request. */
function rpSettings(
	config: JXPConfig,
	req?: RequestLike
): { rpName: string; rpID: string; origins: string[] } {
	const baseUrl = config.url || "http://localhost:4001";
	let hostname = "localhost";
	try {
		hostname = new URL(baseUrl).hostname;
	} catch {
		/* keep default */
	}
	const rpID = config.webauthn?.rp_id || hostname;
	const origins = new Set<string>(
		config.webauthn?.origins && config.webauthn.origins.length
			? config.webauthn.origins
			: [baseUrl.replace(/\/$/, "")]
	);

	// Browsers put the page origin in clientDataJSON — allow localhost ↔ 127.0.0.1
	// and whatever Host the user actually opened, not only API_URL.
	const reqOrigin = headerValue(req?.headers, "origin");
	if (reqOrigin) origins.add(reqOrigin.replace(/\/$/, ""));
	const host = headerValue(req?.headers, "host");
	if (host) {
		const xfProto = headerValue(req?.headers, "x-forwarded-proto");
		const proto =
			xfProto?.split(",")[0]?.trim() ||
			(typeof req?.isSecure === "function" && req.isSecure() ? "https" : "http");
		origins.add(`${proto}://${host}`);
		if (host.startsWith("localhost")) {
			origins.add(`${proto}://${host.replace("localhost", "127.0.0.1")}`);
		} else if (host.startsWith("127.0.0.1")) {
			origins.add(`${proto}://${host.replace("127.0.0.1", "localhost")}`);
		}
	}

	return {
		rpName: config.webauthn?.rp_name || "JXP",
		rpID,
		origins: [...origins],
	};
}

function toBase64Url(buf: Uint8Array): string {
	return Buffer.from(buf).toString("base64url");
}

function fromBase64Url(s: string): Uint8Array {
	return new Uint8Array(Buffer.from(s, "base64url"));
}

export function init(models: Record<string, Model<unknown>>, _config: JXPConfig): void {
	WebAuthnCredential = getModelFromRegistry(models, "webauthncredential") as Model<unknown>;
	User = getModelFromRegistry(models, "user") as Model<unknown>;
}

export async function countForUser(user_id: unknown): Promise<number> {
	if (!WebAuthnCredential) throw new Error("webauthn not initialized");
	return WebAuthnCredential.countDocuments({ user_id }).exec();
}

export async function listCredentials(user_id: unknown): Promise<
	Array<{ id: string; name: string; createdAt?: Date; device_type?: string; backed_up?: boolean }>
> {
	if (!WebAuthnCredential) throw new Error("webauthn not initialized");
	const rows = (await WebAuthnCredential.find({ user_id })
		.select("_id name createdAt device_type backed_up")
		.lean()
		.exec()) as Array<{
		_id: unknown;
		name?: string;
		createdAt?: Date;
		device_type?: string;
		backed_up?: boolean;
	}>;
	return rows.map((r) => ({
		id: String(r._id),
		name: r.name || "Passkey",
		createdAt: r.createdAt,
		device_type: r.device_type,
		backed_up: r.backed_up,
	}));
}

export async function deleteCredential(
	user_id: unknown,
	credentialDocId: string,
	opts: { passwordConfirmed?: boolean; totpEnabled?: boolean } = {}
): Promise<void> {
	if (!WebAuthnCredential) throw new Error("webauthn not initialized");
	const remaining = await WebAuthnCredential.countDocuments({ user_id }).exec();
	const target = await WebAuthnCredential.findOne({ _id: credentialDocId, user_id }).exec();
	if (!target) throw new Error("Credential not found");

	const isLast = remaining <= 1;
	if (isLast && !opts.totpEnabled && !opts.passwordConfirmed) {
		throw new Error("password required to delete last passkey when TOTP is disabled");
	}

	await WebAuthnCredential.deleteOne({ _id: credentialDocId, user_id }).exec();
}

async function credentialsForUser(user_id: unknown) {
	if (!WebAuthnCredential) throw new Error("webauthn not initialized");
	return (await WebAuthnCredential.find({ user_id }).lean().exec()) as Array<{
		credential_id: string;
		public_key: string;
		counter: number;
		transports?: string[];
		_id: unknown;
		user_id: unknown;
	}>;
}

export async function beginRegistration(
	user: { _id: unknown; email?: string; name?: string },
	config: JXPConfig,
	req?: RequestLike
): Promise<{ options: unknown; challenge_token: string }> {
	const { rpName, rpID } = rpSettings(config, req);
	const existing = await credentialsForUser(user._id);
	const options = await generateRegistrationOptions({
		rpName,
		rpID,
		userName: user.email || String(user._id),
		userDisplayName: user.name || user.email || "User",
		userID: new TextEncoder().encode(String(user._id)),
		attestationType: "none",
		excludeCredentials: existing.map((c) => ({
			id: c.credential_id,
			transports: c.transports as string[] | undefined,
		})),
		// Discoverable credentials so "Login with Passkey" works without allowCredentials.
		authenticatorSelection: {
			residentKey: "required",
			userVerification: "preferred",
			requireResidentKey: true,
		},
	});
	const challenge_token = await mfaChallenge.issueWebAuthnChallenge({
		user_id: user._id,
		purpose: mfaChallenge.MFA_PURPOSES.webauthnRegister,
		webauthnChallenge: options.challenge,
		config,
	});
	return { options, challenge_token };
}

export async function finishRegistration(
	user_id: unknown,
	body: {
		challenge_token: string;
		response: RegistrationResponseJSON;
		name?: string;
	},
	config: JXPConfig,
	req?: RequestLike
): Promise<{ id: string; name: string }> {
	if (!WebAuthnCredential) throw new Error("webauthn not initialized");
	const { origins, rpID } = rpSettings(config, req);
	const consumed = await mfaChallenge.consumeWebAuthnChallenge(
		body.challenge_token,
		mfaChallenge.MFA_PURPOSES.webauthnRegister
	);
	if (consumed.user_id && consumed.user_id !== String(user_id)) {
		throw new Error("WebAuthn challenge user mismatch");
	}
	let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
	try {
		verification = await verifyRegistrationResponse({
			response: body.response,
			expectedChallenge: consumed.webauthnChallenge,
			expectedOrigin: origins,
			expectedRPID: rpID,
			requireUserVerification: false,
		});
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		console.error(new Date().toISOString(), "WebAuthn registration verify failed:", message);
		throw err;
	}
	if (!verification.verified || !verification.registrationInfo) {
		throw new Error("Passkey registration failed");
	}
	const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
	const name = body.name || "Passkey";
	const record = await WebAuthnCredential.create({
		user_id,
		credential_id: credential.id,
		public_key: toBase64Url(credential.publicKey),
		counter: credential.counter,
		transports: credential.transports,
		device_type: credentialDeviceType,
		backed_up: credentialBackedUp,
		name,
	});
	return { id: String((record as { _id: unknown })._id), name };
}

export async function beginAuthentication(
	opts: { email?: string; user_id?: unknown },
	config: JXPConfig,
	req?: RequestLike
): Promise<{ options: unknown; challenge_token: string }> {
	if (!User || !WebAuthnCredential) throw new Error("webauthn not initialized");
	const { rpID } = rpSettings(config, req);
	let user_id = opts.user_id;
	let allowCredentials: { id: string; transports?: string[] }[] | undefined;

	if (opts.email) {
		const user = (await User.findOne({ email: String(opts.email).toLowerCase() })
			.select("_id")
			.lean()
			.exec()) as { _id: unknown } | null;
		if (!user) {
			// Return a generic challenge so we don't leak whether the email exists.
			const options = await generateAuthenticationOptions({
				rpID,
				userVerification: "preferred",
			});
			const challenge_token = await mfaChallenge.issueWebAuthnChallenge({
				purpose: mfaChallenge.MFA_PURPOSES.webauthnAuth,
				webauthnChallenge: options.challenge,
				config,
			});
			return { options, challenge_token };
		}
		user_id = user._id;
	}

	if (user_id) {
		const creds = await credentialsForUser(user_id);
		// Non-empty allowCredentials helps security keys that are not discoverable.
		// Omit the field entirely when empty so the browser can use discoverable passkeys.
		if (creds.length) {
			allowCredentials = creds.map((c) => ({
				id: c.credential_id,
				transports: c.transports as string[] | undefined,
			}));
		}
	}

	const options = await generateAuthenticationOptions({
		rpID,
		allowCredentials,
		userVerification: "preferred",
	});
	const challenge_token = await mfaChallenge.issueWebAuthnChallenge({
		user_id,
		purpose: mfaChallenge.MFA_PURPOSES.webauthnAuth,
		webauthnChallenge: options.challenge,
		config,
	});
	return { options, challenge_token };
}

export async function finishAuthentication(
	body: {
		challenge_token: string;
		response: AuthenticationResponseJSON;
	},
	config: JXPConfig,
	req?: RequestLike
): Promise<{ user_id: string }> {
	if (!WebAuthnCredential) throw new Error("webauthn not initialized");
	const { origins, rpID } = rpSettings(config, req);
	const consumed = await mfaChallenge.consumeWebAuthnChallenge(
		body.challenge_token,
		mfaChallenge.MFA_PURPOSES.webauthnAuth
	);
	const response = normalizeAssertionResponse(body.response);
	const credId = response?.id;
	if (!credId) throw new Error("Missing credential id");

	const record = (await WebAuthnCredential.findOne({ credential_id: credId }).exec()) as unknown as {
		_id: unknown;
		user_id: unknown;
		credential_id: string;
		public_key: string;
		counter: number;
		transports?: string[];
	} | null;
	if (!record) throw new Error("Unknown passkey");

	if (consumed.user_id && consumed.user_id !== String(record.user_id)) {
		throw new Error("Passkey does not match challenge user");
	}

	let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
	const clientMeta = peekClientDataMeta(response);
	try {
		const verifyOpts: Record<string, unknown> = {
			response,
			expectedChallenge: consumed.webauthnChallenge,
			expectedOrigin: origins,
			expectedRPID: rpID,
			requireUserVerification: false,
			credential: {
				id: record.credential_id,
				publicKey: fromBase64Url(record.public_key),
				counter: record.counter,
				transports: record.transports as string[] | undefined,
			},
		};
		// Only set when the browser marked the ceremony cross-origin (SimpleWebAuthn v14).
		if (clientMeta.crossOrigin && clientMeta.topOrigin) {
			verifyOpts.expectedTopOrigin = origins;
		}
		verification = await verifyAuthenticationResponse(verifyOpts);
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		console.error(new Date().toISOString(), "WebAuthn authentication verify failed:", message, {
			expectedOrigin: origins,
			expectedRPID: rpID,
			clientOrigin: clientMeta.origin,
			crossOrigin: clientMeta.crossOrigin,
			topOrigin: clientMeta.topOrigin,
			credential_id: credId.slice(0, 12) + "…",
		});
		throw err;
	}
	if (!verification.verified) {
		throw new Error("Passkey authentication failed");
	}
	await WebAuthnCredential.updateOne(
		{ _id: record._id },
		{ $set: { counter: verification.authenticationInfo.newCounter } }
	).exec();
	return { user_id: String(record.user_id) };
}

/** Ensure id/rawId are matching base64url strings (SimpleWebAuthn v14 requires id === rawId). */
function normalizeAssertionResponse(
	response: AuthenticationResponseJSON | undefined
): AuthenticationResponseJSON {
	if (!response) {
		throw new Error("Missing credential response");
	}
	const id = response.id;
	const rawId = response.rawId || id;
	if (!id) throw new Error("Missing credential id");
	return {
		...response,
		id,
		rawId: rawId === id ? rawId : id,
		type: response.type || "public-key",
		clientExtensionResults: response.clientExtensionResults || {},
		response: response.response,
	};
}

function peekClientDataMeta(response: AuthenticationResponseJSON): {
	origin?: string;
	crossOrigin?: boolean;
	topOrigin?: string;
} {
	try {
		const { decodeClientDataJSON } = require("@simplewebauthn/server/helpers");
		const data = decodeClientDataJSON(response.response.clientDataJSON);
		return {
			origin: data.origin,
			crossOrigin: Boolean(data.crossOrigin),
			topOrigin: data.topOrigin,
		};
	} catch {
		return {};
	}
}

module.exports = {
	init,
	countForUser,
	listCredentials,
	deleteCredential,
	beginRegistration,
	finishRegistration,
	beginAuthentication,
	finishAuthentication,
};
