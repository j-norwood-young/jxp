import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import path from "path";
import errors from "restify-errors";
import type { JXPConfig, JXPRequest, JXPResponse } from "../types/jxp-config";
import type { Model } from "mongoose";

export type DocsAccess = "protected" | "disabled" | "public";

export const DOCS_SESSION_COOKIE = "jxp_docs_session";
export const DOCS_CSRF_COOKIE = "jxp_docs_csrf";
const SESSION_MAX_AGE_SEC = 86400;

export interface DocsSessionPayload {
	user_id: string;
	email: string;
	console_key_id?: string;
}

let sharedSecret: string | undefined;
let modelRegistry: Record<string, Model<unknown>> = {};
let cookieSecure = false;

export function parseDocsAccess(raw?: string): DocsAccess {
	const v = (raw ?? "protected").toLowerCase().trim();
	if (v === "disabled" || v === "off" || v === "false" || v === "0") return "disabled";
	if (v === "public" || v === "open") return "public";
	return "protected";
}

export function getDocsAccess(config: JXPConfig): DocsAccess {
	return config.docs?.access ?? "protected";
}

/** Routes that require a docs session (model browser + interactive API). */
export function isProtectedDocsPath(pathname: string): boolean {
	return (
		pathname === "/docs/api" ||
		pathname === "/docs/mcp" ||
		pathname.startsWith("/docs/model/") ||
		pathname === "/docs/diagnostics" ||
		pathname === "/docs/mcp/call"
		|| pathname === "/model"
		|| pathname.startsWith("/model/")
		|| pathname === "/docs/account"
		|| pathname.startsWith("/docs/account/")
	);
}

export function isDocsLoginPath(pathname: string): boolean {
	return pathname === "/docs/login";
}

export function safeNextPath(value: unknown, fallback = "/docs/api"): string {
	return typeof value === "string" &&
		/^\/(?![\/\\])/.test(value) &&
		!value.includes("\\") &&
		!/[^\x20-\x7e]/.test(value)
		? value
		: fallback;
}

function parseCookies(header: string | undefined): Record<string, string> {
	if (!header) return {};
	return header.split(";").reduce<Record<string, string>>((acc, part) => {
		const idx = part.indexOf("=");
		if (idx === -1) return acc;
		const key = part.slice(0, idx).trim();
		const val = part.slice(idx + 1).trim();
		if (key) acc[key] = decodeURIComponent(val);
		return acc;
	}, {});
}

export function verifyDocsSession(req: JXPRequest): DocsSessionPayload | null {
	if (!sharedSecret) return null;
	const cookies = parseCookies(req.headers.cookie as string | undefined);
	const token = cookies[DOCS_SESSION_COOKIE];
	if (!token) return null;
	try {
		return jwt.verify(token, sharedSecret) as DocsSessionPayload;
	} catch {
		return null;
	}
}

async function consoleKeyStillActive(session: DocsSessionPayload): Promise<boolean> {
	if (!session.console_key_id) return false;
	const apikeys = require("./apikeys");
	const record = await apikeys.findActiveApiKeyById(session.user_id, session.console_key_id);
	return Boolean(record);
}

/**
 * JWT session plus live ephemeral "Docs console" API key.
 * Clears the cookie when the key was revoked or expired.
 */
export async function resolveValidDocsSession(
	req: JXPRequest,
	res?: JXPResponse,
): Promise<DocsSessionPayload | null> {
	const session = verifyDocsSession(req);
	if (!session) return null;
	if (await consoleKeyStillActive(session)) return session;
	if (res) clearSessionCookie(res);
	return null;
}

function signDocsSession(payload: DocsSessionPayload): string {
	if (!sharedSecret) throw new Error("SHARED_SECRET is required for docs session");
	return jwt.sign(payload, sharedSecret, { expiresIn: SESSION_MAX_AGE_SEC });
}

function setSessionCookie(res: JXPResponse, token: string, csrf?: string): void {
	const secure = cookieSecure || process.env.DOCS_COOKIE_SECURE === "1" ||
		process.env.DOCS_COOKIE_SECURE === "true" ||
		false;
	const parts = [
		`${DOCS_SESSION_COOKIE}=${encodeURIComponent(token)}`,
		"Path=/",
		"HttpOnly",
		"SameSite=Lax",
		`Max-Age=${SESSION_MAX_AGE_SEC}`,
	];
	if (secure) parts.push("Secure");
	const cookies = [parts.join("; ")];
	if (csrf) {
		cookies.push([
			`${DOCS_CSRF_COOKIE}=${encodeURIComponent(csrf)}`,
			"Path=/",
			"SameSite=Lax",
			`Max-Age=${SESSION_MAX_AGE_SEC}`,
		].join("; "));
	}
	(res as any).header("Set-Cookie", cookies);
}

function clearSessionCookie(res: JXPResponse): void {
	(res as any).header(
		"Set-Cookie",
		[
			`${DOCS_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
			`${DOCS_CSRF_COOKIE}=; Path=/; SameSite=Lax; Max-Age=0`,
		],
	);
}

function csrfToken(req: JXPRequest): string | undefined {
	const cookies = parseCookies(req.headers.cookie as string | undefined);
	const header = req.headers["x-csrf-token"] || req.headers["X-CSRF-Token"];
	return cookies[DOCS_CSRF_COOKIE] && typeof header === "string" && cookies[DOCS_CSRF_COOKIE] === header
		? cookies[DOCS_CSRF_COOKIE]
		: undefined;
}

function requireCsrf(req: JXPRequest): void {
	if (!csrfToken(req)) throw new errors.ForbiddenError("Missing or invalid CSRF token");
}

/** Restify redirect() always requires next; use this in async route handlers. */
function sendRedirect(res: JXPResponse, url: string): void {
	res.status(302);
	res.header("Location", url);
	res.end();
}

export function init(config: JXPConfig, models: Record<string, Model<unknown>> = {}): void {
	sharedSecret = config.shared_secret;
	modelRegistry = models;
	cookieSecure = String(config.url || "").startsWith("https://");
}

type Next = (err?: unknown) => void;

export function docsAccessMiddleware(req: JXPRequest, res: JXPResponse, next: Next): void {
	const pathname = req.path();
	if (!isProtectedDocsPath(pathname)) {
		return next();
	}
	const access = getDocsAccess(req.config);
	if (access === "public") {
		return next();
	}
	if (access === "disabled") {
		return next(new errors.NotFoundError("Not found"));
	}
	resolveValidDocsSession(req, res)
		.then((session) => {
			if (!session) {
				if (req.method === "GET") {
					const nextUrl = encodeURIComponent(pathname);
					res.redirect(302, `/docs/login?next=${nextUrl}`, next);
					return;
				}
				next(new errors.UnauthorizedError("Docs login required"));
				return;
			}
			(req as JXPRequest & { docsSession?: DocsSessionPayload }).docsSession = session;
			next();
		})
		.catch((err) => next(err));
}

export async function loginPage(
	req: JXPRequest,
	res: JXPResponse,
	renderLogin: (res: JXPResponse, data: Record<string, unknown>) => void,
): Promise<void> {
	const access = getDocsAccess(req.config);
	if (access === "disabled") {
		throw new errors.NotFoundError("Not found");
	}
	if (access === "public") {
		sendRedirect(res, "/docs/api");
		return;
	}
	const session = await resolveValidDocsSession(req, res);
	if (session) {
		const nextPath = safeNextPath(req.query.next);
		sendRedirect(res, nextPath);
		return;
	}
	const nextDefault = safeNextPath(req.query.next);
	renderLogin(res, {
		docs_user_email: req.config.docs?.user_email ?? "",
		docs_next: nextDefault,
	});
}

function assertSameOriginLogin(req: JXPRequest): void {
	const origin = req.headers.origin;
	if (typeof origin === "string" && req.headers.host) {
		try {
			if (new URL(origin).host !== req.headers.host) {
				throw new errors.ForbiddenError("Cross-origin docs login is not allowed");
			}
		} catch (err) {
			if (err instanceof errors.ForbiddenError) throw err;
			throw new errors.ForbiddenError("Invalid login origin");
		}
	}
}

async function createDocsSessionForUser(
	req: JXPRequest,
	res: JXPResponse,
	user: { _id: unknown; email: string }
): Promise<void> {
	const apikeys = require("./apikeys");
	const prior = verifyDocsSession(req);
	if (prior?.console_key_id && prior.user_id === String(user._id)) {
		await apikeys.revokeApiKey(user._id, prior.console_key_id);
	}
	const consoleKey = await apikeys.createApiKey(user._id, {
		name: "Docs console",
		expires_at: new Date(Date.now() + SESSION_MAX_AGE_SEC * 1000),
	});
	const consoleKeyId = String(consoleKey.record._id);
	const token = signDocsSession({
		user_id: String(user._id),
		email: user.email,
		console_key_id: consoleKeyId,
	});
	const csrf = crypto.randomBytes(24).toString("base64url");
	setSessionCookie(res, token, csrf);
	res.send({
		ok: true,
		console_key: consoleKey.plaintext,
		console_key_id: consoleKeyId,
		csrf_token: csrf,
	});
}

/** Establish a docs session directly from credentials without exposing a long-lived API key. */
export async function establishSession(req: JXPRequest, res: JXPResponse): Promise<void> {
	const access = getDocsAccess(req.config);
	if (access !== "protected") {
		throw new errors.NotFoundError("Not found");
	}
	assertSameOriginLogin(req);
	const email = String(req.body?.email ?? "").trim().toLowerCase();
	const password = String(req.body?.password ?? "");
	if (!email || !password) {
		throw new errors.BadRequestError("email and password are required");
	}
	const security = require("./security");
	const login = require("./login");
	let user: { _id: unknown; email: string; totp_enabled?: boolean };
	try {
		user = await security.basicAuth([email, password]);
	} catch {
		throw new errors.UnauthorizedError("Incorrect email or password");
	}
	const mfa = await login.requireMfaChallengeResponse(user, req.config);
	if (mfa) {
		res.send(mfa);
		return;
	}
	await createDocsSessionForUser(req, res, user);
}

/** Complete docs login after MFA challenge (TOTP code). */
export async function establishSessionMfa(req: JXPRequest, res: JXPResponse): Promise<void> {
	const access = getDocsAccess(req.config);
	if (access !== "protected") {
		throw new errors.NotFoundError("Not found");
	}
	assertSameOriginLogin(req);
	const challenge = String(req.body?.challenge ?? "");
	const code = String(req.body?.code ?? "");
	if (!challenge || !code) {
		throw new errors.BadRequestError("challenge and code are required");
	}
	const mfaChallenge = require("./mfa_challenge");
	const totp = require("./totp");
	let peeked: { user_id: string };
	try {
		peeked = mfaChallenge.peekMfaChallenge(challenge);
	} catch {
		throw new errors.UnauthorizedError("Invalid MFA code");
	}
	const ok = await totp.verifyCodeOrBackup(peeked.user_id, code);
	if (!ok) {
		throw new errors.UnauthorizedError("Invalid MFA code");
	}
	try {
		await mfaChallenge.consumeMfaChallenge(challenge, req.config);
	} catch {
		throw new errors.UnauthorizedError("Invalid MFA code");
	}
	const { getModelFromRegistry } = require("./builtin_models");
	const User = getModelFromRegistry(modelRegistry, "user");
	const user = (await User.findById(peeked.user_id).select("email").lean().exec()) as {
		_id: unknown;
		email: string;
	} | null;
	if (!user?.email) {
		throw new errors.UnauthorizedError("Invalid MFA code");
	}
	await createDocsSessionForUser(req, res, user);
}

/** Start passwordless passkey login for the docs browser. */
export async function establishSessionPasskeyOptions(
	req: JXPRequest,
	res: JXPResponse
): Promise<void> {
	const access = getDocsAccess(req.config);
	if (access !== "protected") {
		throw new errors.NotFoundError("Not found");
	}
	assertSameOriginLogin(req);
	const webauthn = require("./webauthn");
	const email = String(req.body?.email ?? "").trim().toLowerCase() || undefined;
	res.send(await webauthn.beginAuthentication({ email }, req.config, req));
}

/** Complete passwordless passkey login and establish a docs session. */
export async function establishSessionPasskeyVerify(
	req: JXPRequest,
	res: JXPResponse
): Promise<void> {
	const access = getDocsAccess(req.config);
	if (access !== "protected") {
		throw new errors.NotFoundError("Not found");
	}
	assertSameOriginLogin(req);
	const webauthn = require("./webauthn");
	const { getModelFromRegistry } = require("./builtin_models");
	let auth: { user_id: string };
	try {
		auth = await webauthn.finishAuthentication(
			{
				challenge_token: req.body?.challenge_token,
				response: req.body?.response || req.body?.credential,
			},
			req.config,
			req
		);
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		console.error(new Date().toISOString(), "Docs passkey login failed:", message);
		// Prefer an explicit JSON body so browsers don't show an "empty" 401.
		res.status(401);
		res.send({ ok: false, code: "Unauthorized", message: "Passkey authentication failed" });
		return;
	}
	const User = getModelFromRegistry(modelRegistry, "user");
	const user = (await User.findById(auth.user_id).select("email").lean().exec()) as {
		_id: unknown;
		email: string;
	} | null;
	if (!user?.email) {
		res.status(401);
		res.send({ ok: false, code: "Unauthorized", message: "Passkey authentication failed" });
		return;
	}
	await createDocsSessionForUser(req, res, user);
}

export async function getSession(req: JXPRequest, res: JXPResponse): Promise<void> {
	const access = getDocsAccess(req.config);
	if (access !== "protected") {
		res.send({ authenticated: false });
		return;
	}
	const docsSession = await resolveValidDocsSession(req, res);
	if (!docsSession) {
		throw new errors.UnauthorizedError("Not authenticated");
	}
	res.send({
		authenticated: true,
		email: docsSession.email,
		console_key_id: docsSession.console_key_id,
	});
}

export async function logout(req: JXPRequest, res: JXPResponse): Promise<void> {
	requireCsrf(req);
	const session = verifyDocsSession(req);
	if (session?.console_key_id) {
		const apikeys = require("./apikeys");
		await apikeys.revokeApiKey(session.user_id, session.console_key_id);
	}
	clearSessionCookie(res);
	sendRedirect(res, "/");
}

async function sessionUser(req: JXPRequest, res: JXPResponse): Promise<DocsSessionPayload> {
	const session = await resolveValidDocsSession(req, res);
	if (!session) throw new errors.UnauthorizedError("Not authenticated");
	return session;
}

function publicKey(record: Record<string, unknown>): Record<string, unknown> {
	const value = { ...record };
	delete value.apikey;
	delete value.key_hash;
	return value;
}

export async function listAccountKeys(req: JXPRequest, res: JXPResponse): Promise<void> {
	const session = await sessionUser(req, res);
	const apikeys = require("./apikeys");
	const records = await apikeys.listApiKeys(session.user_id);
	res.send(records.map((record) => publicKey(record.toObject ? record.toObject() : record)));
}

export async function createAccountKey(req: JXPRequest, res: JXPResponse): Promise<void> {
	requireCsrf(req);
	const session = await sessionUser(req, res);
	const apikeys = require("./apikeys");
	const body = req.body || {};
	const scopes = body.scopes;
	if (scopes && typeof scopes === "object") {
		for (const modelName of Object.keys(scopes)) {
			if (!modelRegistry[modelName]) {
				throw new errors.BadRequestError(`Unknown model in API key scope: ${modelName}`);
			}
		}
	}
	const expiresAt = body.expires_at ? new Date(String(body.expires_at)) : undefined;
	if (expiresAt && Number.isNaN(expiresAt.getTime())) {
		throw new errors.BadRequestError("expires_at must be a valid date");
	}
	const result = await apikeys.createApiKey(session.user_id, {
		name: typeof body.name === "string" ? body.name : undefined,
		scopes: scopes as Record<string, string> | undefined,
		allow_admin: body.allow_admin !== false,
		expires_at: expiresAt,
		created_ip: req.connection?.remoteAddress,
	});
	const record = result.record.toObject ? result.record.toObject() : result.record;
	res.send({ key: result.plaintext, record: publicKey(record) });
}

export async function revokeAccountKey(req: JXPRequest, res: JXPResponse): Promise<void> {
	requireCsrf(req);
	const session = await sessionUser(req, res);
	const apikeys = require("./apikeys");
	await apikeys.revokeApiKey(session.user_id, req.params.id);
	res.send({ ok: true });
}

export function logDocsAccessMode(config: JXPConfig): void {
	if (config.quiet_startup) return;
	const access = getDocsAccess(config);
	if (access === "disabled") {
		console.log("API docs browser: disabled (DOCS_ACCESS=disabled)");
	} else if (access === "public") {
		console.log("API docs browser: public (no login for model explorer)");
	} else {
		console.log("API docs browser: protected (login required for model metadata, /docs/api, /docs/mcp, and /docs/model/*)");
	}
}
