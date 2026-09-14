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
	const session = verifyDocsSession(req);
	if (!session) {
		if (req.method === "GET") {
			const nextUrl = encodeURIComponent(pathname);
			res.redirect(302, `/docs/login?next=${nextUrl}`, next);
			return;
		}
		return next(new errors.UnauthorizedError("Docs login required"));
	}
	(req as JXPRequest & { docsSession?: DocsSessionPayload }).docsSession = session;
	return next();
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
	const session = verifyDocsSession(req);
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

/** Establish a docs session directly from credentials without exposing a long-lived API key. */
export async function establishSession(req: JXPRequest, res: JXPResponse): Promise<void> {
	const access = getDocsAccess(req.config);
	if (access !== "protected") {
		throw new errors.NotFoundError("Not found");
	}
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
	const email = String(req.body?.email ?? "").trim().toLowerCase();
	const password = String(req.body?.password ?? "");
	if (!email || !password) {
		throw new errors.BadRequestError("email and password are required");
	}
	const security = require("./security");
	const apikeys = require("./apikeys");
	let user: { _id: unknown; email: string };
	try {
		user = await security.basicAuth([email, password]);
	} catch {
		throw new errors.UnauthorizedError("Incorrect email or password");
	}
	await apikeys.revokeNamedForUser(user._id, "Docs console");
	const consoleKey = await apikeys.createApiKey(user._id, {
		name: "Docs console",
		expires_at: new Date(Date.now() + SESSION_MAX_AGE_SEC * 1000),
	});
	const token = signDocsSession({
		user_id: String(user._id),
		email: user.email,
		console_key_id: String(consoleKey.record._id),
	});
	const csrf = crypto.randomBytes(24).toString("base64url");
	setSessionCookie(res, token, csrf);
	res.send({ ok: true, console_key: consoleKey.plaintext, csrf_token: csrf });
}

export async function getSession(req: JXPRequest, res: JXPResponse): Promise<void> {
	const access = getDocsAccess(req.config);
	if (access !== "protected") {
		res.send({ authenticated: false });
		return;
	}
	const docsSession = verifyDocsSession(req);
	if (!docsSession) {
		throw new errors.UnauthorizedError("Not authenticated");
	}
	res.send({ authenticated: true, email: docsSession.email });
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

function sessionUser(req: JXPRequest): DocsSessionPayload {
	const session = verifyDocsSession(req);
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
	const session = sessionUser(req);
	const apikeys = require("./apikeys");
	const records = await apikeys.listApiKeys(session.user_id);
	res.send(records.map((record) => publicKey(record.toObject ? record.toObject() : record)));
}

export async function createAccountKey(req: JXPRequest, res: JXPResponse): Promise<void> {
	requireCsrf(req);
	const session = sessionUser(req);
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
	const session = sessionUser(req);
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
