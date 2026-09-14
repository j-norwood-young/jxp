import type { IncomingMessage } from "node:http";
import type { McpAuthContext } from "./model_visibility";

const errors = require("restify-errors");
const security = require("../security");

function headerValue(req: IncomingMessage, name: string): string | undefined {
	const raw = req.headers[name.toLowerCase()];
	if (Array.isArray(raw)) return raw[0];
	return raw;
}

function parseApiKey(req: IncomingMessage): string | undefined {
	const fromHeader = headerValue(req, "x-api-key");
	if (fromHeader) return fromHeader;
	const auth = headerValue(req, "authorization");
	if (auth?.trim().toLowerCase().startsWith("bearer ")) {
		return auth.trim().slice(7);
	}
	const url = req.url || "";
	const q = url.includes("?") ? url.slice(url.indexOf("?") + 1) : "";
	const params = new URLSearchParams(q);
	if (params.has("apikey") || params.has("api_key") || params.has("x-api-key")) {
		throw new errors.UnauthorizedError(
			"API keys in query parameters are no longer supported. Send X-API-Key or Authorization: Bearer instead."
		);
	}
	return undefined;
}

export async function authenticateMcpRequest(req: IncomingMessage, requireApiKey: boolean): Promise<McpAuthContext> {
	const apiKey = parseApiKey(req);
	if (!apiKey) {
		if (requireApiKey) {
			throw new errors.UnauthorizedError("MCP requires an API key (X-API-Key header or Bearer token)");
		}
		return { user: null, groups: [] };
	}

	let user = null;
	let apikey = undefined;
	try {
		const result = await security.apiKeyAuthContext(apiKey);
		user = result.user;
		apikey = result.apikey;
	} catch {
		try {
			user = await security.bearerAuth(apiKey);
		} catch {
			throw new errors.UnauthorizedError("Invalid API key or token");
		}
	}

	const groups = await security.getGroups(user._id);
	return { user, groups, apikey };
}
