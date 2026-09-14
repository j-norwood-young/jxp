/**
 * Minimal Restify CORS helpers (replaces restify-cors-middleware2, which
 * still peers on restify ≤11 and conflicts with restify 12).
 */

type CorsOptions = {
	origins?: Array<string | RegExp>;
	credentials?: boolean;
	allowHeaders?: string[];
	exposeHeaders?: string[];
	preflightMaxAge?: number;
};

type RestifyNext = (err?: unknown) => void;
type RestifyReq = {
	method: string;
	headers: Record<string, string | string[] | undefined>;
};
type RestifyRes = {
	setHeader: (name: string, value: string | number | boolean) => void;
	header: (name: string, value: string | number | boolean) => void;
	once: (event: string, cb: () => void) => void;
	send: (code: number) => void;
};

const DEFAULT_ALLOW_HEADERS = [
	"accept",
	"accept-version",
	"content-type",
	"request-id",
	"origin",
	"x-api-version",
	"x-request-id",
	"x-requested-with",
];

const DEFAULT_EXPOSE_HEADERS = [
	"api-version",
	"content-length",
	"content-md5",
	"content-type",
	"date",
	"request-id",
	"response-time",
];

function createOriginMatcher(origins: Array<string | RegExp>) {
	const allowAll = origins.includes("*");
	return (origin: string | undefined): boolean => {
		if (!origin) return false;
		if (allowAll) return true;
		return origins.some((o) =>
			typeof o === "string" ? o === origin : o.test(origin)
		);
	};
}

function uniqLower(values: string[]): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const v of values) {
		const key = v.toLowerCase();
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(v);
	}
	return out;
}

export function createCorsMiddleware(options: CorsOptions = {}) {
	const origins = options.origins?.length ? options.origins : ["*"];
	const credentials = Boolean(options.credentials);
	if (origins.includes("*") && credentials) {
		throw new Error("CORS credentials are not supported with a wildcard origin");
	}

	const allowHeaders = uniqLower([
		...DEFAULT_ALLOW_HEADERS,
		...(options.allowHeaders || []),
	]);
	const exposeHeaders = uniqLower([
		...DEFAULT_EXPOSE_HEADERS,
		...(options.exposeHeaders || []),
	]);
	const matcher = createOriginMatcher(origins);
	const maxAge = options.preflightMaxAge;

	function preflight(req: RestifyReq, res: RestifyRes, next: RestifyNext) {
		if (req.method !== "OPTIONS") return next();

		const originHeader = String(req.headers.origin || "");
		if (!matcher(originHeader)) return next();

		const requestedMethod = req.headers["access-control-request-method"];
		if (!requestedMethod) return next();

		const allowedMethods = [String(requestedMethod), "OPTIONS"];

		res.once("header", () => {
			res.header("access-control-allow-origin", originHeader);
			if (credentials) res.header("access-control-allow-credentials", true);
			if (maxAge) res.header("access-control-max-age", maxAge);
			res.header("access-control-allow-methods", allowedMethods.join(","));
			res.header("access-control-allow-headers", allowHeaders.join(","));
		});

		res.send(204);
	}

	function actual(req: RestifyReq, res: RestifyRes, next: RestifyNext) {
		res.setHeader(
			"vary",
			"origin,access-control-request-method,access-control-request-headers"
		);

		const originHeader = req.headers.origin
			? String(req.headers.origin)
			: undefined;
		if (!originHeader || !matcher(originHeader)) return next();

		res.setHeader("access-control-allow-origin", originHeader);
		if (credentials) res.setHeader("access-control-allow-credentials", "true");
		res.setHeader("access-control-expose-headers", exposeHeaders.join(","));
		return next();
	}

	return { preflight, actual };
}

export default createCorsMiddleware;
