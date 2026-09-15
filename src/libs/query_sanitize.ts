const errors = require("restify-errors");

/** Operators denied in list/query filters (and by default). */
const DEFAULT_DENY_OPERATORS = new Set([
	"$where",
	"$function",
	"$accumulator",
	"$expr",
	"$jsonSchema",
]);

/**
 * Operators denied inside aggregate `$match` stages.
 * `$expr` is allowed here — it is a normal aggregation match form and is
 * documented for `/aggregate`. Dangerous nested ops (`$where`, `$function`, …)
 * remain denied at any depth.
 */
const AGGREGATE_MATCH_DENY_OPERATORS = new Set([
	"$where",
	"$function",
	"$accumulator",
	"$jsonSchema",
]);

const MAX_REGEX_LENGTH = 256;
const NESTED_QUANTIFIER = /(\*|\?|\+|\{)\s*(\*|\?|\+|\{)/;

function getDenySet(base: Set<string>, custom?: string[]): Set<string> {
	if (!custom || !custom.length) return new Set(base);
	return new Set([...base, ...custom]);
}

function validateRegex(pattern: string): void {
	if (pattern.length > MAX_REGEX_LENGTH) {
		throw new errors.BadRequestError("Regex pattern too long");
	}
	if (NESTED_QUANTIFIER.test(pattern)) {
		throw new errors.BadRequestError("Regex pattern not allowed");
	}
}

function sanitizeRegexValue(value: unknown): void {
	if (value instanceof RegExp) {
		validateRegex(value.source);
		return;
	}
	if (typeof value === "string") {
		validateRegex(value);
		return;
	}
	if (value && typeof value === "object") {
		const o = value as Record<string, unknown>;
		if (typeof o.$regex === "string") {
			validateRegex(o.$regex);
		}
	}
}

function walkQuery(obj: unknown, deny: Set<string>, depth = 0): void {
	const MAX_DEPTH = 20;
	if (depth > MAX_DEPTH) {
		throw new errors.BadRequestError("Query nesting too deep");
	}
	if (obj === null || obj === undefined) return;
	if (obj instanceof RegExp) {
		validateRegex(obj.source);
		return;
	}
	if (Array.isArray(obj)) {
		for (const item of obj) {
			walkQuery(item, deny, depth + 1);
		}
		return;
	}
	if (typeof obj !== "object") return;

	for (const key of Object.keys(obj as Record<string, unknown>)) {
		if (key.startsWith("$") && deny.has(key)) {
			throw new errors.BadRequestError(`Operator ${key} is not allowed`);
		}
		if (key === "$regex") {
			sanitizeRegexValue((obj as Record<string, unknown>)[key]);
		}
		const val = (obj as Record<string, unknown>)[key];
		if (val instanceof RegExp) {
			validateRegex(val.source);
		}
		walkQuery(val, deny, depth + 1);
	}
}

export function sanitizeFilter(
	filter: unknown,
	options?: { filter_operators_deny?: string[] }
): Record<string, unknown> {
	if (!filter || typeof filter !== "object" || Array.isArray(filter)) {
		return (filter as Record<string, unknown>) || {};
	}
	const deny = getDenySet(DEFAULT_DENY_OPERATORS, options?.filter_operators_deny);
	walkQuery(filter, deny);
	return filter as Record<string, unknown>;
}

/** Sanitize a `$match` body in an aggregation pipeline (`$expr` allowed). */
export function sanitizeAggregateMatch(
	match: unknown,
	options?: { filter_operators_deny?: string[] }
): Record<string, unknown> {
	if (!match || typeof match !== "object" || Array.isArray(match)) {
		return (match as Record<string, unknown>) || {};
	}
	const deny = getDenySet(AGGREGATE_MATCH_DENY_OPERATORS, options?.filter_operators_deny);
	walkQuery(match, deny);
	return match as Record<string, unknown>;
}

export function parseSearchObject(search: unknown): Record<string, RegExp> {
	const result: Record<string, RegExp> = {};
	if (!search) return result;
	if (typeof search === "string") {
		return result;
	}
	if (typeof search !== "object" || Array.isArray(search)) {
		return result;
	}
	for (const i in search as Record<string, string>) {
		const val = (search as Record<string, string>)[i];
		if (typeof val === "string") {
			validateRegex(val);
			result[i] = new RegExp(val, "i");
		}
	}
	return result;
}

module.exports = {
	sanitizeFilter,
	sanitizeAggregateMatch,
	parseSearchObject,
	DEFAULT_DENY_OPERATORS: [...DEFAULT_DENY_OPERATORS],
	AGGREGATE_MATCH_DENY_OPERATORS: [...AGGREGATE_MATCH_DENY_OPERATORS],
};
