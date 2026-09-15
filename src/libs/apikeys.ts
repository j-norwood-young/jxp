import crypto from "node:crypto";
import errors from "restify-errors";
import type { Model } from "mongoose";

type APIKeyRecord = {
	_id?: unknown;
	user_id?: unknown;
	apikey?: string;
	name?: string;
	key_hash?: string;
	key_prefix?: string;
	last4?: string;
	scopes?: Map<string, string> | Record<string, string>;
	allow_admin?: boolean;
	expires_at?: Date;
	revoked_at?: Date;
	last_accessed?: Date | null;
	last_used_at?: Date;
	created_ip?: string;
	save: () => Promise<APIKeyRecord>;
	updateOne: (update: Record<string, unknown>) => Promise<unknown>;
};

const CRUD_ORDER = "crud";
const MODEL_KEY = /^[A-Za-z0-9_-]+$/;
let APIKey: Model<APIKeyRecord> | null = null;
let pepper: string | undefined;
let warnedAboutFallback = false;

export interface APIKeyCreateOptions {
	name?: string;
	scopes?: Record<string, string>;
	allow_admin?: boolean;
	expires_at?: Date;
	created_ip?: string;
	/** Only for the v5/v6 migration compatibility path. */
	legacyCompatible?: boolean;
}

export function init(models: Record<string, Model<unknown>>, config: { shared_secret?: string; api_key_pepper?: string } = {}): void {
	APIKey = (models.apikey ?? models.APIKey) as Model<APIKeyRecord>;
	pepper = process.env.APIKEY_PEPPER || config.api_key_pepper || config.shared_secret;
	if (!process.env.APIKEY_PEPPER && pepper && !warnedAboutFallback) {
		console.warn("APIKEY_PEPPER is not set; using SHARED_SECRET as the API key hash pepper.");
		warnedAboutFallback = true;
	}
}

function model(): Model<APIKeyRecord> {
	if (!APIKey) throw new Error("API key service has not been initialized");
	return APIKey;
}

function requirePepper(): string {
	if (!pepper) throw new Error("APIKEY_PEPPER or SHARED_SECRET is required for API key hashing");
	return pepper;
}

export function hashApiKey(value: string): string {
	return crypto.createHmac("sha256", requirePepper()).update(value).digest("hex");
}

export function keyDisplay(value: string): { prefix: string; last4: string } {
	return {
		prefix: value.slice(0, 8),
		last4: value.slice(-4),
	};
}

export function normalizeScopes(scopes: Record<string, string> | Map<string, string> | undefined): Map<string, string> | undefined {
	if (scopes instanceof Map) scopes = Object.fromEntries(scopes.entries());
	if (scopes === undefined) return undefined;
	const entries = Object.entries(scopes);
	if (!entries.length) {
		throw new errors.BadRequestError("An empty scopes object is ambiguous; omit scopes for inherited access or grant at least one model");
	}
	const normalized = new Map<string, string>();
	for (const [modelName, rawPerms] of entries) {
		if (!MODEL_KEY.test(modelName)) {
			throw new errors.BadRequestError(`Invalid model name in API key scopes: ${modelName}`);
		}
		const raw = String(rawPerms).toLowerCase();
		if (!/^[crud]+$/.test(raw)) {
			throw new errors.BadRequestError(`Invalid CRUD permissions for API key scope: ${modelName}`);
		}
		const perms = [...new Set(raw.split(""))]
			.filter((letter) => CRUD_ORDER.includes(letter))
			.sort((a, b) => CRUD_ORDER.indexOf(a) - CRUD_ORDER.indexOf(b))
			.join("");
		if (!perms) continue;
		if (perms.length !== raw.length) {
			throw new errors.BadRequestError(`Invalid CRUD permissions for API key scope: ${modelName}`);
		}
		normalized.set(modelName, perms);
	}
	if (!normalized.size) {
		throw new errors.BadRequestError("API key scopes must grant at least one CRUD permission");
	}
	return normalized;
}

export function scopeObject(record: Pick<APIKeyRecord, "scopes">): Record<string, string> | undefined {
	if (!record.scopes) return undefined;
	return record.scopes instanceof Map ? Object.fromEntries(record.scopes.entries()) : record.scopes;
}

export function hasScopes(record: Pick<APIKeyRecord, "scopes">): boolean {
	return Boolean(record.scopes && (record.scopes instanceof Map
		? record.scopes.size
		: Object.keys(record.scopes).length));
}

export function scopeAllows(record: Pick<APIKeyRecord, "scopes">, modelName: string, method: string): boolean {
	if (!hasScopes(record)) return true;
	const scopes = scopeObject(record);
	return Boolean(scopes?.[modelName]?.includes(method));
}

export async function createApiKey(userId: unknown, options: APIKeyCreateOptions = {}): Promise<{ record: APIKeyRecord; plaintext: string }> {
	const plaintext = `jxp_${crypto.randomBytes(32).toString("base64url")}`;
	const display = keyDisplay(plaintext);
	const scopes = normalizeScopes(options.scopes);
	const record = new (model() as unknown as { new (data: Record<string, unknown>): APIKeyRecord })({
		user_id: userId,
		name: options.name?.trim() || "API key",
		key_hash: hashApiKey(plaintext),
		key_prefix: display.prefix,
		last4: display.last4,
		scopes,
		allow_admin: options.allow_admin !== false,
		expires_at: options.expires_at,
		created_ip: options.created_ip,
		// v5 sorts by this field and can only use rows with a plaintext key.
		last_accessed: options.legacyCompatible ? new Date() : null,
		...(options.legacyCompatible ? { apikey: plaintext } : {}),
	});
	await record.save();
	return { record, plaintext };
}

function isActiveApiKey(record: APIKeyRecord | null): record is APIKeyRecord {
	if (!record) return false;
	if (record.revoked_at) return false;
	if (record.expires_at && record.expires_at.getTime() <= Date.now()) return false;
	return true;
}

export async function findApiKey(value: string): Promise<APIKeyRecord | null> {
	const keyHash = hashApiKey(value);
	let record = await model().findOne({ key_hash: keyHash }).exec() as APIKeyRecord | null;
	if (!record) {
		// Allows a staged deployment before the migration command runs. Never
		// removes or overwrites the legacy value.
		record = await model().findOne({ apikey: value }).exec() as APIKeyRecord | null;
		if (record && !record.key_hash) {
			const display = keyDisplay(value);
			await record.updateOne({
				$set: { key_hash: keyHash, key_prefix: display.prefix, last4: display.last4 },
			});
			record.key_hash = keyHash;
			record.key_prefix = display.prefix;
			record.last4 = display.last4;
		}
	}
	return isActiveApiKey(record) ? record : null;
}

/** Active (non-revoked, non-expired) key owned by the user, by Mongo id. */
export async function findActiveApiKeyById(userId: unknown, id: unknown): Promise<APIKeyRecord | null> {
	if (id == null || id === "") return null;
	const record = await model().findOne({ _id: id, user_id: userId }).exec() as APIKeyRecord | null;
	return isActiveApiKey(record) ? record : null;
}

export async function markUsed(record: APIKeyRecord): Promise<void> {
	await record.updateOne({ $set: { last_used_at: new Date() } });
}

export async function listApiKeys(userId: unknown): Promise<APIKeyRecord[]> {
	return await model().find({ user_id: userId, revoked_at: { $exists: false } })
		.sort({ createdAt: -1 }).exec() as APIKeyRecord[];
}

export async function revokeApiKey(userId: unknown, id: unknown): Promise<void> {
	await model().updateOne({ _id: id, user_id: userId }, { $set: { revoked_at: new Date() } }).exec();
}

export async function revokeAllForUser(userId: unknown): Promise<void> {
	await model().updateMany({ user_id: userId }, { $set: { revoked_at: new Date() } }).exec();
}

export async function revokeNamedForUser(userId: unknown, name: string): Promise<void> {
	await model().updateMany(
		{ user_id: userId, name, revoked_at: { $exists: false } },
		{ $set: { revoked_at: new Date() } },
	).exec();
}

export function isLegacyPlaintext(record: Pick<APIKeyRecord, "apikey">): boolean {
	return typeof record.apikey === "string" && record.apikey.length > 0;
}
