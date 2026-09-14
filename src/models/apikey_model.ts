import JXPSchema from "../libs/schema";
import type { Types } from "mongoose";

export interface IAPIKeyScope {
	[key: string]: string;
}

export interface IAPIKey {
	_id?: Types.ObjectId;
	user_id?: Types.ObjectId;
	/** Legacy plaintext value retained only during the v5/v6 dual-run window. */
	apikey?: string;
	name?: string;
	key_hash?: string;
	key_prefix?: string;
	last4?: string;
	scopes?: Map<string, string> | IAPIKeyScope;
	allow_admin?: boolean;
	expires_at?: Date;
	revoked_at?: Date;
	last_accessed?: Date;
	last_used_at?: Date;
	created_ip?: string;
}

const APIKeySchema = new JXPSchema(
	{
		user_id: { type: global.ObjectId, index: true },
		// Kept for JXP 5 servers until the explicit purge migration is run.
		apikey: { type: String },
		name: { type: String, default: "API key" },
		key_hash: { type: String },
		key_prefix: String,
		last4: String,
		scopes: {
			type: Map,
			of: String,
			default: undefined,
		},
		allow_admin: { type: Boolean, default: true },
		expires_at: { type: Date, index: true },
		revoked_at: Date,
		last_accessed: { type: Date, default: Date.now, index: true },
		last_used_at: { type: Date, index: true },
		created_ip: String,
	},
	{
		internal: true,
		toJSON: { virtuals: true, flattenMaps: true },
		toObject: { virtuals: true, flattenMaps: true },
	}
);

APIKeySchema.index({ key_hash: 1 }, { unique: true, sparse: true });
APIKeySchema.index({ apikey: 1 }, { unique: true, sparse: true });

const APIKey = JXPSchema.model<IAPIKey>("APIKey", APIKeySchema);
export default APIKey;
