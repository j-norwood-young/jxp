import JXPSchema from "../libs/schema";
import { getRefreshTokenExpiry } from "../libs/load-config";
import type { Types } from "mongoose";

export interface IRefreshToken {
	_id?: Types.ObjectId;
	user_id?: Types.ObjectId;
	refresh_token?: string;
	refresh_token_hash?: string;
	expires_in?: number;
	expire_at?: Date;
	createdAt?: Date;
}

const RefreshTokenSchema = new JXPSchema(
	{
		user_id: { type: global.ObjectId, index: true },
		refresh_token: { type: String, index: true },
		refresh_token_hash: { type: String, index: true },
		expires_in: { type: Number, default: getRefreshTokenExpiry() },
		expire_at: { type: Date, default: () => new Date(Date.now() + getRefreshTokenExpiry() * 1000), index: true },
	},
	{
		perms: {
			admin: "crud",
			owner: "crud",
			user: "",
		},
	}
);

RefreshTokenSchema.index(
	{ expire_at: 1 },
	{ expireAfterSeconds: 0 }
);
RefreshTokenSchema.index({ refresh_token_hash: 1 }, { unique: true, sparse: true });

const RefreshToken = JXPSchema.model<IRefreshToken>("RefreshToken", RefreshTokenSchema);
export default RefreshToken;
