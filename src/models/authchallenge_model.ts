import JXPSchema from "../libs/schema";
import type { Types } from "mongoose";

export interface IAuthChallenge {
	_id?: Types.ObjectId;
	jti_hash?: string;
	user_id?: Types.ObjectId;
	purpose?: string;
	/** Opaque challenge payload (e.g. WebAuthn challenge string). */
	payload?: string;
	expire_at?: Date;
	createdAt?: Date;
}

const AuthChallengeSchema = new JXPSchema(
	{
		jti_hash: { type: String, required: true },
		user_id: { type: global.ObjectId, index: true },
		purpose: { type: String, required: true, index: true },
		payload: String,
		expire_at: { type: Date, required: true },
	},
	{
		internal: true,
		perms: {
			admin: "crud",
			owner: "",
			user: "",
		},
	}
);

AuthChallengeSchema.index({ jti_hash: 1 }, { unique: true });
AuthChallengeSchema.index({ expire_at: 1 }, { expireAfterSeconds: 0 });

const AuthChallenge = JXPSchema.model<IAuthChallenge>("AuthChallenge", AuthChallengeSchema);
export default AuthChallenge;
