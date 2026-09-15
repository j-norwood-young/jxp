import JXPSchema from "../libs/schema";
import type { Types } from "mongoose";

export interface IWebAuthnCredential {
	_id?: Types.ObjectId;
	user_id?: Types.ObjectId;
	credential_id?: string;
	public_key?: string;
	counter?: number;
	transports?: string[];
	device_type?: string;
	backed_up?: boolean;
	name?: string;
	createdAt?: Date;
	updatedAt?: Date;
}

const WebAuthnCredentialSchema = new JXPSchema(
	{
		user_id: { type: global.ObjectId, index: true, required: true },
		credential_id: { type: String, required: true },
		public_key: { type: String, required: true },
		counter: { type: Number, default: 0 },
		transports: { type: [String], default: undefined },
		device_type: String,
		backed_up: Boolean,
		name: { type: String, default: "Passkey" },
	},
	{
		internal: true,
		perms: {
			admin: "crud",
			owner: "crud",
			user: "",
		},
	}
);

WebAuthnCredentialSchema.index({ credential_id: 1 }, { unique: true });
WebAuthnCredentialSchema.index({ user_id: 1, credential_id: 1 });

const WebAuthnCredential = JXPSchema.model<IWebAuthnCredential>(
	"WebAuthnCredential",
	WebAuthnCredentialSchema
);
export default WebAuthnCredential;
