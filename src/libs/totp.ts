import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import QRCode from "qrcode";
import { generateSecret, generateURI, verify } from "otplib";
import { getModelFromRegistry } from "./builtin_models";
import type { JXPConfig } from "../types/jxp-config";
import type { Model } from "mongoose";

let User: Model<unknown> | null = null;
let sharedSecret = "";
let passwordRounds = 12;

const BACKUP_CODE_COUNT = 10;

function requireSecret(): string {
	if (!sharedSecret) throw new Error("shared_secret is required for TOTP encryption");
	return sharedSecret;
}

function deriveKey(pepper: string): Buffer {
	return crypto.createHash("sha256").update(pepper).digest();
}

export function encryptSecret(plaintext: string, pepper = sharedSecret): string {
	const key = deriveKey(pepper || requireSecret());
	const iv = crypto.randomBytes(12);
	const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
	const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
	const tag = cipher.getAuthTag();
	return Buffer.concat([iv, tag, enc]).toString("base64url");
}

export function decryptSecret(ciphertext: string, pepper = sharedSecret): string {
	const key = deriveKey(pepper || requireSecret());
	const buf = Buffer.from(ciphertext, "base64url");
	const iv = buf.subarray(0, 12);
	const tag = buf.subarray(12, 28);
	const data = buf.subarray(28);
	const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
	decipher.setAuthTag(tag);
	return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

function issuer(config: JXPConfig): string {
	return config.mfa?.totp_issuer || "JXP";
}

function generateBackupCodes(): string[] {
	const codes: string[] = [];
	for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
		codes.push(crypto.randomBytes(5).toString("hex"));
	}
	return codes;
}

function normalizeCode(code: unknown): string {
	return String(code || "").trim().replace(/\s+/g, "");
}

async function verifyTotpCode(secret: string, code: string): Promise<boolean> {
	if (!/^\d{6}$/.test(code)) return false;
	try {
		const result = await verify({ token: code, secret, epochTolerance: 30 });
		return Boolean(result.valid);
	} catch {
		return false;
	}
}

export function init(models: Record<string, Model<unknown>>, config: JXPConfig): void {
	User = getModelFromRegistry(models, "user") as Model<unknown>;
	sharedSecret = config.shared_secret || process.env.SHARED_SECRET || "";
	passwordRounds = Number(config.bcrypt_rounds || process.env.BCRYPT_ROUNDS || 12);
}

export async function setup(
	user_id: unknown,
	email: string,
	config: JXPConfig
): Promise<{ secret: string; otpauth_url: string; qr_data_url: string; backup_codes: string[] }> {
	if (!User) throw new Error("totp not initialized");
	const secret = generateSecret();
	const backup_codes = generateBackupCodes();
	const hashes = backup_codes.map((c) => bcrypt.hashSync(c, passwordRounds));
	await User.updateOne(
		{ _id: user_id },
		{
			$set: {
				totp_pending_secret_enc: encryptSecret(secret),
				totp_backup_hashes: hashes,
			},
		}
	).exec();
	const otpauth_url = generateURI({
		issuer: issuer(config),
		label: email,
		secret,
	});
	const qr_data_url = await QRCode.toDataURL(otpauth_url, {
		errorCorrectionLevel: "M",
		margin: 1,
		width: 240,
		color: { dark: "#0c0d10", light: "#ffffff" },
	});
	return { secret, otpauth_url, qr_data_url, backup_codes };
}

export async function confirm(user_id: unknown, code: string): Promise<void> {
	if (!User) throw new Error("totp not initialized");
	const trimmed = normalizeCode(code);
	if (!trimmed) throw new Error("Enter the 6-digit code from your authenticator");
	if (!/^\d{6}$/.test(trimmed)) {
		throw new Error("Enter the 6-digit code from your authenticator (not the secret or backup codes)");
	}
	const user = (await User.findById(user_id).exec()) as {
		totp_pending_secret_enc?: string;
	} | null;
	if (!user?.totp_pending_secret_enc) {
		throw new Error("No pending TOTP setup");
	}
	const secret = decryptSecret(user.totp_pending_secret_enc);
	const ok = await verifyTotpCode(secret, trimmed);
	if (!ok) {
		throw new Error("Invalid MFA code");
	}
	await User.updateOne(
		{ _id: user_id },
		{
			$set: {
				totp_enabled: true,
				totp_secret_enc: user.totp_pending_secret_enc,
			},
			$unset: { totp_pending_secret_enc: 1 },
		}
	).exec();
}

export async function disable(user_id: unknown, code: string): Promise<void> {
	if (!User) throw new Error("totp not initialized");
	const trimmed = normalizeCode(code);
	if (!trimmed) throw new Error("Enter a verification or backup code");
	const ok = await verifyCodeOrBackup(user_id, trimmed);
	if (!ok) throw new Error("Invalid MFA code");
	await User.updateOne(
		{ _id: user_id },
		{
			$set: { totp_enabled: false },
			$unset: {
				totp_secret_enc: 1,
				totp_pending_secret_enc: 1,
				totp_backup_hashes: 1,
			},
		}
	).exec();
}

export async function status(user_id: unknown): Promise<{ enabled: boolean }> {
	if (!User) throw new Error("totp not initialized");
	const user = (await User.findById(user_id).select("totp_enabled").lean().exec()) as {
		totp_enabled?: boolean;
	} | null;
	return { enabled: Boolean(user?.totp_enabled) };
}

export async function verifyCodeOrBackup(user_id: unknown, code: string): Promise<boolean> {
	if (!User) throw new Error("totp not initialized");
	const user = (await User.findById(user_id).exec()) as {
		totp_enabled?: boolean;
		totp_secret_enc?: string;
		totp_backup_hashes?: string[];
	} | null;
	if (!user?.totp_enabled || !user.totp_secret_enc) return false;
	const trimmed = normalizeCode(code);
	if (!trimmed) return false;

	if (/^\d{6}$/.test(trimmed)) {
		const secret = decryptSecret(user.totp_secret_enc);
		if (await verifyTotpCode(secret, trimmed)) return true;
	}

	const hashes = user.totp_backup_hashes || [];
	for (let i = 0; i < hashes.length; i++) {
		if (await bcrypt.compare(trimmed, hashes[i])) {
			hashes.splice(i, 1);
			await User.updateOne({ _id: user_id }, { $set: { totp_backup_hashes: hashes } }).exec();
			return true;
		}
	}
	return false;
}

module.exports = {
	init,
	setup,
	confirm,
	disable,
	status,
	verifyCodeOrBackup,
	encryptSecret,
	decryptSecret,
};
