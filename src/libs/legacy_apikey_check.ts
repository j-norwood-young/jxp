import type { Model } from "mongoose";

export async function warnAboutLegacyApiKeys(
	models: Record<string, Model<unknown>>,
	config: { quiet_startup?: boolean } = {},
): Promise<number> {
	if (process.env.APIKEY_LEGACY_DUAL_RUN === "true" || process.env.APIKEY_LEGACY_DUAL_RUN === "1") {
		return 0;
	}
	const model = models.apikey;
	if (!model) return 0;
	const count = await model.countDocuments({ apikey: { $exists: true, $type: "string", $ne: "" } }).exec();
	if (count && !config.quiet_startup) {
		console.warn(
			`! ${count} API key(s) still hold plaintext values in the legacy apikey field.\n` +
			"  They remain valid for JXP 5 servers sharing this database, so they are not fully secured yet.\n" +
			"  After the last JXP 5 server is retired, run: npx jxp-purge-legacy-apikeys --confirm"
		);
	}
	return count;
}
