#! /usr/bin/env node
import mongoose from "mongoose";
import { Command } from "commander";
import { loadEnv, getMongoConnectionString, loadJxpConfig } from "../libs/load-config";
import { hashApiKey, keyDisplay, init as initApiKeys } from "../libs/apikeys";

const pkg = require("../../package.json");

loadEnv();

const program = new Command()
	.name("jxp-migrate-apikeys")
	.description("Backfill hashed API key metadata without removing legacy plaintext values")
	.version(pkg.version)
	.option("--dry-run", "Report changes without writing them");
program.parse();

async function main(): Promise<void> {
	const config = loadJxpConfig();
	initApiKeys({}, config);
	if (!config.shared_secret && !process.env.APIKEY_PEPPER) {
		throw new Error("Set APIKEY_PEPPER or SHARED_SECRET before migrating API keys");
	}
	await mongoose.connect(getMongoConnectionString());
	const collection = mongoose.connection.collection("apikeys");
	const query = { apikey: { $exists: true, $type: "string", $ne: "" } };
	const keys = await collection.find(query, {
		projection: { _id: 1, apikey: 1, key_hash: 1, key_prefix: 1, last4: 1 },
	}).toArray();
	const dryRun = Boolean(program.opts().dryRun);
	let migrated = 0;
	for (const key of keys) {
		if (key.key_hash) continue;
		const display = keyDisplay(key.apikey);
		migrated += 1;
		if (!dryRun) {
			await collection.updateOne(
				{ _id: key._id },
				{ $set: { key_hash: hashApiKey(key.apikey), key_prefix: display.prefix, last4: display.last4 } },
			);
		}
	}

	if (!dryRun) {
		await collection.dropIndex("user_id_1").catch(() => undefined);
		await collection.createIndex({ user_id: 1 }, { name: "user_id_1" });
		await collection.dropIndex("apikey_1").catch(() => undefined);
		await collection.createIndex({ apikey: 1 }, { name: "apikey_1", unique: true, sparse: true });
		await collection.createIndex({ key_hash: 1 }, { name: "key_hash_1", unique: true, sparse: true });
	}
	console.log(`${dryRun ? "Would migrate" : "Migrated"} ${migrated} API key(s); legacy apikey values were ${dryRun ? "not changed" : "preserved"}.`);
	await mongoose.disconnect();
}

main().catch(async (error) => {
	console.error(error instanceof Error ? error.message : error);
	await mongoose.disconnect().catch(() => undefined);
	process.exit(1);
});
