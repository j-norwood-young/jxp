#! /usr/bin/env node
import mongoose from "mongoose";
import { Command } from "commander";
import { getMongoConnectionString, loadEnv, loadJxpConfig } from "../libs/load-config";

const pkg = require("../../package.json");

loadEnv();

const program = new Command()
	.name("jxp-purge-legacy-apikeys")
	.description("Remove plaintext API key values after all JXP 5 servers are retired")
	.version(pkg.version)
	.option("--dry-run", "Report candidates without writing changes (default)")
	.option("--stale-only", "Only remove keys unused for the requested number of days")
	.option("--days <days>", "Stale threshold", "90")
	.option("--confirm", "Actually unset legacy plaintext values");
program.parse();

async function main(): Promise<void> {
	const options = program.opts<{
		dryRun?: boolean;
		staleOnly?: boolean;
		days: string;
		confirm?: boolean;
	}>();
	await mongoose.connect(getMongoConnectionString());
	const collection = mongoose.connection.collection("apikeys");
	const incomplete = await collection.countDocuments({
		$or: [{ key_hash: { $exists: false } }, { key_hash: null }],
	});
	if (incomplete) {
		throw new Error(`Refusing to purge: ${incomplete} API key(s) have no key_hash. Run jxp-migrate-apikeys first.`);
	}

	const filter: Record<string, unknown> = { apikey: { $exists: true, $type: "string", $ne: "" } };
	if (options.staleOnly) {
		const days = Number(options.days);
		if (!Number.isFinite(days) || days < 0) throw new Error("--days must be a non-negative number");
		filter.$or = [
			{ last_used_at: { $exists: false } },
			{ last_used_at: { $lt: new Date(Date.now() - days * 86400_000) } },
		];
	}
	const count = await collection.countDocuments(filter);
	if (!options.confirm) {
		console.log(`Dry run: ${count} legacy plaintext API key(s) match. Use --confirm after retiring JXP 5.`);
		await mongoose.disconnect();
		return;
	}
	const result = await collection.updateMany(filter, { $unset: { apikey: "" } });
	await collection.dropIndex("apikey_1").catch(() => undefined);
	await collection.createIndex({ apikey: 1 }, { name: "apikey_1", unique: true, sparse: true });
	console.log(`Purged ${result.modifiedCount} legacy plaintext API key(s).`);
	await mongoose.disconnect();
}

main().catch(async (error) => {
	console.error(error instanceof Error ? error.message : error);
	await mongoose.disconnect().catch(() => undefined);
	process.exit(1);
});
