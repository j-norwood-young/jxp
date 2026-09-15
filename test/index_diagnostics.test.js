const { expect } = require("chai");
const {
	classifyExplain,
	hasCollScan,
	extractScanStagePath,
	formatScanStagePath,
	shouldMonitorQuery,
	summarizeFilter,
	SYNC_CONFIRM_PHRASE,
	syncAllModels,
	alignModelIndexes,
	ensurePrimaryIndexesAndWarnOthers,
	ensurePrimaryIndexesOnStartup,
	isPrimaryAuthModel,
	formatAuditReportHuman,
	listQueryLogs,
	setQueryLogModel,
} = require("../dist/libs/index_diagnostics");

function mockModel({
	modelName,
	collectionName,
	toCreate = [],
	toDrop = [],
	syncError = null,
}) {
	let syncCalled = false;
	const model = {
		modelName,
		collection: { name: collectionName || `${modelName.toLowerCase()}s` },
		schema: { indexes: () => [] },
		listIndexes: async () => [{ name: "_id_", key: { _id: 1 } }],
		diffIndexes: async () => ({ toCreate, toDrop }),
		syncIndexes: async () => {
			syncCalled = true;
			if (syncError) throw syncError;
		},
	};
	return {
		model,
		wasSyncCalled: () => syncCalled,
	};
}

describe("index_diagnostics", () => {
	it("detects collection scan alert", () => {
		const explain = {
			executionStats: {
				nReturned: 2,
				totalDocsExamined: 5000,
				totalKeysExamined: 0,
				executionTimeMillis: 12,
				executionStages: {
					stage: "COLLSCAN",
				},
			},
		};
		const r = classifyExplain(explain, {
			minDocsExamined: 50,
			docsExaminedRatio: 10,
			smallCollectionThreshold: 100,
			collectionDocCount: 5000,
		});
		expect(r.severity).to.eql("alert");
		expect(r.reason).to.eql("collection_scan");
		expect(r.stage).to.eql("COLLSCAN");
	});

	it("extracts scan path through PROJECTION_SIMPLE wrapper", () => {
		const path = extractScanStagePath({
			stage: "PROJECTION_SIMPLE",
			inputStage: {
				stage: "DISTINCT_SCAN",
				inputStage: { stage: "COLLSCAN" },
			},
		});
		expect(path).to.eql(["COLLSCAN", "DISTINCT_SCAN"]);
		expect(formatScanStagePath(path)).to.eql("COLLSCAN → DISTINCT_SCAN");
	});

	it("ignores small collections", () => {
		const explain = {
			executionStats: {
				nReturned: 1,
				totalDocsExamined: 100,
				totalKeysExamined: 0,
				executionStages: { stage: "COLLSCAN" },
			},
		};
		const r = classifyExplain(explain, { collectionDocCount: 50, smallCollectionThreshold: 1000 });
		expect(r.severity).to.eql("ignore");
		expect(r.reason).to.eql("small_collection");
	});

	it("detects nested COLLSCAN in inputStage", () => {
		const stage = {
			stage: "FETCH",
			inputStage: { stage: "COLLSCAN" },
		};
		expect(hasCollScan(stage)).to.be.true;
	});

	it("classifies efficient index use as ok", () => {
		const explain = {
			executionStats: {
				nReturned: 3,
				totalDocsExamined: 3,
				totalKeysExamined: 3,
				executionStages: {
					stage: "FETCH",
					inputStage: { stage: "IXSCAN" },
				},
			},
		};
		const r = classifyExplain(explain, { collectionDocCount: 10000 });
		expect(r.severity).to.eql("ok");
		expect(r.stage).to.eql("IXSCAN → FETCH");
	});

	it("shouldMonitorQuery skips explain and internal monitor queries", () => {
		const base = { options: {} };
		expect(shouldMonitorQuery(base)).to.be.true;
		expect(shouldMonitorQuery({ options: { explain: "executionStats" } })).to.be.false;
		expect(shouldMonitorQuery({ options: { explain: true } })).to.be.false;
		expect(shouldMonitorQuery({ options: { _indexDiagExplain: true } })).to.be.false;
	});

	it("summarizes filters without throwing", () => {
		expect(summarizeFilter({ email: "a@b.com", day: 1 })).to.include("email");
	});

	it("syncAllModels requires confirm phrase", async () => {
		try {
			await syncAllModels({}, { confirm: "nope" });
			expect.fail("should throw");
		} catch (err) {
			expect(err.message).to.include(SYNC_CONFIRM_PHRASE);
		}
	});

	it("identifies primary auth models", () => {
		expect(isPrimaryAuthModel({ modelName: "APIKey" })).to.be.true;
		expect(isPrimaryAuthModel({ modelName: "User" })).to.be.true;
		expect(isPrimaryAuthModel({ modelName: "Reader" })).to.be.false;
		expect(isPrimaryAuthModel({ modelName: "IndexQueryLog" })).to.be.false;
	});

	it("alignModelIndexes creates missing and drops extras", async () => {
		const { model, wasSyncCalled } = mockModel({
			modelName: "APIKey",
			toCreate: [{ key_hash: 1 }],
			toDrop: ["user_id_1"],
		});
		const result = await alignModelIndexes(model);
		expect(wasSyncCalled()).to.be.true;
		expect(result.created).to.eql([JSON.stringify({ key_hash: 1 })]);
		expect(result.dropped).to.eql(["user_id_1"]);
		expect(result.error).to.be.undefined;
	});

	it("alignModelIndexes skips sync when already aligned", async () => {
		const { model, wasSyncCalled } = mockModel({
			modelName: "User",
			toCreate: [],
			toDrop: [],
		});
		const result = await alignModelIndexes(model);
		expect(wasSyncCalled()).to.be.false;
		expect(result.created).to.eql([]);
		expect(result.dropped).to.eql([]);
	});

	it("ensurePrimaryIndexesAndWarnOthers syncs primary and reports others missing", async () => {
		const api = mockModel({
			modelName: "APIKey",
			toCreate: [],
			toDrop: ["user_id_1"],
		});
		const reader = mockModel({
			modelName: "Reader",
			collectionName: "readers",
			toCreate: [{ email: 1 }],
			toDrop: ["stale_extra_1"],
		});
		const report = await ensurePrimaryIndexesAndWarnOthers(
			{ apikey: api.model, reader: reader.model },
			{ quiet: true }
		);
		expect(api.wasSyncCalled()).to.be.true;
		expect(reader.wasSyncCalled()).to.be.false;
		expect(report.primary).to.have.length(1);
		expect(report.primary[0].dropped).to.eql(["user_id_1"]);
		expect(report.missingOthers).to.have.length(1);
		expect(report.missingOthers[0].modelName).to.eql("Reader");
		expect(report.missingOthers[0].missing).to.eql([{ email: 1 }]);
	});

	it("ensurePrimaryIndexesOnStartup returns null when disabled", async () => {
		const result = await ensurePrimaryIndexesOnStartup(
			{},
			{ index_diagnostics: { ensure_primary_on_startup: false } }
		);
		expect(result).to.eql(null);
	});

	it("listQueryLogs falls back to memory buffer when model unset", async () => {
		setQueryLogModel(null);
		const r = await listQueryLogs({ limit: 10 });
		expect(r).to.have.property("entries");
		expect(r).to.have.property("monitor_status");
		expect(r.persisted).to.eql(false);
		expect(r.entries).to.be.an("array");
	});

	it("formatAuditReportHuman marks OK collections", () => {
		const text = formatAuditReportHuman({
			generatedAt: new Date().toISOString(),
			summary: { total: 1, ok: 1, withMissing: 0, withExtra: 0, errors: 0 },
			collections: [
				{
					modelName: "test",
					collection: "tests",
					ok: true,
					missing: [],
					extra: [],
					schemaIndexes: [],
					dbIndexes: [],
				},
			],
		});
		expect(text).to.include("test: OK");
	});
});
