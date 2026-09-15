const { expect } = require("chai");
const {
	sanitizeFilter,
	sanitizeAggregateMatch,
} = require("../dist/libs/query_sanitize");

describe("query_sanitize", () => {
	describe("sanitizeFilter", () => {
		it("rejects $expr in list/query filters", () => {
			expect(() =>
				sanitizeFilter({
					$expr: { $eq: ["$foo", "bar"] },
				})
			).to.throw("Operator $expr is not allowed");
		});

		it("rejects $where", () => {
			expect(() => sanitizeFilter({ $where: "true" })).to.throw(
				"Operator $where is not allowed"
			);
		});

		it("allows ordinary field filters", () => {
			const filter = { foo: "bar", count: { $gte: 1 } };
			expect(sanitizeFilter(filter)).to.equal(filter);
		});
	});

	describe("sanitizeAggregateMatch", () => {
		it("allows $expr in aggregate $match", () => {
			const match = {
				$expr: {
					$and: [{ $gte: ["$createdAt", { $dateFromString: { dateString: "2020-01-01" } }] }],
				},
			};
			expect(sanitizeAggregateMatch(match)).to.equal(match);
		});

		it("still rejects $where inside aggregate $match", () => {
			expect(() => sanitizeAggregateMatch({ $where: "true" })).to.throw(
				"Operator $where is not allowed"
			);
		});

		it("still rejects $function nested under $expr", () => {
			expect(() =>
				sanitizeAggregateMatch({
					$expr: {
						$function: { body: "function() { return true; }", args: [], lang: "js" },
					},
				})
			).to.throw("Operator $function is not allowed");
		});
	});
});
