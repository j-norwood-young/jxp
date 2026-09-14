const { expect } = require("chai");
const apikeys = require("../dist/libs/apikeys");

describe("apikey scopes", () => {
	it("normalizes CRUD permissions in canonical order", () => {
		const scopes = apikeys.normalizeScopes({ reader: "ur", segment: "crud" });
		expect(scopes.get("reader")).to.equal("ru");
		expect(scopes.get("segment")).to.equal("crud");
	});

	it("denies unlisted models when scopes are present", () => {
		const key = { scopes: new Map([["reader", "r"]]) };
		expect(apikeys.scopeAllows(key, "reader", "r")).to.equal(true);
		expect(apikeys.scopeAllows(key, "reader", "u")).to.equal(false);
		expect(apikeys.scopeAllows(key, "segment", "r")).to.equal(false);
	});

	it("inherits all user permissions when scopes are absent", () => {
		expect(apikeys.scopeAllows({}, "segment", "crud")).to.equal(true);
	});

	it("rejects an explicitly empty scope object", () => {
		expect(() => apikeys.normalizeScopes({})).to.throw("omit scopes");
	});
});
