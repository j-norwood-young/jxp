/**
 * Load test environment before any JXP modules (mocha --require test/env.js).
 */
process.env.NODE_ENV = "test";

const path = require("path");
const dotenv = require("dotenv");

const root = path.join(__dirname, "..");
dotenv.config({ path: path.join(root, ".env") });
dotenv.config({ path: path.join(root, ".env.test"), override: true });

process.env.MODEL_DIR = process.env.MODEL_DIR || "./dist/models";
process.env.PORT = process.env.PORT || "4005";
process.env.MONGO_CONNECTION_STRING =
	process.env.MONGO_CONNECTION_STRING || "mongodb://127.0.0.1/test";
process.env.LOG_FILE = process.env.LOG_FILE || "./logs/test.log";
process.env.SHARED_SECRET = process.env.SHARED_SECRET || "test-shared-secret";
process.env.APIKEY_PEPPER = process.env.APIKEY_PEPPER || "test-apikey-pepper";
process.env.CACHE_ENABLED = process.env.CACHE_ENABLED ?? "true";
process.env.CACHE_DEBUG = process.env.CACHE_DEBUG ?? "true";
process.env.CACHE_TTL = process.env.CACHE_TTL || "600";
process.env.QUERY_LIMITS_ENABLED = process.env.QUERY_LIMITS_ENABLED ?? "true";
process.env.QUERY_LIMITS_LARGE_COLLECTION_THRESHOLD =
	process.env.QUERY_LIMITS_LARGE_COLLECTION_THRESHOLD || "10000";
process.env.QUERY_LIMITS_MAX = process.env.QUERY_LIMITS_MAX || "1000";
process.env.QUERY_LIMITS_DEFAULT = process.env.QUERY_LIMITS_DEFAULT || "100";
// Docs browser tests use protected mode; set DOCS_ACCESS=public to match old open behavior.
process.env.DOCS_ACCESS = process.env.DOCS_ACCESS || "protected";
// Always off for the shared test server (login_rate_limit.test.js covers throttle in isolation).
process.env.LOGIN_RATE_LIMIT_ENABLED = "false";
