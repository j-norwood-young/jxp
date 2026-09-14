const crypto = require("node:crypto");
const errors = require("restify-errors");
const security = require("./security");
const ObjectID = require('mongodb').ObjectID;
const { getModelFromRegistry } = require("./builtin_models");
var User = null;
const connection_string = require("./connection_string");

const init = (models, _config) => {
	User = getModelFromRegistry(models, "user");
};

const checkUserDoesNotExist = (req, _res, next) => {
	Promise.resolve().then(async () => {
		const configuredToken = req.config?.setup_token || process.env.SETUP_TOKEN;
		const suppliedToken = req.headers?.["x-setup-token"];
		const remoteAddress = req.connection?.remoteAddress || req.socket?.remoteAddress || "";
		const localRequest = ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(remoteAddress);
		if (!configuredToken && !localRequest) {
			throw new errors.ForbiddenError("Initial setup is restricted to localhost; configure SETUP_TOKEN for remote setup");
		}
		if (configuredToken && suppliedToken !== configuredToken) {
			throw new errors.ForbiddenError("Invalid setup token");
		}
		const count = await User.countDocuments();
		if (count) {
			throw new errors.ConflictError("Cannot setup if user exists");
		}
	}).then(() => next()).catch((err) => {
		console.error(err);
		next(err.code ? err : new errors.InternalServerError(err.toString()));
	});
};

const setup = async (req, res) => {
	try {
		const password = (req.body && req.body.password) ? req.body.password : crypto.randomBytes(18).toString("base64url");
		const user = new User({
			password: security.encPassword(password),
			email: req.body.email || "admin@example.com",
			name: req.body.name || "admin",
			admin: true
		});
		await user.save();
		console.log(
			"Created admin user",
			user.name,
			"<" + user.email + ">",
			":",
			password
		);
		res.send({
			status: "success",
			name: user.name,
			email: user.email,
			password
		});
	} catch(err) {
		console.error(err);
		throw new errors.InternalServerError(err.toString());
	}
};

// Unlike setup, which just automates user creation, you can upload any data you want
const data_setup = async (req, res) => {
	try {
		const { MongoClient } = require("mongodb");
		const client = await MongoClient.connect(connection_string);
		const db = client.db(client.databaseName);
		const data = req.body;
		const results = {};
		const _id_reg = new RegExp("_id$");
		for (let collection in data) {
			for (let row of data[collection]) {
				row.createdAt = new Date();
				row._deleted = false;
				// Ensure all _id's are of type id
				for (let field in row) {
					if (_id_reg.test(field)) {
						row[field] = ObjectID(row[field]);
					}
				}
			}
			const result = await db.collection(collection).insertMany(data[collection]);
			results[collection] = result;
		}
		res.send({ status: "success", results });
	} catch(err) {
		console.error(err);
		throw new errors.InternalServerError(err.toString());
	}
}

module.exports = {
	init,
	checkUserDoesNotExist,
	setup,
	data_setup
};
