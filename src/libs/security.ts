const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const errors = require("restify-errors");
const { getModelFromRegistry } = require("./builtin_models");
const apikeys = require("./apikeys");
var APIKey = null;
var Token = null;
var Groups = null;
var User = null;
var RefreshToken = null;
var provider = "";
var passwordRounds = 12;
var tokenPepper = "";

const generateSecret = () => crypto.randomBytes(32).toString("base64url");
const hashToken = value => crypto.createHmac("sha256", tokenPepper).update(value).digest("hex");

const bulkwrite_guard = require("./bulkwrite_guard");
const { logRequestError } = require("./request_log");

const init = function (models, config) {
	APIKey = getModelFromRegistry(models, "apikey");
	Groups = getModelFromRegistry(models, "usergroups");
	User = getModelFromRegistry(models, "user");
	Token = getModelFromRegistry(models, "token");
	RefreshToken = getModelFromRegistry(models, "refreshtoken");
	apikeys.init(models, config);
	passwordRounds = Number(config.bcrypt_rounds || process.env.BCRYPT_ROUNDS || 12);
	tokenPepper = config.shared_secret || process.env.APIKEY_PEPPER || "";
	if (config.url) provider = config.url;
};

/** Verify email + password credentials (login / docs / WS). Not HTTP Basic Auth. */
const basicAuth = async ba => {
	try {
		if (!Array.isArray(ba) || ba.length !== 2) {
			throw ("Credentials incorrectly formatted");
		}
		var email = ba[0];
		var password = ba[1];
		const user = await User.findOne({ email }).exec();
		if (!user) {
			throw (new Date(), `Incorrect username or password for ${email}`);
		}
		if (!await bcrypt.compare(password, user.password)) {
			throw (`Incorrect username or password for ${email}`);
		}
		return user;
	} catch (err) {
		console.error(new Date(), err);
		throw err;
	}
};

const bearerAuthData = req => {
	if (!req.headers.authorization) {
		return false;
	}
	try {
		const token = req.headers.authorization.split(" ")[1];
		return token;
	} catch (err) {
		return false;
	}
}

const bearerAuth = async t => {
	try {
		if (!t) throw ("Token invalid");
		const token = await Token.findOne({
			provider,
			$or: [{ access_token_hash: hashToken(t) }, { access_token: t }],
		}).exec();
		if (!token) {
			throw (`Token ${t} not found`);
		}
		if (!tokenIsValid(token)) {
			throw (`Token is no loger valid`);
		}
		const user = await User.findOne({ _id: token.user_id }).exec();
		if (!user) {
			throw (`Could not find user`);
		}
		return user;
	} catch (err) {
		console.error(err);
		throw err;
	}
}

const apiKeyAuth = async apikey => {
	try {
		if (!apikey) throw ("Missing apikey");
		const result = await apikeys.findApiKey(apikey);
		if (!result) throw ("Could not find apikey");
		const user = await User.findOne({ _id: result.user_id }).exec();
		if (!user) throw ("Could not find user associated to apikey");
		return user;
	} catch (err) {
		console.error(new Date(), err);
		throw err;
	}
};

const apiKeyAuthContext = async apikey => {
	if (!apikey) throw ("Missing apikey");
	const result = await apikeys.findApiKey(apikey);
	if (!result) throw ("Could not find apikey");
	const user = await User.findOne({ _id: result.user_id }).exec();
	if (!user) throw ("Could not find user associated to apikey");
	await apikeys.markUsed(result);
	return { user, apikey: result };
};

const getGroups = async user_id => {
	try {
		const userGroup = await Groups.findOne({ user_id });
		var groups = userGroup && userGroup.groups ? userGroup.groups : [];
		return groups;
	} catch (err) {
		console.error(new Date(), err);
		throw err;
	}
};

const encPassword = password => {
	return bcrypt.hashSync(password, passwordRounds);
};

const generateApiKey = async user_id => {
	try {
		let existing = await APIKey.findOne({ user_id, apikey: { $exists: true } }).sort({ last_accessed: -1 }).exec();
		if (existing) {
			await existing.updateOne({ last_accessed: new Date() });
			return existing;
		}
		const result = await apikeys.createApiKey(user_id, { legacyCompatible: true });
		return result.record;
	} catch (err) {
		console.error(new Date(), err);
		throw err;
	}
};

const tokenIsValid = token => {
	if (!token) return false;
	const now = +new Date();
	const expires_at = +new Date(token.createdAt) + (token.expires_in * 1000);
	return (expires_at > now);
}

const tokenExpires = (token: { createdAt: Date | string; expires_in: number }) => {
	return new Date(new Date(token.createdAt).getTime() + token.expires_in * 1000);
}

const generateToken = async user_id => {
	try {
		var token = new Token();
		token.user_id = user_id;
		const rawToken = generateSecret();
		token.access_token_hash = hashToken(rawToken);
		token.provider = provider;
		await token.save();
		token.access_token = rawToken;
		return token;
	} catch (err) {
		console.error(new Date(), err);
		throw err;
	}
};

const ensureToken = async user_id => {
	try {
		const token = await Token.findOne({ user_id, provider }).sort({ createdAt: -1 }).exec();
		if (tokenIsValid(token) && token.access_token) {
			return token;
		}
		return await generateToken(user_id);
	} catch (err) {
		console.error(new Date(), err);
		throw err;
	}
}

const refreshToken = async user_id => {
	await revokeToken(user_id);
	return await ensureToken(user_id);
}

const revokeToken = async user_id => {
	await Token.deleteOne({ user_id, provider });
	return;
}

const generateRefreshToken = async user_id => {
	try {
		var refreshtoken = new RefreshToken();
		refreshtoken.user_id = user_id;
		const rawRefreshToken = generateSecret();
		refreshtoken.refresh_token_hash = hashToken(rawRefreshToken);
		await refreshtoken.save();
		refreshtoken.refresh_token = rawRefreshToken;
		return refreshtoken;
	} catch (err) {
		console.error(new Date(), err);
		throw err;
	}
};

const ensureRefreshToken = async user_id => {
	const refreshtoken = await RefreshToken.findOne({ user_id }).sort({ createdAt: -1 }).exec();
	if (tokenIsValid(refreshtoken) && refreshtoken.refresh_token) {
		return refreshtoken;
	}
	return await generateRefreshToken(user_id);
}

const revokeRefreshToken = async user_id => {
	await RefreshToken.deleteMany({ user_id });
	return;
}

const refresh = async (req, res) => {
	try {
		if (req.headers.authorization && req.headers.authorization.trim().toLowerCase().indexOf("bearer") === 0) {
			const rawRefreshToken = bearerAuthData(req);
			const refresh_token = await RefreshToken.findOne({
				$or: [{ refresh_token_hash: hashToken(rawRefreshToken) }, { refresh_token: rawRefreshToken }],
			}).exec();
			if (!refresh_token) throw ("Refresh token not found");
			if (!tokenIsValid(refresh_token)) throw ("Refresh token has expired");
			const user_id = refresh_token.user_id;
			const token = await refreshToken(user_id);
			await revokeRefreshToken(user_id);
			const new_refresh_token = await generateRefreshToken(user_id);
			res.send({
				user_id: user_id,
				token: token.access_token,
				token_expires: tokenExpires(token),
				refresh_token: new_refresh_token.refresh_token,
				refresh_token_expires: tokenExpires(new_refresh_token)
			});
		} else {
			throw ("Missing refresh token")
		}
	} catch (err) {
		console.error(err);
		if (err.code) throw err;
		throw new errors.ForbiddenError(err.toString());
	}
}

const login = async (req, res) => {
	try {
		const authenticate_result = await authenticate(req);
		if (!authenticate_result) {
			res.user = null;
			res.groups = [];
			return;
		}
		res = Object.assign(res, authenticate_result);
	} catch (err) {
		console.error(err);
		if (err.code) throw err;
		throw new errors.ForbiddenError(err.toString());
	}
};

const authenticate = async req => {
	let user = null;
	const legacyQueryKey = ["apikey", "api_key", "apiKey", "API_KEY", "x-api-key"]
		.find((name) => req.query && Object.prototype.hasOwnProperty.call(req.query, name));
	if (legacyQueryKey) {
		throw new errors.UnauthorizedError(
			"API keys in query parameters are no longer supported because they leak into logs, browser history, and Referer headers. " +
			"Send the key in the X-API-Key header, use Authorization: Bearer <token>, or upgrade jxp-helper to v3."
		);
	}
	if (!req.headers.authorization && !(req.headers["X-API-Key"] || req.headers["x-api-key"])) {
		return false;
	}
	let apikeyRecord = null;
	if (req.headers.authorization && req.headers.authorization.trim().toLowerCase().indexOf("basic") === 0) {
		throw new errors.UnauthorizedError(
			"Basic Auth is no longer supported because credentials are only base64-encoded and leak easily. " +
			"Use Authorization: Bearer <token> or the X-API-Key header."
		);
	} else if (req.headers.authorization && req.headers.authorization.trim().toLowerCase().indexOf("bearer") === 0) {
		// Token Auth
		user = await bearerAuth(bearerAuthData(req));
	} else if (req.headers["X-API-Key"] || req.headers["x-api-key"]) {
		// API Key
		const rawKey = req.headers["X-API-Key"] || req.headers["x-api-key"];
		const result = await apiKeyAuthContext(Array.isArray(rawKey) ? rawKey[0] : rawKey);
		user = result.user;
		apikeyRecord = result.apikey;
	} else {
		throw ("Could not find any way to authenticate");
	}
	if (!user) {
		throw ("Could not find user");
	}
	return {
		groups: await getGroups(user._id),
		username: user.email,
		user,
		apikey: apikeyRecord
	}

}

const auth = async (req, res) => {
	// Check against model as to whether we're allowed to edit this model
	if (!req.Model) {
		// console.error("Model missing");
		throw new errors.BadRequestError("Model missing");
	}
	try {
		var method = null;
		// console.log("req.route.name", req.route.name);
		if (req.method == "GET" || req.route.name === "postquerymodelname" || req.route.name === "postaggregatemodelname") {
			method = "r";
		} else if (req.method == "POST") {
			method = "c";
		} else if (req.method == "PUT") {
			method = "u";
		} else if (req.method == "DELETE") {
			method = "d";
		} else {
			// console.error("Unsupported operation", req.method);
			throw new errors.InternalServerError(`Unsupported operation: ${req.method}`);
		}
		enforceKeyScope(res.apikey, req.modelname, method);
		const effectiveUser = res.apikey?.allow_admin === false
			? { ...res.user, admin: false }
			: res.user;
		return await check_perms(effectiveUser, res.groups, req.Model, method, req.params.item_id);
	} catch (err) {
		logRequestError(req, res, err, "auth");
		if (err.code) throw err;
		throw new errors.ForbiddenError(err.toString());
	}
};

// Bulk auth: admins bypass; others need perms matching each operation (e.g. updateOne → create + update).
const bulkAuth = async (req, res,) => {
	try {
		const required = bulkwrite_guard.requiredPermsForBulkOps(req.body);
		const effectiveUser = res.apikey?.allow_admin === false
			? { ...res.user, admin: false }
			: res.user;
		for (const method of required) {
			enforceKeyScope(res.apikey, req.modelname, method);
			await check_perms(effectiveUser, res.groups, req.Model, method);
		}
	} catch (err) {
		logRequestError(req, res, err, "bulkAuth");
		if (err.code) throw err;
		throw new errors.ForbiddenError(err.toString());
	}
};

const enforceKeyScope = (key, modelname, method) => {
	if (!key) return;
	if (!apikeys.scopeAllows(key, modelname, method)) {
		throw new errors.ForbiddenError(
			`API key does not grant ${method} access to model ${modelname}`
		);
	}
};

const check_perms = async (user, groups, model, method, item_id?: string) => {
	try {
		const perms = model.schema.get("_perms");
		//If no perms are set, then this isn't an available model
		if (!perms.admin) {
			console.error("Model permissions not set correctly - add an admin section");
			throw new errors.InternalServerError("Model permissions not set correctly - add an admin section");
		}
		//First check if "all" is able to do this. If so, let's get on with it.
		if (perms.all && perms.all.length) {
			if (perms.all.indexOf(method) !== -1) {
				return;
			}
		}
		//This isn't an 'all' situation, so let's bail if the user isn't logged in
		if (!user) {
			throw new errors.ForbiddenError("User not logged in");
		}
		//Let's check perms in this order - admin, user, group, owner
		//Admin check
		if (user.admin && perms.admin && perms.admin.includes(method)) {
			// console.log("Matched permission 'admin':" + method);
			return;
		}
		//User check
		if (perms.user && perms.user.includes(method)) {
			// console.log("Matched permission 'user':" + method);
			return;
		}
		//Group check
		for (let group of groups) {
			if (perms[group] && perms[group].includes(method)) {
				// console.log("Matched permission '" + group + "':" + method);
				return;
			}
		}
		//Owner check
		if (!item_id) throw (`Authorization failed - ${method}`);
		const item = await model.findById(item_id);
		if (item && item._owner_id && item._owner_id.toString() == user._id.toString() && (perms.owner && perms.owner.includes(method))) return;
		throw ("Authorization failed");
	} catch (err) {
		if (err.code) throw err;
		throw new errors.ForbiddenError(err.toString());
	}
}

const admin_only = (req, res, next) => { // Chain after login
	if (!res.user) {
		const err = new errors.ForbiddenError("User not logged in");
		logRequestError(req, res, err, "admin_only");
		return next(err);
	}
	if (!effectiveAdmin(res)) {
		const err = new errors.ForbiddenError("User not admin");
		logRequestError(req, res, err, "admin_only");
		return next(err);
	}
	next();
}

const effectiveAdmin = (res) => Boolean(res.user?.admin && res.apikey?.allow_admin !== false);

const Security = {
	init,
	basicAuth,
	encPassword,
	generateApiKey,
	generateToken,
	ensureToken,
	refreshToken,
	revokeToken,
	tokenExpires,
	generateRefreshToken,
	ensureRefreshToken,
	revokeRefreshToken,
	login,
	refresh,
	authenticate,
	auth,
	admin_only,
	check_perms,
	enforceKeyScope,
	effectiveAdmin,
	getGroups,
	apiKeyAuth,
	apiKeyAuthContext,
	bearerAuth,
	bulkAuth
};

module.exports = Security;
