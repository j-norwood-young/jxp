const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const security = require("../libs/security");
const nodemailer = require("nodemailer");
const errors = require("restify-errors");
const { getModelFromRegistry } = require("./builtin_models");
const totp = require("./totp");
const mfaChallenge = require("./mfa_challenge");
const webauthn = require("./webauthn");

let User = null;

const init = function (models, config) {
	User = getModelFromRegistry(models, "user");
	totp.init(models, config);
	mfaChallenge.init(models, config);
	webauthn.init(models, config);
};

async function mfaMethodsForUser(user) {
	const methods = [];
	if (user.totp_enabled) methods.push("totp");
	return methods;
}

async function issueTokenPair(user_id) {
	const token = await security.refreshToken(user_id);
	const refreshtoken = await security.ensureRefreshToken(user_id);
	return {
		user_id,
		token: token.access_token,
		token_expires: security.tokenExpires(token),
		refresh_token: refreshtoken.refresh_token,
		refresh_token_expires: security.tokenExpires(refreshtoken),
		provider: token.provider,
	};
}

async function requireMfaChallengeResponse(user, config) {
	const methods = await mfaMethodsForUser(user);
	if (!methods.length) return null;
	const challenge = await mfaChallenge.issueMfaChallenge(user._id, config);
	return {
		status: "mfa_required",
		challenge,
		methods,
	};
}

const recover = async (req, res) => {
	try {
		const transporter = nodemailer.createTransport({
			host: req.config.smtp_server,
			port: 25,
			auth: {
				user: req.config.smtp_username,
				pass: req.config.smtp_password,
			},
			tls: { rejectUnauthorized: req.config.smtp_tls_verify !== false },
		});
		const email = req.body.email;
		if (!email) {
			console.error("Missing email parameter");
			throw new errors.BadRequestError("Missing email parameter");
		}
		const user = await User.findOne({ email });
		if (!user) {
			res.send({ status: "ok", message: "If that account exists, recovery instructions will be sent" });
			return;
		}
		const rawToken = crypto.randomBytes(32).toString("base64url");
		user.temp_hash = security.encPassword(rawToken);
		await user.save();
		const token = jwt.sign(
			{ purpose: "password-recovery", jti: rawToken, id: user._id },
			req.config.shared_secret,
			{ expiresIn: "2d" }
		);
		var text = `Someone (hopefully you) requested a password reset. Please click on the following url to recover your password. If you did not request a password reset, you can ignore this message. \n${req.config.password_recovery_url}/${token}`;
		var html = text;
		var mail_format = req.params.mail_format || req.body.mail_format;
		if (mail_format) {
			html = mail_format;
			html = html.replace(/\{\{recover_url\}\}/i, req.config.password_recovery_url + "/" + token);
		}
		transporter.sendMail(
			{
				from: req.config.smtp_from,
				to: user.email,
				subject: "Password Recovery",
				text: text,
				html: html,
			},
			function (result) {
				console.log({ msg: "Mailer result", result });
			}
		);
		res.send({ status: "ok", message: "Sent recovery email" });
	} catch (err) {
		if (err.code) throw err;
		throw new errors.UnauthorizedError(err.toString());
	}
};

const logout = async (req, res) => {
	try {
		if (!res.user) throw new errors.ForbiddenError("You don't seem to be logged in");
		await security.revokeToken(res.user._id);
		res.send({ status: "ok", message: "User logged out" });
	} catch (err) {
		console.error(err);
		if (err.code) throw err;
		throw new errors.InternalServerError(err.toString());
	}
};

const oauth = (req, res, next) => {
	const provider_config = req.config.oauth[req.params.provider];
	if (!provider_config) {
		throw new errors.InternalServerError(`oAuth ${req.params.provider} config not defined`);
	}
	const state = crypto.randomBytes(24).toString("base64url");
	res.header(
		"Set-Cookie",
		`jxp_oauth_state=${encodeURIComponent(state)}; Path=/; HttpOnly; SameSite=Lax`
	);
	const uri = `${provider_config.auth_uri}?client_id=${provider_config.app_id}&redirect_uri=${req.config.url}/login/oauth/callback/${req.params.provider}&scope=${provider_config.scope}&state=${state}&response_type=code`;
	res.redirect(uri, next);
};

const oauth_callback = async (req, res) => {
	const provider = req.params.provider;
	const provider_config = req.config.oauth[provider];
	const code = req.query.code;
	try {
		if (req.query.error) {
			throw (req.query.error);
		}
		const stateCookie = String(req.headers.cookie || "").split(";")
			.map((part) => part.trim())
			.find((part) => part.startsWith("jxp_oauth_state="))
			?.slice("jxp_oauth_state=".length);
		if (!stateCookie || stateCookie !== req.query.state) {
			throw ("oauth_state_invalid");
		}
		if (!code) {
			throw ("missing_code");
		}
		const tokenBody = {
			client_id: provider_config.app_id,
			redirect_uri: `${req.config.url}/login/oauth/callback/${req.params.provider}`,
			client_secret: provider_config.app_secret,
			code: code,
			grant_type: "authorization_code",
		};
		const tokenRes = await fetch(provider_config.token_uri, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(tokenBody),
		});
		if (!tokenRes.ok) {
			throw ("token_request_failed");
		}
		const token = (await tokenRes.json()) as { access_token?: string };
		if (!token.access_token) {
			throw ("missing_access_token");
		}
		const dataRes = await fetch(provider_config.api_uri, {
			headers: { Authorization: `Bearer ${token.access_token}` },
		});
		if (!dataRes.ok) {
			throw ("api_request_failed");
		}
		const data = (await dataRes.json()) as {
			email?: string;
			emailAddress?: string;
			id?: string;
			elements?: Array<{ "handle~"?: { emailAddress?: string } }>;
			[key: string]: unknown;
		};
		if (data.emailAddress) {
			data.email = data.emailAddress;
		}
		if (data.elements && data.elements[0] && data.elements[0]["handle~"] && data.elements[0]["handle~"].emailAddress) { // LinkedIn
			data.email = data.elements[0]["handle~"].emailAddress;
		}
		if (!data.email) {
			throw ("missing_data");
		}
		const search: Record<string, unknown> = {};
		search[provider + ".id"] = data.id;
		const user = await User.findOne(search);
		if (!user) {
			throw ("no_user");
		}
		(user as { [key: string]: unknown })[provider] = data;
		await user.save();
		var jwt_token = jwt.sign({ purpose: "oauth-login", user_id: user._id }, req.config.shared_secret, {
			expiresIn: "1m"
		});
		res.redirect(`${req.config.oauth.success_uri}?token=${jwt_token}`);
	} catch (err) {
		console.error(err);
		if (typeof err === 'string' || err instanceof String) {
			res.redirect(`${req.config.oauth.fail_uri}?error=${err}&provider=${provider}`);
		} else {
			res.redirect(`${req.config.oauth.fail_uri}?error=unknown&provider=${provider}`);
		}
		return;
	}
}

const login = async (req, res) => {
	const ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
	let email = req.params.email || req.body.email;
	let password = req.params.password || req.body.password;
	const userpass = security.basicAuthData(req);
	if (userpass) {
		email = userpass[0];
		password = userpass[1];
	}
	if (!password || !email) {
		console.error(new Date(), "Missing email or password parameters");
		throw new errors.ForbiddenError("Missing email or password parameters");
	}
	try {
		const user = await User.findOne({ email });
		if (!user) {
			console.error(new Date(), `Authentication failed - user not found`, ip, email);
			throw new errors.ForbiddenError("Incorrect email or password");
		}
		if (!(await bcrypt.compare(password, user.password))) {
			console.error(new Date(), `Authentication failed - invalid password`, ip, email);
			throw new errors.ForbiddenError("Incorrect email or password");
		}
		const mfa = await requireMfaChallengeResponse(user, req.config);
		if (mfa) {
			res.result = mfa;
			return;
		}
		res.result = await issueTokenPair(user._id);
	} catch (err) {
		console.error(new Date(), `Authentication failed`, ip, err);
		if (err.code) throw err;
		throw new errors.ForbiddenError("Incorrect email or password");
	}
};

const completeMfa = async (req, res) => {
	try {
		const challenge = req.body?.challenge;
		if (!challenge) {
			throw new errors.BadRequestError("challenge is required");
		}
		const peeked = mfaChallenge.peekMfaChallenge(challenge);
		const code = req.body?.code;
		if (!code) {
			throw new errors.BadRequestError("code is required");
		}
		const ok = await totp.verifyCodeOrBackup(peeked.user_id, code);
		if (!ok) {
			throw new errors.UnauthorizedError("Invalid MFA code");
		}
		await mfaChallenge.consumeMfaChallenge(challenge, req.config);
		res.send(await issueTokenPair(peeked.user_id));
	} catch (err) {
		if (err.code) throw err;
		throw new errors.UnauthorizedError(err.message || "Invalid MFA code");
	}
};

const totpSetup = async (req, res) => {
	try {
		if (!res.user) throw new errors.UnauthorizedError("Unauthorized");
		const result = await totp.setup(res.user._id, res.user.email, req.config);
		res.send(result);
	} catch (err) {
		if (err.code) throw err;
		throw new errors.BadRequestError(err.message || String(err));
	}
};

const totpConfirm = async (req, res) => {
	try {
		if (!res.user) throw new errors.UnauthorizedError("Unauthorized");
		await totp.confirm(res.user._id, req.body?.code);
		res.send({ status: "ok", enabled: true });
	} catch (err) {
		if (err.code) throw err;
		throw new errors.UnauthorizedError(err.message || "Invalid MFA code");
	}
};

const totpDisable = async (req, res) => {
	try {
		if (!res.user) throw new errors.UnauthorizedError("Unauthorized");
		await totp.disable(res.user._id, req.body?.code);
		res.send({ status: "ok", enabled: false });
	} catch (err) {
		if (err.code) throw err;
		throw new errors.UnauthorizedError(err.message || "Invalid MFA code");
	}
};

const totpStatus = async (req, res) => {
	try {
		if (!res.user) throw new errors.UnauthorizedError("Unauthorized");
		res.send(await totp.status(res.user._id));
	} catch (err) {
		if (err.code) throw err;
		throw new errors.InternalServerError(err.toString());
	}
};

const webauthnRegisterOptions = async (req, res) => {
	try {
		if (!res.user) throw new errors.UnauthorizedError("Unauthorized");
		res.send(await webauthn.beginRegistration(res.user, req.config, req));
	} catch (err) {
		if (err.code) throw err;
		throw new errors.BadRequestError(err.message || String(err));
	}
};

const webauthnRegisterVerify = async (req, res) => {
	try {
		if (!res.user) throw new errors.UnauthorizedError("Unauthorized");
		const result = await webauthn.finishRegistration(
			res.user._id,
			{
				challenge_token: req.body?.challenge_token,
				response: req.body?.response || req.body?.credential,
				name: req.body?.name,
			},
			req.config,
			req
		);
		res.send(result);
	} catch (err) {
		if (err.code) throw err;
		throw new errors.BadRequestError(err.message || String(err));
	}
};

const webauthnList = async (req, res) => {
	try {
		if (!res.user) throw new errors.UnauthorizedError("Unauthorized");
		res.send({ data: await webauthn.listCredentials(res.user._id) });
	} catch (err) {
		if (err.code) throw err;
		throw new errors.InternalServerError(err.toString());
	}
};

const webauthnDelete = async (req, res) => {
	try {
		if (!res.user) throw new errors.UnauthorizedError("Unauthorized");
		const status = await totp.status(res.user._id);
		let passwordConfirmed = false;
		if (req.body?.password) {
			const user = await User.findById(res.user._id);
			passwordConfirmed = await bcrypt.compare(req.body.password, user.password);
		}
		await webauthn.deleteCredential(res.user._id, req.params.id, {
			totpEnabled: status.enabled,
			passwordConfirmed,
		});
		res.send({ status: "ok" });
	} catch (err) {
		if (err.code) throw err;
		throw new errors.BadRequestError(err.message || String(err));
	}
};

const webauthnLoginOptions = async (req, res) => {
	try {
		const email = req.body?.email;
		res.send(await webauthn.beginAuthentication({ email }, req.config, req));
	} catch (err) {
		if (err.code) throw err;
		throw new errors.BadRequestError(err.message || String(err));
	}
};

const webauthnLoginVerify = async (req, res) => {
	try {
		const auth = await webauthn.finishAuthentication(
			{
				challenge_token: req.body?.challenge_token,
				response: req.body?.response || req.body?.credential,
			},
			req.config,
			req
		);
		res.send(await issueTokenPair(auth.user_id));
	} catch (err) {
		if (err.code) throw err;
		console.error(new Date().toISOString(), "Passkey login failed:", err.message || err);
		throw new errors.UnauthorizedError(err.message || "Passkey authentication failed");
	}
};

const getJWT = async (req, res) => {
	var user = null;
	if (!security.effectiveAdmin(res)) {
		throw new errors.UnauthorizedError("Unauthorized");
	}
	var email = req.params.email || req.body.email;
	if (!email) {
		throw new errors.BadRequestError("Email required");
	}
	try {
		const result = await User.findOne({ email: email });
		if (!result || !result._id) {
			throw new errors.NotFoundError("User not found");
		}
		user = result;
		try {
			const accessToken = await security.generateToken(user._id);
			res.send({
				email: user.email,
				token: accessToken.access_token,
				token_expires: security.tokenExpires(accessToken),
			});
		} catch (err) {
			throw new errors.UnauthorizedError("Unauthorized");
		}
	} catch (err) {
		if (err.code) throw err;
		throw new errors.InternalServerError(err.toString());
	}
};

const changePassword = async (req, res) => {
	try {
		if (!res.user) throw new errors.UnauthorizedError("Unauthorized");
		const currentPassword = String(req.body?.current_password ?? "");
		const newPassword = String(req.body?.new_password ?? "");
		if (!currentPassword || !newPassword) {
			throw new errors.BadRequestError("current_password and new_password are required");
		}
		if (newPassword.length < 8) {
			throw new errors.BadRequestError("new_password must be at least 8 characters");
		}
		const user = await User.findById(res.user._id);
		if (!user) throw new errors.UnauthorizedError("Unauthorized");
		if (!(await bcrypt.compare(currentPassword, user.password))) {
			throw new errors.UnauthorizedError("Current password is incorrect");
		}
		user.password = security.encPassword(newPassword);
		await user.save();
		res.send({ status: "ok", message: "Password updated" });
	} catch (err) {
		if (err.code) throw err;
		throw new errors.BadRequestError(err.message || String(err));
	}
};

const Login = {
	init,
	recover,
	logout,
	oauth,
	oauth_callback,
	login,
	getJWT,
	changePassword,
	completeMfa,
	totpSetup,
	totpConfirm,
	totpDisable,
	totpStatus,
	webauthnRegisterOptions,
	webauthnRegisterVerify,
	webauthnList,
	webauthnDelete,
	webauthnLoginOptions,
	webauthnLoginVerify,
	requireMfaChallengeResponse,
	issueTokenPair,
	mfaMethodsForUser,
};

module.exports = Login;
