/**
 * Shared WebAuthn helpers for docs login / re-auth.
 * Exposes window.JxpDocsPasskey.login(email) → session JSON { ok, console_key, ... }
 */
(function (global) {
	"use strict";

	function bufferToBase64url(buffer) {
		const bytes = new Uint8Array(buffer);
		let str = "";
		for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
		return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
	}

	function base64urlToBuffer(value) {
		const padded = value.replace(/-/g, "+").replace(/_/g, "/");
		const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
		const binary = atob(padded + pad);
		const bytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
		return bytes.buffer;
	}

	function publicKeyRequestOptions(options) {
		if (window.PublicKeyCredential && typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
			return PublicKeyCredential.parseRequestOptionsFromJSON(options);
		}
		const copy = structuredClone(options);
		copy.challenge = base64urlToBuffer(options.challenge);
		if (copy.allowCredentials) {
			copy.allowCredentials = copy.allowCredentials.map(function (cred) {
				return { ...cred, id: base64urlToBuffer(cred.id) };
			});
		}
		return copy;
	}

	function assertionToJSON(credential) {
		if (typeof credential.toJSON === "function") return credential.toJSON();
		const response = credential.response;
		return {
			id: credential.id,
			rawId: bufferToBase64url(credential.rawId),
			type: credential.type,
			clientExtensionResults: credential.getClientExtensionResults
				? credential.getClientExtensionResults()
				: {},
			response: {
				clientDataJSON: bufferToBase64url(response.clientDataJSON),
				authenticatorData: bufferToBase64url(response.authenticatorData),
				signature: bufferToBase64url(response.signature),
				userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : undefined,
			},
		};
	}

	async function login(email) {
		if (!window.PublicKeyCredential) {
			throw new Error("This browser does not support passkeys");
		}
		const normalized = email ? String(email).trim().toLowerCase() : "";
		if (!normalized || normalized.indexOf("@") < 0) {
			throw new Error("Enter your email above, then click Login with Passkey");
		}
		const optionsRes = await fetch("/docs/session/webauthn/options", {
			method: "POST",
			headers: { "Content-Type": "application/json", Accept: "application/json" },
			credentials: "same-origin",
			body: JSON.stringify({ email: normalized }),
		});
		const begin = await optionsRes.json().catch(function () {
			return {};
		});
		if (optionsRes.status === 429) {
			throw new Error("Too many login attempts. Please wait a minute and try again.");
		}
		if (!optionsRes.ok || !begin.options || !begin.challenge_token) {
			throw new Error(begin.message || "Could not start passkey login");
		}
		if (!begin.options.allowCredentials || !begin.options.allowCredentials.length) {
			throw new Error(
				"No passkey is registered for this email. Sign in with password, then add one under Account → Settings.",
			);
		}
		const assertion = await navigator.credentials.get({
			publicKey: publicKeyRequestOptions(begin.options),
		});
		if (!assertion) throw new Error("Passkey login was cancelled");

		const verifyRes = await fetch("/docs/session/webauthn/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json", Accept: "application/json" },
			credentials: "same-origin",
			body: JSON.stringify({
				challenge_token: begin.challenge_token,
				response: assertionToJSON(assertion),
			}),
		});
		const rawText = await verifyRes.text();
		let sessionBody = {};
		try {
			sessionBody = rawText ? JSON.parse(rawText) : {};
		} catch {
			sessionBody = {};
		}
		if (verifyRes.status === 429) {
			throw new Error("Too many login attempts. Please wait a minute and try again.");
		}
		if (!verifyRes.ok || !sessionBody.ok) {
			const detail =
				sessionBody.message ||
				sessionBody.code ||
				(rawText && rawText.slice(0, 160)) ||
				"Passkey authentication failed";
			throw new Error(detail);
		}
		return sessionBody;
	}

	global.JxpDocsPasskey = { login: login };
})(typeof window !== "undefined" ? window : globalThis);
