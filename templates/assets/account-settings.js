(function () {
	"use strict";

	function consoleKey() {
		return sessionStorage.getItem("jxp_docs_console_key") || "";
	}

	function authHeaders(json) {
		const headers = {
			Accept: "application/json",
			"X-API-Key": consoleKey(),
		};
		if (json) headers["Content-Type"] = "application/json";
		return headers;
	}

	function flash(message, kind) {
		const el = document.getElementById("settings-flash");
		if (!el) return;
		el.textContent = message;
		el.className = `alert alert-${kind || "success"}`;
		el.classList.remove("d-none");
		el.scrollIntoView({ behavior: "smooth", block: "nearest" });
	}

	function setInlineError(id, message) {
		const el = document.getElementById(id);
		if (!el) return;
		if (!message) {
			el.hidden = true;
			el.textContent = "";
			return;
		}
		el.hidden = false;
		el.textContent = message;
	}

	function requireKey() {
		if (!consoleKey()) {
			flash("Docs console key missing. Sign in again.", "danger");
			return false;
		}
		return true;
	}

	async function api(path, options) {
		const response = await fetch(path, {
			credentials: "same-origin",
			...options,
			headers: {
				...authHeaders(Boolean(options && options.body)),
				...(options && options.headers),
			},
		});
		const body = await response.json().catch(function () {
			return {};
		});
		if (!response.ok) {
			const err = new Error(body.message || body.err || `Request failed (${response.status})`);
			err.status = response.status;
			err.body = body;
			throw err;
		}
		return body;
	}

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

	function publicKeyCreateOptions(options) {
		if (window.PublicKeyCredential && typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
			return PublicKeyCredential.parseCreationOptionsFromJSON(options);
		}
		const copy = structuredClone(options);
		copy.challenge = base64urlToBuffer(options.challenge);
		copy.user.id = base64urlToBuffer(options.user.id);
		if (copy.excludeCredentials) {
			copy.excludeCredentials = copy.excludeCredentials.map(function (cred) {
				return { ...cred, id: base64urlToBuffer(cred.id) };
			});
		}
		return copy;
	}

	function credentialToJSON(credential) {
		if (typeof credential.toJSON === "function") return credential.toJSON();
		const response = credential.response;
		const json = {
			id: credential.id,
			rawId: bufferToBase64url(credential.rawId),
			type: credential.type,
			clientExtensionResults: credential.getClientExtensionResults
				? credential.getClientExtensionResults()
				: {},
			response: {
				clientDataJSON: bufferToBase64url(response.clientDataJSON),
				attestationObject: bufferToBase64url(response.attestationObject),
			},
		};
		if (response.getTransports) json.response.transports = response.getTransports();
		return json;
	}

	function withBusy(button, busy) {
		if (!button) return;
		button.disabled = busy;
		button.dataset.originalText = button.dataset.originalText || button.textContent;
		button.textContent = busy ? "Working…" : button.dataset.originalText;
	}

	function getModal(id) {
		const el = document.getElementById(id);
		if (!el || typeof bootstrap === "undefined" || !bootstrap.Modal) return null;
		return bootstrap.Modal.getOrCreateInstance(el);
	}

	function showModal(id) {
		const modal = getModal(id);
		if (modal) modal.show();
	}

	function hideModal(id) {
		const modal = getModal(id);
		if (modal) modal.hide();
	}

	let totpEnabled = false;
	let passkeyCount = 0;
	let pendingPasskeyDeleteId = null;
	let pendingPasskeyCredential = null;
	let pendingPasskeyChallenge = null;

	async function refreshTotp() {
		const status = await api("/login/totp/status", { method: "GET" });
		totpEnabled = Boolean(status.enabled);
		const badge = document.getElementById("totp-status");
		const enabled = document.getElementById("totp-enabled-panel");
		const disabled = document.getElementById("totp-disabled-panel");
		if (status.enabled) {
			badge.textContent = "Enabled";
			badge.className = "badge docs-settings-status text-bg-success";
			enabled.classList.remove("d-none");
			disabled.classList.add("d-none");
		} else {
			badge.textContent = "Disabled";
			badge.className = "badge docs-settings-status text-bg-secondary";
			enabled.classList.add("d-none");
			disabled.classList.remove("d-none");
		}
		return status;
	}

	async function refreshPasskeys() {
		const result = await api("/login/webauthn/credentials", { method: "GET" });
		const list = document.getElementById("passkeys-list");
		list.replaceChildren();
		const rows = result.data || [];
		passkeyCount = rows.length;
		if (!rows.length) {
			const empty = document.createElement("tr");
			const cell = document.createElement("td");
			cell.colSpan = 4;
			cell.className = "text-muted";
			cell.textContent = "No passkeys registered yet.";
			empty.appendChild(cell);
			list.appendChild(empty);
			return rows;
		}
		for (const item of rows) {
			const row = document.createElement("tr");
			const values = [
				item.name || "Passkey",
				item.createdAt ? new Date(item.createdAt).toLocaleString() : "—",
				item.device_type || "—",
			];
			for (const value of values) {
				const cell = document.createElement("td");
				cell.textContent = value;
				row.appendChild(cell);
			}
			const actions = document.createElement("td");
			const button = document.createElement("button");
			button.type = "button";
			button.className = "btn btn-sm btn-outline-danger";
			button.textContent = "Remove";
			button.addEventListener("click", function () {
				openPasskeyDeleteModal(item);
			});
			actions.appendChild(button);
			row.appendChild(actions);
			list.appendChild(row);
		}
		return rows;
	}

	function openPasskeyDeleteModal(item) {
		pendingPasskeyDeleteId = item.id;
		setInlineError("passkey-delete-error", "");
		const passwordInput = document.getElementById("passkey-delete-password");
		const passwordWrap = document.getElementById("passkey-delete-password-wrap");
		const message = document.getElementById("passkey-delete-message");
		passwordInput.value = "";
		const needsPassword = passkeyCount <= 1 && !totpEnabled;
		passwordWrap.classList.toggle("d-none", !needsPassword);
		passwordInput.required = needsPassword;
		message.textContent = needsPassword
			? `Remove “${item.name || "Passkey"}”? This is your last passkey and TOTP is off — enter your password to confirm.`
			: `Remove “${item.name || "Passkey"}” from your account?`;
		showModal("passkey-delete-modal");
		if (needsPassword) {
			setTimeout(function () {
				passwordInput.focus();
			}, 200);
		}
	}

	function promptPasskeyName() {
		return new Promise(function (resolve) {
			const modalEl = document.getElementById("passkey-name-modal");
			const form = document.getElementById("passkey-name-form");
			const input = document.getElementById("passkey-name-input");
			const modal = getModal("passkey-name-modal");
			if (!modalEl || !form || !input || !modal) {
				resolve("Passkey");
				return;
			}

			input.value = "Passkey";
			let settled = false;

			function finish(value) {
				if (settled) return;
				settled = true;
				modalEl.removeEventListener("hidden.bs.modal", onHidden);
				form.removeEventListener("submit", onSubmit);
				resolve(value);
			}

			function onHidden() {
				finish(null);
			}

			function onSubmit(event) {
				event.preventDefault();
				const name = input.value.trim() || "Passkey";
				modal.hide();
				finish(name);
			}

			modalEl.addEventListener("hidden.bs.modal", onHidden);
			form.addEventListener("submit", onSubmit);
			modal.show();
			setTimeout(function () {
				input.focus();
				input.select();
			}, 200);
		});
	}

	document.addEventListener("DOMContentLoaded", function () {
		if (!requireKey()) return;

		document.getElementById("password-form").addEventListener("submit", async function (event) {
			event.preventDefault();
			const currentPassword = document.getElementById("current-password").value;
			const newPassword = document.getElementById("new-password").value;
			const confirmPassword = document.getElementById("confirm-password").value;
			if (newPassword !== confirmPassword) {
				flash("New passwords do not match.", "danger");
				return;
			}
			const submit = event.target.querySelector('[type="submit"]');
			withBusy(submit, true);
			try {
				await api("/login/password", {
					method: "POST",
					body: JSON.stringify({
						current_password: currentPassword,
						new_password: newPassword,
					}),
				});
				event.target.reset();
				flash("Password updated.");
			} catch (err) {
				flash(err.message, "danger");
			} finally {
				withBusy(submit, false);
			}
		});

		document.getElementById("totp-start-btn").addEventListener("click", async function () {
			const btn = document.getElementById("totp-start-btn");
			withBusy(btn, true);
			try {
				const setup = await api("/login/totp/setup", { method: "POST", body: "{}" });
				const qr = document.getElementById("totp-qr");
				if (setup.qr_data_url) {
					qr.src = setup.qr_data_url;
					qr.hidden = false;
				} else {
					qr.removeAttribute("src");
					qr.hidden = true;
				}
				document.getElementById("totp-secret").textContent = setup.secret;
				document.getElementById("totp-otpauth-link").href = setup.otpauth_url;
				document.getElementById("totp-backup-codes").textContent = (setup.backup_codes || []).join(
					"\n",
				);
				setInlineError("totp-confirm-error", "");
				document.getElementById("totp-confirm-code").value = "";
				showModal("totp-setup-modal");
				setTimeout(function () {
					document.getElementById("totp-confirm-code").focus();
				}, 300);
			} catch (err) {
				flash(err.message, "danger");
			} finally {
				withBusy(btn, false);
			}
		});

		document.getElementById("totp-confirm-form").addEventListener("submit", async function (event) {
			event.preventDefault();
			setInlineError("totp-confirm-error", "");
			const code = document.getElementById("totp-confirm-code").value.trim().replace(/\s+/g, "");
			if (!/^\d{6}$/.test(code)) {
				setInlineError(
					"totp-confirm-error",
					"Enter the 6-digit code from your authenticator (not the secret or a backup code).",
				);
				return;
			}
			const submit = document.querySelector('#totp-setup-modal [type="submit"]');
			withBusy(submit, true);
			try {
				await api("/login/totp/confirm", {
					method: "POST",
					body: JSON.stringify({ code: code }),
				});
				hideModal("totp-setup-modal");
				flash("Authenticator enabled.");
				await refreshTotp();
			} catch (err) {
				setInlineError("totp-confirm-error", err.message);
			} finally {
				withBusy(submit, false);
			}
		});

		document.getElementById("totp-disable-btn").addEventListener("click", function () {
			setInlineError("totp-disable-error", "");
			document.getElementById("totp-disable-code").value = "";
			showModal("totp-disable-modal");
			setTimeout(function () {
				document.getElementById("totp-disable-code").focus();
			}, 200);
		});

		document.getElementById("totp-disable-form").addEventListener("submit", async function (event) {
			event.preventDefault();
			setInlineError("totp-disable-error", "");
			const code = document.getElementById("totp-disable-code").value.trim().replace(/\s+/g, "");
			if (!code) {
				setInlineError("totp-disable-error", "Enter a 6-digit authenticator code or a backup code.");
				return;
			}
			if (!/^\d{6}$/.test(code) && !/^[a-fA-F0-9]{8,}$/.test(code)) {
				setInlineError(
					"totp-disable-error",
					"Use a 6-digit authenticator code or one of your backup codes.",
				);
				return;
			}
			const submit = event.target.querySelector('[type="submit"]');
			withBusy(submit, true);
			try {
				await api("/login/totp/disable", {
					method: "POST",
					body: JSON.stringify({ code: code }),
				});
				hideModal("totp-disable-modal");
				flash("Authenticator disabled.");
				await refreshTotp();
			} catch (err) {
				setInlineError("totp-disable-error", err.message);
			} finally {
				withBusy(submit, false);
			}
		});

		document.getElementById("passkey-delete-form").addEventListener("submit", async function (event) {
			event.preventDefault();
			if (!pendingPasskeyDeleteId || !requireKey()) return;
			setInlineError("passkey-delete-error", "");
			const passwordInput = document.getElementById("passkey-delete-password");
			const passwordWrap = document.getElementById("passkey-delete-password-wrap");
			const needsPassword = !passwordWrap.classList.contains("d-none");
			const password = passwordInput.value;
			if (needsPassword && !password) {
				setInlineError("passkey-delete-error", "Enter your password to continue.");
				passwordInput.focus();
				return;
			}
			const submit = event.target.querySelector('[type="submit"]');
			withBusy(submit, true);
			try {
				await api(`/login/webauthn/credentials/${encodeURIComponent(pendingPasskeyDeleteId)}/delete`, {
					method: "POST",
					body: JSON.stringify(password ? { password } : {}),
				});
				hideModal("passkey-delete-modal");
				pendingPasskeyDeleteId = null;
				flash("Passkey removed.");
				await refreshPasskeys();
			} catch (err) {
				const msg = String(err.message || "");
				if (/password/i.test(msg)) {
					passwordWrap.classList.remove("d-none");
					passwordInput.required = true;
					setInlineError("passkey-delete-error", "Enter your password to remove this passkey.");
					passwordInput.focus();
				} else {
					setInlineError("passkey-delete-error", msg);
				}
			} finally {
				withBusy(submit, false);
			}
		});

		document.getElementById("passkey-add-btn").addEventListener("click", async function () {
			if (!window.PublicKeyCredential) {
				flash("This browser does not support passkeys.", "danger");
				return;
			}
			const btn = document.getElementById("passkey-add-btn");
			withBusy(btn, true);
			try {
				const begin = await api("/login/webauthn/register/options", {
					method: "POST",
					body: "{}",
				});
				const credential = await navigator.credentials.create({
					publicKey: publicKeyCreateOptions(begin.options),
				});
				if (!credential) throw new Error("Passkey creation was cancelled");
				pendingPasskeyCredential = credential;
				pendingPasskeyChallenge = begin.challenge_token;
				const name = await promptPasskeyName();
				if (!name) {
					pendingPasskeyCredential = null;
					pendingPasskeyChallenge = null;
					flash("Passkey registration cancelled.", "warning");
					return;
				}
				await api("/login/webauthn/register/verify", {
					method: "POST",
					body: JSON.stringify({
						challenge_token: pendingPasskeyChallenge,
						name: name,
						response: credentialToJSON(pendingPasskeyCredential),
					}),
				});
				pendingPasskeyCredential = null;
				pendingPasskeyChallenge = null;
				flash("Passkey registered.");
				await refreshPasskeys();
			} catch (err) {
				pendingPasskeyCredential = null;
				pendingPasskeyChallenge = null;
				flash(err.message || "Could not register passkey", "danger");
			} finally {
				withBusy(btn, false);
			}
		});

		Promise.all([refreshTotp(), refreshPasskeys()]).catch(function (err) {
			flash(err.message, "danger");
		});
	});
})();
