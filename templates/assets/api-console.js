(function () {
	"use strict";

	const STORAGE_KEY = "jxp_docs_api_key";
	const STORAGE_REMEMBER = "jxp_docs_remember_key";
	const CONSOLE_KEY = "jxp_docs_console_key";
	const CONSOLE_KEY_ID = "jxp_docs_console_key_id";

	let reauthModal = null;
	let reauthBound = false;
	let sessionLoadPromise = null;

	function getApiKey() {
		const input = document.getElementById("docs-api-key");
		return input ? input.value.trim() : "";
	}

	function setApiKeyInput(value) {
		const input = document.getElementById("docs-api-key");
		if (input) {
			input.value = value || "";
			input.dispatchEvent(new Event("input", { bubbles: true }));
		}
	}

	function storeConsoleKey(key, keyId) {
		if (key) sessionStorage.setItem(CONSOLE_KEY, key);
		else sessionStorage.removeItem(CONSOLE_KEY);
		if (keyId) sessionStorage.setItem(CONSOLE_KEY_ID, keyId);
		else sessionStorage.removeItem(CONSOLE_KEY_ID);
	}

	function clearConsoleKey() {
		sessionStorage.removeItem(CONSOLE_KEY);
		sessionStorage.removeItem(CONSOLE_KEY_ID);
		setApiKeyInput("");
	}

	function loadStoredKey() {
		if (localStorage.getItem(STORAGE_REMEMBER) !== "1") return;
		const key = localStorage.getItem(STORAGE_KEY);
		if (!key) return;
		const input = document.getElementById("docs-api-key");
		const remember = document.getElementById("docs-remember-key");
		if (input) input.value = key;
		if (remember) remember.checked = true;
	}

	function saveKeyIfRemembered() {
		const remember = document.getElementById("docs-remember-key");
		const input = document.getElementById("docs-api-key");
		if (!remember || !input) return;
		if (remember.checked) {
			localStorage.setItem(STORAGE_REMEMBER, "1");
			localStorage.setItem(STORAGE_KEY, input.value.trim());
		} else {
			localStorage.removeItem(STORAGE_REMEMBER);
			localStorage.removeItem(STORAGE_KEY);
		}
	}

	function formatBody(text) {
		if (!text) return "";
		try {
			return JSON.stringify(JSON.parse(text), null, 2);
		} catch {
			return text;
		}
	}

	function formatResponse(text) {
		if (!text) return "(empty)";
		try {
			return JSON.stringify(JSON.parse(text), null, 2);
		} catch {
			return text;
		}
	}

	async function sendRequest(panel) {
		const method = panel.dataset.method;
		const pathInput = panel.querySelector(".api-path-input");
		const bodyInput = panel.querySelector(".api-body-input");
		const responseEl = panel.querySelector(".api-response");
		const metaEl = panel.querySelector(".api-response-meta");
		const btn = panel.querySelector(".api-send-btn");

		const path = pathInput ? pathInput.value.trim() : panel.dataset.defaultPath;
		if (!path.startsWith("/")) {
			responseEl.textContent = "Path must start with /";
			responseEl.classList.remove("empty");
			return;
		}

		const headers = { Accept: "application/json" };
		const apiKey = getApiKey();
		if (apiKey) headers["X-API-Key"] = apiKey;

		const opts = { method, headers };
		if (bodyInput && (method === "POST" || method === "PUT")) {
			const raw = bodyInput.value.trim();
			if (raw) {
				headers["Content-Type"] = "application/json";
				opts.body = raw;
			}
		}

		btn.disabled = true;
		responseEl.textContent = "Sending…";
		responseEl.classList.remove("empty");
		metaEl.textContent = "";

		const start = performance.now();
		try {
			const res = await fetch(path, opts);
			const elapsed = Math.round(performance.now() - start);
			const text = await res.text();
			responseEl.textContent = formatResponse(text);
			metaEl.textContent = `HTTP ${res.status} ${res.statusText} · ${elapsed} ms`;
			metaEl.className = "api-response-meta " + (res.ok ? "text-success" : "text-danger");
			if (res.status === 401 && document.documentElement.dataset.docsAccess === "protected") {
				clearConsoleKey();
				showReauthModal("Your API key was rejected. Sign in again to continue.");
			}
		} catch (err) {
			responseEl.textContent = String(err.message || err);
			metaEl.textContent = "Request failed";
			metaEl.className = "api-response-meta text-danger";
		} finally {
			btn.disabled = false;
		}
	}

	function initPanel(panel) {
		const sendBtn = panel.querySelector(".api-send-btn");
		if (sendBtn) {
			sendBtn.addEventListener("click", function () {
				saveKeyIfRemembered();
				sendRequest(panel);
			});
		}
		const bodyInput = panel.querySelector(".api-body-input");
		if (bodyInput) {
			bodyInput.addEventListener("blur", function () {
				bodyInput.value = formatBody(bodyInput.value);
			});
		}
	}

	function getReauthModal() {
		const el = document.getElementById("docs-reauth-modal");
		if (!el || typeof bootstrap === "undefined" || !bootstrap.Modal) return null;
		if (!reauthModal) reauthModal = bootstrap.Modal.getOrCreateInstance(el);
		return reauthModal;
	}

	function showReauthModal(message) {
		const errEl = document.getElementById("docs-reauth-error");
		if (errEl) {
			if (message) {
				errEl.textContent = message;
				errEl.hidden = false;
			} else {
				errEl.hidden = true;
				errEl.textContent = "";
			}
		}
		const modal = getReauthModal();
		if (modal) modal.show();
	}

	function hideReauthModal() {
		const modal = getReauthModal();
		if (modal) modal.hide();
	}

	function bindReauthForm() {
		if (reauthBound) return;
		const form = document.getElementById("docs-reauth-form");
		const errEl = document.getElementById("docs-reauth-error");
		const passkeyBtn = document.getElementById("docs-reauth-passkey");
		if (!form || !errEl) return;
		reauthBound = true;

		function showErr(message) {
			errEl.textContent = message;
			errEl.hidden = false;
		}

		form.addEventListener("submit", async function (e) {
			e.preventDefault();
			errEl.hidden = true;
			const email = form.email.value.trim();
			const password = form.password.value;
			try {
				const sessRes = await fetch("/docs/session", {
					method: "POST",
					headers: {
						"Content-Type": "application/json",
						Accept: "application/json",
					},
					credentials: "same-origin",
					body: JSON.stringify({ email, password }),
				});
				const sessionBody = await sessRes.json().catch(function () {
					return {};
				});
				if (sessRes.status === 429) {
					showErr("Too many login attempts. Please wait a minute and try again.");
					return;
				}
				if (sessionBody.status === "mfa_required") {
					showErr("This account requires an authenticator code. Sign in from the login page.");
					return;
				}
				if (!sessRes.ok || !sessionBody.ok) {
					showErr(sessionBody.message || "Incorrect email or password");
					return;
				}
				storeConsoleKey(sessionBody.console_key, sessionBody.console_key_id);
				setApiKeyInput(sessionBody.console_key || "");
				form.password.value = "";
				sessionLoadPromise = Promise.resolve();
				hideReauthModal();
			} catch {
				showErr("Login request failed");
			}
		});

		if (passkeyBtn) {
			passkeyBtn.addEventListener("click", async function () {
				errEl.hidden = true;
				if (!window.JxpDocsPasskey || typeof window.JxpDocsPasskey.login !== "function") {
					showErr("Passkey login is unavailable");
					return;
				}
				passkeyBtn.disabled = true;
				const original = passkeyBtn.innerHTML;
				passkeyBtn.textContent = "Waiting for passkey…";
				try {
					const email = form.email && form.email.value ? form.email.value.trim() : "";
					if (!email) {
						showErr("Enter your email above, then click Login with Passkey");
						return;
					}
					const sessionBody = await window.JxpDocsPasskey.login(email);
					storeConsoleKey(sessionBody.console_key, sessionBody.console_key_id);
					setApiKeyInput(sessionBody.console_key || "");
					form.password.value = "";
					sessionLoadPromise = Promise.resolve();
					hideReauthModal();
				} catch (err) {
					showErr(err.message || "Passkey authentication failed");
				} finally {
					passkeyBtn.disabled = false;
					passkeyBtn.innerHTML = original;
				}
			});
		}
	}

	/**
	 * Restore the ephemeral console key, or challenge for login when the
	 * session cookie outlives the key (revoked, expired, or cleared storage).
	 */
	function loadSessionApiKey() {
		if (sessionLoadPromise) return sessionLoadPromise;
		sessionLoadPromise = (async function () {
			const access = document.documentElement.dataset.docsAccess;
			if (access !== "protected") return;
			// Login page has no session yet — probing /docs/session only adds a noisy 401.
			if (document.getElementById("docs-login-form")) return;
			bindReauthForm();

			const sessionKey = sessionStorage.getItem(CONSOLE_KEY);
			const storedKeyId = sessionStorage.getItem(CONSOLE_KEY_ID);
			const looksAuthenticated = Boolean(
				document.querySelector('form[action="/docs/logout"]'),
			);

			let session = null;
			try {
				const res = await fetch("/docs/session", { credentials: "same-origin" });
				if (res.ok) {
					session = await res.json();
				}
			} catch {
				/* ignore network errors */
			}

			if (!session || !session.authenticated) {
				clearConsoleKey();
				if (looksAuthenticated) {
					showReauthModal("Your docs session is no longer valid. Sign in again.");
				}
				return;
			}

			if (sessionKey && storedKeyId && storedKeyId === session.console_key_id) {
				setApiKeyInput(sessionKey);
				return;
			}

			// Cookie is valid but plaintext console key is missing or stale.
			clearConsoleKey();
			showReauthModal();
		})();
		return sessionLoadPromise;
	}

	// Expose for MCP / diagnostics pages that also need the console key.
	window.jxpDocsAuth = {
		loadSessionApiKey: loadSessionApiKey,
		showReauthModal: showReauthModal,
		clearConsoleKey: clearConsoleKey,
		storeConsoleKey: storeConsoleKey,
		getConsoleKey: function () {
			return sessionStorage.getItem(CONSOLE_KEY) || "";
		},
	};

	document.addEventListener("DOMContentLoaded", function () {
		const access = document.documentElement.dataset.docsAccess;
		loadSessionApiKey().then(function () {
			if (access !== "protected") loadStoredKey();
		});

		const keyInput = document.getElementById("docs-api-key");
		const remember = document.getElementById("docs-remember-key");
		if (keyInput) {
			keyInput.addEventListener("change", saveKeyIfRemembered);
		}
		if (remember) {
			remember.addEventListener("change", saveKeyIfRemembered);
		}

		document.querySelectorAll(".api-try-panel").forEach(initPanel);
		const logout = document.querySelector('form[action="/docs/logout"]');
		if (logout) {
			logout.addEventListener("submit", async function (event) {
				event.preventDefault();
				clearConsoleKey();
				const csrfCookie = document.cookie.split("; ").find((value) => value.startsWith("jxp_docs_csrf="));
				const token = csrfCookie ? decodeURIComponent(csrfCookie.split("=").slice(1).join("=")) : "";
				await fetch("/docs/logout", {
					method: "POST",
					headers: { "X-CSRF-Token": token },
					credentials: "same-origin"
				});
				window.location.href = "/";
			});
		}
	});
})();
