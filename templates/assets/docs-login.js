(function () {
	"use strict";

	document.addEventListener("DOMContentLoaded", function () {
		const form = document.getElementById("docs-login-form");
		const errEl = document.getElementById("docs-login-error");
		const credsEl = document.getElementById("docs-login-credentials");
		const mfaEl = document.getElementById("docs-login-mfa");
		const submitBtn = document.getElementById("docs-login-submit");
		const codeInput = document.getElementById("docs-login-code");
		const passkeyBtn = document.getElementById("docs-login-passkey");
		const passkeyWrap = document.getElementById("docs-login-passkey-wrap");
		if (!form || !errEl) return;

		let mfaChallenge = null;

		function showError(msg) {
			errEl.textContent = msg;
			errEl.hidden = false;
		}

		function nextPath() {
			const candidate = form.next && form.next.value ? form.next.value : "";
			return /^\/(?![\/\\])/.test(candidate) && !candidate.includes("\\")
				? candidate
				: "/docs/api";
		}

		function storeSession(sessionBody) {
			if (sessionBody.console_key) {
				sessionStorage.setItem("jxp_docs_console_key", sessionBody.console_key);
				if (sessionBody.console_key_id) {
					sessionStorage.setItem(
						"jxp_docs_console_key_id",
						sessionBody.console_key_id,
					);
				}
			}
		}

		function enterMfaMode(challenge) {
			mfaChallenge = challenge;
			if (credsEl) credsEl.hidden = true;
			if (mfaEl) mfaEl.hidden = false;
			if (passkeyWrap) passkeyWrap.hidden = true;
			if (submitBtn) submitBtn.textContent = "Verify code";
			if (codeInput) {
				codeInput.required = true;
				codeInput.focus();
			}
			form.email && (form.email.required = false);
			form.password && (form.password.required = false);
		}

		form.addEventListener("submit", async function (e) {
			e.preventDefault();
			errEl.hidden = true;

			try {
				let sessRes;
				let sessionBody;

				if (mfaChallenge) {
					sessRes = await fetch("/docs/session/mfa", {
						method: "POST",
						headers: {
							"Content-Type": "application/json",
							Accept: "application/json",
						},
						credentials: "same-origin",
						body: JSON.stringify({
							challenge: mfaChallenge,
							code: codeInput ? codeInput.value.trim() : "",
						}),
					});
				} else {
					const email = form.email.value.trim();
					const password = form.password.value;
					sessRes = await fetch("/docs/session", {
						method: "POST",
						headers: {
							"Content-Type": "application/json",
							Accept: "application/json",
						},
						credentials: "same-origin",
						body: JSON.stringify({ email, password }),
					});
				}

				sessionBody = await sessRes.json().catch(function () {
					return {};
				});

				if (sessRes.status === 429) {
					showError("Too many login attempts. Please wait a minute and try again.");
					return;
				}

				if (sessionBody.status === "mfa_required" && sessionBody.challenge) {
					enterMfaMode(sessionBody.challenge);
					return;
				}

				if (!sessRes.ok || !sessionBody.ok) {
					showError(sessionBody.message || "Incorrect email or password");
					return;
				}
				storeSession(sessionBody);
				window.location.href = nextPath();
			} catch {
				showError("Login request failed");
			}
		});

		if (passkeyBtn) {
			passkeyBtn.addEventListener("click", async function () {
				errEl.hidden = true;
				if (!window.JxpDocsPasskey || typeof window.JxpDocsPasskey.login !== "function") {
					showError("Passkey login is unavailable");
					return;
				}
				passkeyBtn.disabled = true;
				const original = passkeyBtn.innerHTML;
				passkeyBtn.textContent = "Waiting for passkey…";
				try {
					const email = form.email && form.email.value ? form.email.value.trim() : "";
					if (!email) {
						showError("Enter your email above, then click Login with Passkey");
						return;
					}
					const sessionBody = await window.JxpDocsPasskey.login(email);
					storeSession(sessionBody);
					window.location.href = nextPath();
				} catch (err) {
					showError(err.message || "Passkey authentication failed");
				} finally {
					passkeyBtn.disabled = false;
					passkeyBtn.innerHTML = original;
				}
			});
		}
	});
})();
