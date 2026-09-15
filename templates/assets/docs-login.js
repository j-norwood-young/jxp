(function () {
	"use strict";

	document.addEventListener("DOMContentLoaded", function () {
		const form = document.getElementById("docs-login-form");
		const errEl = document.getElementById("docs-login-error");
		if (!form || !errEl) return;

		form.addEventListener("submit", async function (e) {
			e.preventDefault();
			errEl.hidden = true;
			const email = form.email.value.trim();
			const password = form.password.value;
			const candidate = form.next && form.next.value ? form.next.value : "";
			const next = /^\/(?![\/\\])/.test(candidate) && !candidate.includes("\\")
				? candidate
				: "/docs/api";

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
					errEl.textContent =
						"Too many login attempts. Please wait a minute and try again.";
					errEl.hidden = false;
					return;
				}
				if (!sessRes.ok || !sessionBody.ok) {
					errEl.textContent =
						sessionBody.message || "Incorrect email or password";
					errEl.hidden = false;
					return;
				}
				if (sessionBody.console_key) {
					sessionStorage.setItem("jxp_docs_console_key", sessionBody.console_key);
					if (sessionBody.console_key_id) {
						sessionStorage.setItem(
							"jxp_docs_console_key_id",
							sessionBody.console_key_id,
						);
					}
				}

				window.location.href = next;
			} catch {
				errEl.textContent = "Login request failed";
				errEl.hidden = false;
			}
		});
	});
})();
