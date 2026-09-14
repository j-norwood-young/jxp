(function () {
	"use strict";

	function csrf() {
		const part = document.cookie.split("; ").find((value) => value.startsWith("jxp_docs_csrf="));
		return part ? decodeURIComponent(part.split("=").slice(1).join("=")) : "";
	}

	function scopeLabel(scopes) {
		if (!scopes || !Object.keys(scopes).length) return "Full access (inherits your permissions)";
		return Object.entries(scopes).map(([model, perms]) => `${model}: ${perms}`).join(", ");
	}

	async function loadKeys() {
		const response = await fetch("/docs/account/keys/data", { credentials: "same-origin" });
		if (!response.ok) throw new Error("Could not load API keys");
		const keys = await response.json();
		const list = document.getElementById("keys-list");
		list.replaceChildren();
		for (const key of keys) {
			const row = document.createElement("tr");
			const values = [
				`${key.name || "API key"} ${key.key_prefix || ""}…${key.last4 || ""}`,
				scopeLabel(key.scopes),
				key.expires_at ? new Date(key.expires_at).toLocaleString() : "Never",
				key.last_used_at ? new Date(key.last_used_at).toLocaleString() : "Never"
			];
			for (const value of values) {
				const cell = document.createElement("td");
				cell.textContent = value;
				row.appendChild(cell);
			}
			const actions = document.createElement("td");
			const revoke = document.createElement("button");
			revoke.className = "btn btn-sm btn-outline-danger revoke-key";
			revoke.dataset.id = key._id;
			revoke.textContent = "Revoke";
			actions.appendChild(revoke);
			row.appendChild(actions);
			list.appendChild(row);
		}
		document.querySelectorAll(".revoke-key").forEach((button) => {
			button.addEventListener("click", async () => {
				await fetch(`/docs/account/keys/${button.dataset.id}/revoke`, {
					method: "POST",
					headers: { "X-CSRF-Token": csrf(), Accept: "application/json" }
				});
				await loadKeys();
			});
		});
	}

	document.addEventListener("DOMContentLoaded", () => {
		const limited = document.getElementById("limited-key");
		const table = document.getElementById("scope-table");
		limited.addEventListener("change", () => table.classList.toggle("d-none", !limited.checked));
		document.getElementById("copy-key").addEventListener("click", () => navigator.clipboard.writeText(document.getElementById("new-key").value));
		document.getElementById("key-create-form").addEventListener("submit", async (event) => {
			event.preventDefault();
			const scopes = {};
			if (limited.checked) {
				document.querySelectorAll("[data-model]").forEach((row) => {
					const permissions = [...row.querySelectorAll(".scope-perm:checked")].map((box) => box.dataset.method).join("");
					if (permissions) scopes[row.dataset.model] = permissions;
				});
			}
			const response = await fetch("/docs/account/keys", {
				method: "POST",
				headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf(), Accept: "application/json" },
				body: JSON.stringify({
					name: document.getElementById("key-name").value,
					expires_at: document.getElementById("key-expires").value || undefined,
					allow_admin: document.getElementById("key-admin").checked,
					...(limited.checked ? { scopes } : {})
				})
			});
			const result = await response.json();
			if (!response.ok) {
				document.getElementById("key-error").textContent = result.message || "Could not create key";
				return;
			}
			document.getElementById("new-key").value = result.key;
			document.getElementById("key-created").classList.remove("d-none");
			event.target.reset();
			table.classList.add("d-none");
			await loadKeys();
		});
		loadKeys().catch((error) => { document.getElementById("key-error").textContent = error.message; });
	});
})();
