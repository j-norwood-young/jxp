import { expect, test } from "@playwright/test";

test("anonymous visitors see the JXP landing page without model metadata", async ({ page }) => {
	await page.goto("/");
	await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
	await expect(page.getByText("API at a glance")).toHaveCount(0);
	await expect(page.getByRole("link", { name: /Browse API/i })).toBeVisible();
});

test("anonymous visitors are sent to login before the API browser", async ({ page }) => {
	const response = await page.goto("/docs/api");
	expect(response?.status()).toBe(200);
	await expect(page).toHaveURL(/\/docs\/login/);
	await expect(page.getByRole("heading", { name: /sign in/i })).toBeVisible();
});

test("anonymous model metadata is gated", async ({ request }) => {
	const response = await request.get("/model", { maxRedirects: 0 });
	expect(response.status()).toBe(302);
	expect(response.headers().location).toContain("/docs/login");
});
