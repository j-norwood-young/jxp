import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
	testDir: "./test/e2e",
	fullyParallel: false,
	forbidOnly: !!process.env.CI,
	retries: process.env.CI ? 2 : 0,
	reporter: "html",
	use: {
		baseURL: process.env.BASE_URL ?? "http://127.0.0.1:4001",
		trace: "on-first-retry",
		screenshot: "only-on-failure",
	},
	projects: [
		{
			name: "chromium",
			use: { ...devices["Desktop Chrome"] },
		},
	],
	webServer: {
		command: "npm run build && node dist/bin/server.js",
		url: process.env.BASE_URL ?? "http://127.0.0.1:4001",
		reuseExistingServer: !process.env.CI,
		timeout: 30_000,
	},
});
