import { describe, expect, it } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { OidcFetch } from "../src/login-command.ts";
import { createClientRegistry } from "../src/client-registry.ts";
import { createCredentialVault } from "../src/credential-vault.ts";
import { createApp } from "../src/server.ts";

const TOKEN = "test-admin-token";

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** Stubs GitLab's token endpoint refresh directly — the credential itself carries baseUrl/clientId, so resolveRefreshFn finds this without a name-based registry. */
const gitlabRefreshFetch: OidcFetch = async (input) => {
	const url = String(input);
	if (url === "https://gitlab.example.com/oauth/token") {
		return jsonResponse({ access_token: "rotated-gitlab-token", token_type: "bearer", expires_in: 7200 });
	}
	throw new Error(`unexpected fetch in test: ${url}`);
};

function buildDeps(dir: string) {
	const vault = createCredentialVault({ dir, masterKey: randomBytes(32) });
	const clients = createClientRegistry(join(dir, "clients.json"));
	return { vault, token: TOKEN, clients, fetchImpl: gitlabRefreshFetch };
}

function withToken(path: string, token: string, init: RequestInit = {}): Request {
	return new Request(`http://enigma.local${path}`, {
		...init,
		headers: { ...init.headers, authorization: `Bearer ${token}` },
	});
}

function authed(path: string, init: RequestInit = {}): Request {
	return new Request(`http://enigma.local${path}`, {
		...init,
		headers: { ...init.headers, authorization: `Bearer ${TOKEN}` },
	});
}

describe("enigma vault server", () => {
	it("rejects every route without a valid bearer token", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const app = createApp(buildDeps(dir));
			const response = await app.fetch(new Request("http://enigma.local/health"));
			expect(response.status).toBe(401);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("serves health and ready", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const app = createApp(buildDeps(dir));
			const health = await app.fetch(authed("/health"));
			expect(health.status).toBe(200);
			expect((await health.json() as { ok: boolean }).ok).toBe(true);

			const ready = await app.fetch(authed("/ready"));
			expect(ready.status).toBe(200);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("GET /keys lists stored backends, empty when none configured yet", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			expect(await (await app.fetch(authed("/keys"))).json()).toEqual([]);

			deps.vault.save("github", { accessToken: "gh-token" });
			expect(await (await app.fetch(authed("/keys"))).json()).toEqual(["github"]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("GET /creds/:backend returns the stored credential, 404 when not configured", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			deps.vault.save("jenkins", { accessToken: "jenkins-token", extra: { url: "https://jenkins.example.com" } });

			const found = await app.fetch(authed("/creds/jenkins"));
			expect(found.status).toBe(200);
			expect(await found.json()).toEqual({ accessToken: "jenkins-token", extra: { url: "https://jenkins.example.com" } });

			const missing = await app.fetch(authed("/creds/nonexistent"));
			expect(missing.status).toBe(404);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("GET /creds/:backend is case-insensitive end to end -- a credential stored under one casing is reachable via any other", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			deps.vault.save("WidgetApi", { accessToken: "widget-token" });

			expect(await (await app.fetch(authed("/creds/widgetapi"))).json()).toEqual({ accessToken: "widget-token" });
			expect(await (await app.fetch(authed("/creds/WIDGETAPI"))).json()).toEqual({ accessToken: "widget-token" });
			expect(await (await app.fetch(authed("/creds/WidgetApi"))).json()).toEqual({ accessToken: "widget-token" });
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /rotate/:backend refreshes and persists, using the backend's own refresh function", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			deps.vault.save("gitlab", { accessToken: "stale-gitlab-token", refreshToken: "r1", extra: { baseUrl: "https://gitlab.example.com", clientId: "c" } });

			const response = await app.fetch(authed("/rotate/gitlab", { method: "POST" }));
			expect(response.status).toBe(204);
			expect(deps.vault.get("gitlab")?.accessToken).toBe("rotated-gitlab-token");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /rotate/:backend on a backend with no refresh function configured returns 400, not a silent no-op", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			deps.vault.save("github", { accessToken: "gh-token" });

			const response = await app.fetch(authed("/rotate/github", { method: "POST" }));
			expect(response.status).toBe(400);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /rotate/:backend on a backend with no stored credential returns 404", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const app = createApp(buildDeps(dir));
			const response = await app.fetch(authed("/rotate/gitlab", { method: "POST" }));
			expect(response.status).toBe(404);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /revoke/:backend deletes the stored credential and is idempotent", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			deps.vault.save("github", { accessToken: "gh-token" });

			expect((await app.fetch(authed("/revoke/github", { method: "POST" }))).status).toBe(204);
			expect(deps.vault.get("github")).toBeUndefined();
			// Revoking again (already absent) is idempotent, not an error.
			expect((await app.fetch(authed("/revoke/github", { method: "POST" }))).status).toBe(204);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("returns 404 for an unknown route", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const app = createApp(buildDeps(dir));
			expect((await app.fetch(authed("/nonexistent-route"))).status).toBe(404);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("per-client scoped access to GET /creds/:backend", () => {
	it("a registered client's own token can fetch a backend it's registered for", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			deps.vault.save("jira", { accessToken: "jira-token" });
			const clientToken = deps.clients.add("tickets", ["jira", "github"]);
			const app = createApp(deps);

			const response = await app.fetch(withToken("/creds/jira", clientToken));
			expect(response.status).toBe(200);
			expect(await response.json()).toEqual({ accessToken: "jira-token" });
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("a client registered before backend names were normalized (raw mixed-case data on disk, not written through registry.add) still gets scoped access -- defense in depth, not just a write-time fix", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			deps.vault.save("widgetapi", { accessToken: "widget-token" });

			const legacyToken = "legacy-plaintext-token-not-real";
			const registryPath = join(dir, "clients.json");
			writeFileSync(
				registryPath,
				JSON.stringify({
					version: 1,
					clients: [
						{
							name: "acme-consumer",
							backends: ["WidgetApi"], // raw casing, as production data looked before normalization
							tokenHash: createHash("sha256").update(legacyToken).digest("hex"),
							createdAt: new Date().toISOString(),
						},
					],
				}),
			);

			const app = createApp(deps);
			const response = await app.fetch(withToken("/creds/widgetapi", legacyToken));
			expect(response.status).toBe(200);
			expect(await response.json()).toEqual({ accessToken: "widget-token" });
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("a client's scope check is case-insensitive end to end -- registered with one casing, credential stored and requested with others", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			deps.vault.save("WidgetApi", { accessToken: "widget-token" });
			const clientToken = deps.clients.add("acme-consumer", ["widgetapi"]);
			const app = createApp(deps);

			const response = await app.fetch(withToken("/creds/WIDGETAPI", clientToken));
			expect(response.status).toBe(200);
			expect(await response.json()).toEqual({ accessToken: "widget-token" });
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("rejects a registered client's own token for a backend it was not registered for", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			deps.vault.save("jenkins", { accessToken: "jenkins-token" });
			const clientToken = deps.clients.add("tickets", ["jira", "github"]);
			const app = createApp(deps);

			const response = await app.fetch(withToken("/creds/jenkins", clientToken));
			expect(response.status).toBe(403);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("rejects an unrecognized token outright, distinct from a wrong-scope rejection", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			deps.vault.save("jira", { accessToken: "jira-token" });
			const app = createApp(deps);

			const response = await app.fetch(withToken("/creds/jira", "not-a-real-token"));
			expect(response.status).toBe(401);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("the admin token still works against /creds/:backend regardless of client registration", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			deps.vault.save("jira", { accessToken: "jira-token" });
			const app = createApp(deps);

			expect((await app.fetch(authed("/creds/jira"))).status).toBe(200);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("a client's own token is refused on admin-only routes (health, keys, rotate, revoke)", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const clientToken = deps.clients.add("tickets", ["jira"]);
			const app = createApp(deps);

			expect((await app.fetch(withToken("/health", clientToken))).status).toBe(401);
			expect((await app.fetch(withToken("/keys", clientToken))).status).toBe(401);
			expect((await app.fetch(withToken("/rotate/jira", clientToken, { method: "POST" }))).status).toBe(401);
			expect((await app.fetch(withToken("/revoke/jira", clientToken, { method: "POST" }))).status).toBe(401);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("a removed client's token stops working immediately", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			deps.vault.save("jira", { accessToken: "jira-token" });
			const clientToken = deps.clients.add("tickets", ["jira"]);
			const app = createApp(deps);
			expect((await app.fetch(withToken("/creds/jira", clientToken))).status).toBe(200);

			deps.clients.remove("tickets");
			expect((await app.fetch(withToken("/creds/jira", clientToken))).status).toBe(401);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("GET /whoami", () => {
	it("a registered client's own token returns its name and its backend list, normalized to lowercase regardless of the casing it was registered with", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const clientToken = deps.clients.add("acme-consumer", ["WidgetApi", "GadgetApi"]);
			const app = createApp(deps);

			const response = await app.fetch(withToken("/whoami", clientToken));
			expect(response.status).toBe(200);
			expect(await response.json()).toEqual({ name: "acme-consumer", backends: ["widgetapi", "gadgetapi"] });
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("the admin token gets a distinct, unrestricted self-description rather than a client's own scope", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const app = createApp(buildDeps(dir));
			const response = await app.fetch(authed("/whoami"));
			expect(response.status).toBe(200);
			expect(await response.json()).toEqual({ name: "admin", backends: null });
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("rejects an unrecognized token, same as any other route", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const app = createApp(buildDeps(dir));
			expect((await app.fetch(withToken("/whoami", "not-a-real-token"))).status).toBe(401);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("a removed client's token stops working against /whoami too", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const clientToken = deps.clients.add("acme-consumer", ["WidgetApi"]);
			const app = createApp(deps);
			expect((await app.fetch(withToken("/whoami", clientToken))).status).toBe(200);

			deps.clients.remove("acme-consumer");
			expect((await app.fetch(withToken("/whoami", clientToken))).status).toBe(401);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
