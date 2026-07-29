import { describe, expect, it } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Logger } from "@danypops/daemon-kit/logging";
import type { OidcFetch } from "../src/login-command.ts";
import type { EnigmaAdminClient, VaultCredential } from "../src/client.ts";
import { createClientRegistry } from "../src/client-registry.ts";
import { createCredentialVault } from "../src/credential-vault.ts";
import { createApp, createUnixSocketHandler } from "../src/server.ts";
import { createEnigmaSecretsBackend } from "../src/secrets-backend-adapter.ts";

/** A minimal EnigmaAdminClient whose getCredentials hits the real app.fetch -- lets a test drive createEnigmaSecretsBackend().reveal() against the genuine HTTP route and its real audit logging, not a fake in-memory client. */
function clientOverHttp(app: { fetch: (request: Request) => Promise<Response> }): EnigmaAdminClient {
	return {
		listCredentialKeys: async () => [],
		getCredentials: async (backend: string) => {
			const response = await app.fetch(authed(`/creds/${encodeURIComponent(backend)}`));
			if (response.status === 404) return undefined;
			if (!response.ok) throw new Error(`unexpected status ${response.status}`);
			return (await response.json()) as VaultCredential;
		},
		rotateCredential: async () => {},
		revokeCredential: async () => {},
		listClients: async () => [],
		health: async () => ({ ok: true, version: "test" }),
	};
}

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

function fakeLogger(): { logger: Logger; entries: Array<{ msg: string; fields: Record<string, unknown> }> } {
	const entries: Array<{ msg: string; fields: Record<string, unknown> }> = [];
	const logger: Logger = {
		debug: () => {},
		info: (msg, fields) => entries.push({ msg, fields: fields ?? {} }),
		warn: () => {},
		error: () => {},
	};
	return { logger, entries };
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

	it("GET /clients lists every registered client (name+backends+uid), admin-only", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			expect(await (await app.fetch(authed("/clients"))).json()).toEqual([]);

			const pipesToken = deps.clients.add("pipes", ["github", "jenkins-ci"]);
			deps.clients.add("tickets", ["github", "jira"], { uid: 1001 });
			const list = await (await app.fetch(authed("/clients"))).json();
			expect(list).toEqual([
				{ name: "pipes", backends: ["github", "jenkins-ci"], createdAt: expect.any(String) },
				{ name: "tickets", backends: ["github", "jira"], createdAt: expect.any(String), uid: 1001 },
			]);
			// never leaks a client's own token, only its name/scope
			expect(JSON.stringify(list)).not.toContain(pipesToken);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("GET /clients is refused for a registered client's own token, matching every other admin-only route", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			const clientToken = deps.clients.add("pipes", ["github"]);
			expect((await app.fetch(withToken("/clients", clientToken))).status).toBe(401);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /clients registers a new client and returns its token once, admin-only -- the daemon does the write, not the caller's own filesystem", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			const response = await app.fetch(authed("/clients", { method: "POST", body: JSON.stringify({ name: "web-spider", backends: ["brave", "tavily"] }) }));
			expect(response.status).toBe(201);
			const { token } = (await response.json()) as { token: string };
			expect(typeof token).toBe("string");
			expect(token.length).toBeGreaterThan(0);

			// the registration really landed -- the same token now authenticates as that client
			const registration = deps.clients.authenticate(token);
			expect(registration?.name).toBe("web-spider");
			expect(registration?.backends).toEqual(["brave", "tavily"]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /clients accepts an optional uid, binding the client for the Unix-socket transport too", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			const response = await app.fetch(authed("/clients", { method: "POST", body: JSON.stringify({ name: "web-spider", backends: ["brave"], uid: 4217278 }) }));
			expect(response.status).toBe(201);
			expect(deps.clients.authenticateByUid(4217278)?.name).toBe("web-spider");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /clients returns 409 for a name that's already registered", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			deps.clients.add("web-spider", ["brave"]);
			const response = await app.fetch(authed("/clients", { method: "POST", body: JSON.stringify({ name: "web-spider", backends: ["tavily"] }) }));
			expect(response.status).toBe(409);
			expect((await response.json() as { error: string }).error).toContain('"web-spider" is already registered');
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /clients returns 409 when the requested uid is already bound to a different client", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			deps.clients.add("pipes", ["github"], { uid: 1001 });
			const response = await app.fetch(authed("/clients", { method: "POST", body: JSON.stringify({ name: "web-spider", backends: ["brave"], uid: 1001 }) }));
			expect(response.status).toBe(409);
			expect((await response.json() as { error: string }).error).toContain("already bound");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /clients returns 400 for a missing name, missing backends, or an empty backends array", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			const noName = await app.fetch(authed("/clients", { method: "POST", body: JSON.stringify({ backends: ["brave"] }) }));
			expect(noName.status).toBe(400);
			const noBackends = await app.fetch(authed("/clients", { method: "POST", body: JSON.stringify({ name: "web-spider" }) }));
			expect(noBackends.status).toBe(400);
			const emptyBackends = await app.fetch(authed("/clients", { method: "POST", body: JSON.stringify({ name: "web-spider", backends: [] }) }));
			expect(emptyBackends.status).toBe(400);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /clients returns 400 for malformed JSON", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			const response = await app.fetch(authed("/clients", { method: "POST", body: "not json" }));
			expect(response.status).toBe(400);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /clients is refused for a registered client's own token, and for no token at all", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			const clientToken = deps.clients.add("pipes", ["github"]);
			const asClient = await app.fetch(withToken("/clients", clientToken, { method: "POST", body: JSON.stringify({ name: "web-spider", backends: ["brave"] }) }));
			expect(asClient.status).toBe(401);
			const unauthenticated = await app.fetch(new Request("http://enigma.local/clients", { method: "POST", body: JSON.stringify({ name: "web-spider", backends: ["brave"] }) }));
			expect(unauthenticated.status).toBe(401);
			// neither attempt actually registered anything
			expect(deps.clients.list()).toEqual([{ name: "pipes", backends: ["github"], createdAt: expect.any(String) }]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /clients/:name/rotate reissues that client's token, invalidating the old one", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			const oldToken = deps.clients.add("web-spider", ["brave"]);
			const response = await app.fetch(authed("/clients/web-spider/rotate", { method: "POST" }));
			expect(response.status).toBe(200);
			const { token: newToken } = (await response.json()) as { token: string };
			expect(newToken).not.toBe(oldToken);
			expect(deps.clients.authenticate(oldToken)).toBeUndefined();
			expect(deps.clients.authenticate(newToken)?.name).toBe("web-spider");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /clients/:name/rotate returns 404 for an unregistered name", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			expect((await app.fetch(authed("/clients/nonexistent/rotate", { method: "POST" }))).status).toBe(404);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /clients/:name/remove deletes the registration, its old token stops working", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			const token = deps.clients.add("web-spider", ["brave"]);
			const response = await app.fetch(authed("/clients/web-spider/remove", { method: "POST" }));
			expect(response.status).toBe(204);
			expect(deps.clients.authenticate(token)).toBeUndefined();
			expect(deps.clients.list()).toEqual([]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /clients/:name/remove returns 404 for an unregistered name", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			expect((await app.fetch(authed("/clients/nonexistent/remove", { method: "POST" }))).status).toBe(404);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POST /clients/:name/rotate and /remove are refused for a registered client's own token", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			const app = createApp(deps);
			deps.clients.add("web-spider", ["brave"]);
			const clientToken = deps.clients.add("pipes", ["github"]);
			expect((await app.fetch(withToken("/clients/web-spider/rotate", clientToken, { method: "POST" }))).status).toBe(401);
			expect((await app.fetch(withToken("/clients/web-spider/remove", clientToken, { method: "POST" }))).status).toBe(401);
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

describe("createUnixSocketHandler: identity resolved from a kernel-verified peer uid, never a bearer token", () => {
	function unauthed(path: string, init: RequestInit = {}): Request {
		return new Request(`http://enigma.local${path}`, init);
	}

	it("a peer uid matching the configured adminUid gets full admin access, with no Authorization header at all", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			deps.vault.save("widgetapi", { accessToken: "secret", extra: {} });
			const handler = createUnixSocketHandler(deps, { adminUid: 1001 });

			const response = await handler(unauthed("/creds/widgetapi"), { pid: 1, uid: 1001, gid: 1001 });
			expect(response.status).toBe(200);
			expect(await response.json()).toEqual({ accessToken: "secret", extra: {} });
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("a peer uid bound to a registered client gets that client's scoped access, same 403 boundary as the bearer-token path", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			deps.vault.save("widgetapi", { accessToken: "secret", extra: {} });
			deps.vault.save("gadgetapi", { accessToken: "other-secret", extra: {} });
			deps.clients.add("acme-consumer", ["widgetapi"], { uid: 2002 });
			const handler = createUnixSocketHandler(deps, { adminUid: 1001 });

			const inScope = await handler(unauthed("/creds/widgetapi"), { pid: 1, uid: 2002, gid: 2002 });
			expect(inScope.status).toBe(200);

			const outOfScope = await handler(unauthed("/creds/gadgetapi"), { pid: 1, uid: 2002, gid: 2002 });
			expect(outOfScope.status).toBe(403);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("an unrecognized peer uid is rejected outright, same as a missing/wrong bearer token", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			deps.vault.save("widgetapi", { accessToken: "secret", extra: {} });
			const handler = createUnixSocketHandler(deps, { adminUid: 1001 });

			const response = await handler(unauthed("/creds/widgetapi"), { pid: 1, uid: 9999, gid: 9999 });
			expect(response.status).toBe(401);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("an Authorization header presented over the unix transport is ignored -- identity comes only from the kernel-verified peer, never a header a peer could forge", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			deps.vault.save("widgetapi", { accessToken: "secret", extra: {} });
			const handler = createUnixSocketHandler(deps, { adminUid: 1001 });

			// Presents the real admin bearer token, but from an unrecognized uid -- must still be rejected.
			const response = await handler(withToken("/creds/widgetapi", TOKEN), { pid: 1, uid: 9999, gid: 9999 });
			expect(response.status).toBe(401);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("/whoami over the unix transport reports the peer-resolved identity, admin or client, same shape as the bearer-token path", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const deps = buildDeps(dir);
			deps.clients.add("acme-consumer", ["widgetapi"], { uid: 2002 });
			const handler = createUnixSocketHandler(deps, { adminUid: 1001 });

			const adminWhoami = await handler(unauthed("/whoami"), { pid: 1, uid: 1001, gid: 1001 });
			expect(await adminWhoami.json()).toEqual({ name: "admin", backends: null });

			const clientWhoami = await handler(unauthed("/whoami"), { pid: 1, uid: 2002, gid: 2002 });
			expect(await clientWhoami.json()).toEqual({ name: "acme-consumer", backends: ["widgetapi"] });
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("credential audit logging: every read/rotate/revoke is logged, never the value itself", () => {
	it("logs a successful GET /creds/:backend as admin, with the outcome and identity but never the credential", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const { logger, entries } = fakeLogger();
			const deps = { ...buildDeps(dir), logger };
			deps.vault.save("widgetapi", { accessToken: "super-secret-value", extra: { note: "also secret" } });
			const app = createApp(deps);

			const response = await app.fetch(authed("/creds/widgetapi"));
			expect(response.status).toBe(200);

			expect(entries).toEqual([{ msg: "credential_access", fields: { backend: "widgetapi", outcome: "ok", identity: "admin" } }]);
			// The whole point: no log entry anywhere contains the actual secret value.
			expect(JSON.stringify(entries)).not.toContain("super-secret-value");
			expect(JSON.stringify(entries)).not.toContain("also secret");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("reveal() through createEnigmaSecretsBackend hits the real audited route -- credential_access fires, value never appears in the log", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const { logger, entries } = fakeLogger();
			const deps = { ...buildDeps(dir), logger };
			deps.vault.save("widgetapi", { accessToken: "super-secret-value" });
			const app = createApp(deps);
			const backend = createEnigmaSecretsBackend(clientOverHttp(app));

			const revealed = await backend.reveal("widgetapi");

			expect(revealed).toEqual({ accessToken: "super-secret-value" });
			expect(entries).toEqual([{ msg: "credential_access", fields: { backend: "widgetapi", outcome: "ok", identity: "admin" } }]);
			expect(JSON.stringify(entries)).not.toContain("super-secret-value");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("logs 'not_found' when the backend has no stored credential", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const { logger, entries } = fakeLogger();
			const app = createApp({ ...buildDeps(dir), logger });

			await app.fetch(authed("/creds/nothing-here"));

			expect(entries).toEqual([{ msg: "credential_access", fields: { backend: "nothing-here", outcome: "not_found", identity: "admin" } }]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("logs 'unauthenticated' for a request with no valid bearer token at all", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const { logger, entries } = fakeLogger();
			const app = createApp({ ...buildDeps(dir), logger });

			await app.fetch(new Request("http://enigma.local/creds/widgetapi"));

			expect(entries).toEqual([{ msg: "credential_access", fields: { backend: "widgetapi", outcome: "unauthenticated", identity: "none" } }]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("logs 'denied' for a registered client requesting a backend outside its own scope, naming the client", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const { logger, entries } = fakeLogger();
			const deps = { ...buildDeps(dir), logger };
			const clientToken = deps.clients.add("acme-consumer", ["widgetapi"]);
			const app = createApp(deps);

			await app.fetch(withToken("/creds/other-backend", clientToken));

			expect(entries).toEqual([{ msg: "credential_access", fields: { backend: "other-backend", outcome: "denied", identity: "client", client: "acme-consumer" } }]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("logs credential_revoke on a successful revoke", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const { logger, entries } = fakeLogger();
			const deps = { ...buildDeps(dir), logger };
			deps.vault.save("widgetapi", { accessToken: "secret" });
			const app = createApp(deps);

			await app.fetch(authed("/revoke/widgetapi", { method: "POST" }));

			expect(entries).toEqual([{ msg: "credential_revoke", fields: { backend: "widgetapi", outcome: "ok", identity: "admin" } }]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("logs credential_rotate on a successful rotate", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const { logger, entries } = fakeLogger();
			const deps = { ...buildDeps(dir), logger };
			deps.vault.save("gitlab", { accessToken: "old-token", refreshToken: "refresh-me", extra: { baseUrl: "https://gitlab.example.com", clientId: "c" } });
			const app = createApp(deps);

			const response = await app.fetch(authed("/rotate/gitlab", { method: "POST" }));
			expect(response.status).toBe(204);

			expect(entries).toEqual([{ msg: "credential_rotate", fields: { backend: "gitlab", outcome: "ok", identity: "admin" } }]);
			expect(JSON.stringify(entries)).not.toContain("old-token");
			expect(JSON.stringify(entries)).not.toContain("refresh-me");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("includes the kernel-verified peer uid when the access came over the unix transport", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const { logger, entries } = fakeLogger();
			const deps = { ...buildDeps(dir), logger };
			deps.vault.save("widgetapi", { accessToken: "secret" });
			const handler = createUnixSocketHandler(deps, { adminUid: 1001 });

			await handler(new Request("http://enigma.local/creds/widgetapi"), { pid: 1, uid: 1001, gid: 1001 });

			expect(entries).toEqual([{ msg: "credential_access", fields: { backend: "widgetapi", outcome: "ok", identity: "admin", uid: 1001 } }]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("emits no log entries at all when no logger is supplied -- optional, not required", async () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-server-"));
		try {
			const app = createApp(buildDeps(dir));
			// No logger in deps -- must not throw.
			const response = await app.fetch(authed("/creds/nothing-here"));
			expect(response.status).toBe(404);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
