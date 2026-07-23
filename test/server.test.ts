import { describe, expect, it } from "bun:test";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { OidcFetch } from "../src/login-command.ts";
import { createCredentialVault } from "../src/credential-vault.ts";
import { createApp } from "../src/server.ts";

const TOKEN = "test-supervisor-token";

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
	return { vault, token: TOKEN, fetchImpl: gitlabRefreshFetch };
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
