import { describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { tryEnigmaAccessToken, tryEnigmaCredential, tryEnigmaWhoAmI } from "../src/index.ts";

function tmpXdg(): { dir: string; env: { XDG_RUNTIME_DIR: string; XDG_STATE_HOME: string } } {
	const dir = mkdtempSync(join(tmpdir(), "enigma-client-"));
	return { dir, env: { XDG_RUNTIME_DIR: join(dir, "run"), XDG_STATE_HOME: join(dir, "state") } };
}

function fixtureServer(handler: (request: Request) => Response) {
	return Bun.serve({ port: 0, fetch: handler });
}

describe("tryEnigmaCredential", () => {
	it("resolves undefined immediately when no Enigma handle file exists -- not running, not an error", async () => {
		const { dir, env } = tmpXdg();
		try {
			expect(await tryEnigmaCredential("github", { env })).toBeUndefined();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("resolves undefined when a handle exists but the token file doesn't -- never mints Enigma's own token", async () => {
		const { dir, env } = tmpXdg();
		try {
			const handleDir = join(env.XDG_RUNTIME_DIR, "enigma");
			mkdirSync(handleDir, { recursive: true });
			writeFileSync(join(handleDir, "handle.json"), JSON.stringify({ host: "127.0.0.1", port: 39217, pid: 1 }));
			expect(await tryEnigmaCredential("github", { env })).toBeUndefined();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("fetches the real credential shape from a live vault when both the handle and token are present", async () => {
		const { dir, env } = tmpXdg();
		let server: ReturnType<typeof Bun.serve> | undefined;
		try {
			server = fixtureServer((request) => {
				if (request.headers.get("authorization") !== "Bearer fixture-enigma-bearer") return new Response("unauthorized", { status: 401 });
				const url = new URL(request.url);
				if (url.pathname === "/creds/jenkins") {
					return new Response(JSON.stringify({ accessToken: "fixture-jenkins-token", extra: { url: "https://jenkins.example.com", username: "bot" } }), {
						headers: { "content-type": "application/json" },
					});
				}
				return new Response("not found", { status: 404 });
			});

			const handleDir = join(env.XDG_RUNTIME_DIR, "enigma");
			const stateDir = join(env.XDG_STATE_HOME, "enigma");
			mkdirSync(handleDir, { recursive: true });
			mkdirSync(stateDir, { recursive: true });
			writeFileSync(join(handleDir, "handle.json"), JSON.stringify({ host: "127.0.0.1", port: server.port, pid: process.pid }));
			writeFileSync(join(stateDir, "token"), "fixture-enigma-bearer\n");

			const full = await tryEnigmaCredential("jenkins", { env });
			expect(full).toEqual({ accessToken: "fixture-jenkins-token", extra: { url: "https://jenkins.example.com", username: "bot" } });

			const bare = await tryEnigmaAccessToken("jenkins", { env });
			expect(bare).toBe("fixture-jenkins-token");

			const missing = await tryEnigmaCredential("gitlab", { env });
			expect(missing).toBeUndefined(); // real 404 -- backend not configured in the vault
		} finally {
			server?.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("never throws and resolves undefined when the vault is unreachable", async () => {
		const { dir, env } = tmpXdg();
		try {
			const handleDir = join(env.XDG_RUNTIME_DIR, "enigma");
			const stateDir = join(env.XDG_STATE_HOME, "enigma");
			mkdirSync(handleDir, { recursive: true });
			mkdirSync(stateDir, { recursive: true });
			// A port nothing is listening on -- connection refused, exercises the same catch-and-fall-through path as a timeout.
			writeFileSync(join(handleDir, "handle.json"), JSON.stringify({ host: "127.0.0.1", port: 1, pid: process.pid }));
			writeFileSync(join(stateDir, "token"), "fixture-enigma-bearer\n");
			expect(await tryEnigmaCredential("github", { env })).toBeUndefined();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("an explicitly passed token is used instead of reading the shared token file -- the registered-client seam", async () => {
		const { dir, env } = tmpXdg();
		let server: ReturnType<typeof Bun.serve> | undefined;
		try {
			server = fixtureServer((request) => {
				if (request.headers.get("authorization") !== "Bearer my-own-registered-token") return new Response("unauthorized", { status: 401 });
				return new Response(JSON.stringify({ accessToken: "scoped-token" }), { headers: { "content-type": "application/json" } });
			});

			const handleDir = join(env.XDG_RUNTIME_DIR, "enigma");
			mkdirSync(handleDir, { recursive: true });
			writeFileSync(join(handleDir, "handle.json"), JSON.stringify({ host: "127.0.0.1", port: server.port, pid: process.pid }));
			// Deliberately no shared token file written -- proves the explicit token is what's used, not a fallback read.

			const result = await tryEnigmaCredential("jira", { env, token: "my-own-registered-token" });
			expect(result).toEqual({ accessToken: "scoped-token" });
		} finally {
			server?.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("a wrong explicit token is rejected just like a wrong shared-file token would be", async () => {
		const { dir, env } = tmpXdg();
		let server: ReturnType<typeof Bun.serve> | undefined;
		try {
			server = fixtureServer((request) => (request.headers.get("authorization") === "Bearer the-real-token" ? new Response("{}") : new Response("unauthorized", { status: 401 })));
			const handleDir = join(env.XDG_RUNTIME_DIR, "enigma");
			mkdirSync(handleDir, { recursive: true });
			writeFileSync(join(handleDir, "handle.json"), JSON.stringify({ host: "127.0.0.1", port: server.port, pid: process.pid }));

			expect(await tryEnigmaCredential("jira", { env, token: "wrong-token" })).toBeUndefined();
		} finally {
			server?.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("tryEnigmaAccessToken", () => {
	it("resolves undefined the same way tryEnigmaCredential does when nothing is configured", async () => {
		const { dir, env } = tmpXdg();
		try {
			expect(await tryEnigmaAccessToken("github", { env })).toBeUndefined();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("tryEnigmaWhoAmI", () => {
	it("resolves undefined immediately when no Enigma handle file exists", async () => {
		const { dir, env } = tmpXdg();
		try {
			expect(await tryEnigmaWhoAmI({ env })).toBeUndefined();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("fetches this client's own name and backend scope from a live vault", async () => {
		const { dir, env } = tmpXdg();
		let server: ReturnType<typeof Bun.serve> | undefined;
		try {
			server = fixtureServer((request) => {
				if (request.headers.get("authorization") !== "Bearer acme-consumer-token") return new Response("unauthorized", { status: 401 });
				if (new URL(request.url).pathname !== "/whoami") return new Response("not found", { status: 404 });
				return new Response(JSON.stringify({ name: "acme-consumer", backends: ["widgetapi", "gadgetapi"] }), {
					headers: { "content-type": "application/json" },
				});
			});

			const handleDir = join(env.XDG_RUNTIME_DIR, "enigma");
			mkdirSync(handleDir, { recursive: true });
			writeFileSync(join(handleDir, "handle.json"), JSON.stringify({ host: "127.0.0.1", port: server.port, pid: process.pid }));

			const result = await tryEnigmaWhoAmI({ env, token: "acme-consumer-token" });
			expect(result).toEqual({ name: "acme-consumer", backends: ["widgetapi", "gadgetapi"] });
		} finally {
			server?.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("resolves undefined for a wrong token, same as any other unauthenticated call", async () => {
		const { dir, env } = tmpXdg();
		let server: ReturnType<typeof Bun.serve> | undefined;
		try {
			server = fixtureServer(() => new Response("unauthorized", { status: 401 }));
			const handleDir = join(env.XDG_RUNTIME_DIR, "enigma");
			mkdirSync(handleDir, { recursive: true });
			writeFileSync(join(handleDir, "handle.json"), JSON.stringify({ host: "127.0.0.1", port: server.port, pid: process.pid }));

			expect(await tryEnigmaWhoAmI({ env, token: "wrong-token" })).toBeUndefined();
		} finally {
			server?.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
