import { describe, expect, it } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connectEnigmaClient } from "../src/client.ts";
import { resolveEnigmaPaths } from "../src/paths.ts";

function tmpEnigmaPaths() {
	const dir = mkdtempSync(join(tmpdir(), "enigma-client-admin-"));
	const env = { XDG_RUNTIME_DIR: join(dir, "run"), XDG_STATE_HOME: join(dir, "state") };
	return { dir, paths: resolveEnigmaPaths({ env }) };
}

function fixtureServer(handler: (request: Request) => Response) {
	return Bun.serve({ port: 0, fetch: handler });
}

function writeHandle(handlePath: string, port: number | undefined): void {
	if (port === undefined) throw new Error("fixture server has no port -- did Bun.serve fail to bind?");
	mkdirSync(join(handlePath, ".."), { recursive: true });
	writeFileSync(handlePath, JSON.stringify({ host: "127.0.0.1", port, pid: 1 }));
}

describe("connectEnigmaClient: handle discovery", () => {
	it("finds a handle at the primary (XDG_RUNTIME_DIR-scoped) path and can make a real authenticated call", async () => {
		const { dir, paths } = tmpEnigmaPaths();
		let server: ReturnType<typeof Bun.serve> | undefined;
		try {
			mkdirSync(join(paths.token, ".."), { recursive: true });
			writeFileSync(paths.token, "a".repeat(64));
			server = fixtureServer((request) => {
				if (request.headers.get("authorization") !== `Bearer ${"a".repeat(64)}`) return new Response("unauthorized", { status: 401 });
				return new Response(JSON.stringify(["jira", "github"]), { headers: { "content-type": "application/json" } });
			});
			writeHandle(paths.handle, server.port);

			const client = connectEnigmaClient(paths);
			expect(await client.listCredentialKeys()).toEqual(["jira", "github"]);
		} finally {
			server?.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("falls back to a system-wide handle path when the primary has nothing -- mirrors enigma-client's own cross-uid discovery fix", async () => {
		const { dir, paths } = tmpEnigmaPaths();
		let server: ReturnType<typeof Bun.serve> | undefined;
		try {
			mkdirSync(join(paths.token, ".."), { recursive: true });
			writeFileSync(paths.token, "b".repeat(64));
			server = fixtureServer((request) => {
				if (request.headers.get("authorization") !== `Bearer ${"b".repeat(64)}`) return new Response("unauthorized", { status: 401 });
				return new Response(JSON.stringify([]), { headers: { "content-type": "application/json" } });
			});
			const fallbackHandlePath = join(dir, "system-wide", "handle.json");
			writeHandle(fallbackHandlePath, server.port);
			// paths.handle deliberately left unwritten -- this is the whole point of the fallback.

			const client = connectEnigmaClient(paths, fallbackHandlePath);
			expect(await client.listCredentialKeys()).toEqual([]);
		} finally {
			server?.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("prefers the primary path over the fallback when both have a handle", async () => {
		const { dir, paths } = tmpEnigmaPaths();
		let primaryServer: ReturnType<typeof Bun.serve> | undefined;
		let fallbackServer: ReturnType<typeof Bun.serve> | undefined;
		try {
			mkdirSync(join(paths.token, ".."), { recursive: true });
			writeFileSync(paths.token, "c".repeat(64));
			primaryServer = fixtureServer(() => new Response(JSON.stringify(["primary"]), { headers: { "content-type": "application/json" } }));
			fallbackServer = fixtureServer(() => new Response(JSON.stringify(["fallback"]), { headers: { "content-type": "application/json" } }));
			writeHandle(paths.handle, primaryServer.port);
			const fallbackHandlePath = join(dir, "system-wide", "handle.json");
			writeHandle(fallbackHandlePath, fallbackServer.port);

			const client = connectEnigmaClient(paths, fallbackHandlePath);
			expect(await client.listCredentialKeys()).toEqual(["primary"]);
		} finally {
			primaryServer?.stop(true);
			fallbackServer?.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("throws a clear 'not running' error when neither the primary nor the fallback path has a handle", () => {
		const { dir, paths } = tmpEnigmaPaths();
		try {
			const fallbackHandlePath = join(dir, "system-wide", "handle.json");
			expect(() => connectEnigmaClient(paths, fallbackHandlePath)).toThrow(/not running/i);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("connectEnigmaClient: admin token resolution never mints a throwaway token", () => {
	it("throws a clear, distinguishing error when a handle is found but no token exists at the resolved path -- never silently mints one", () => {
		const { dir, paths } = tmpEnigmaPaths();
		try {
			writeHandle(paths.handle, 1);
			expect(() => connectEnigmaClient(paths)).toThrow(/admin token/i);
			// The whole point: connecting must never have side effects that create state elsewhere.
			expect(existsSync(paths.token)).toBe(false);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("reads an existing token from disk unchanged -- never rewrites or rotates it as a side effect of connecting", async () => {
		const { dir, paths } = tmpEnigmaPaths();
		let server: ReturnType<typeof Bun.serve> | undefined;
		try {
			mkdirSync(join(paths.token, ".."), { recursive: true });
			const realToken = "d".repeat(64);
			writeFileSync(paths.token, `${realToken}\n`);
			server = fixtureServer((request) => {
				if (request.headers.get("authorization") !== `Bearer ${realToken}`) return new Response("unauthorized", { status: 401 });
				return new Response(JSON.stringify([]), { headers: { "content-type": "application/json" } });
			});
			writeHandle(paths.handle, server.port);

			await connectEnigmaClient(paths).listCredentialKeys();
			expect(readFileSync(paths.token, "utf8")).toBe(`${realToken}\n`);
		} finally {
			server?.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
