import { describe, expect, it } from "bun:test";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { serveUnixRpc } from "@danypops/vehicle-server/unix-rpc-server";
import { connectEnigmaClient } from "../src/client.ts";
import { createClientRegistry } from "../src/client-registry.ts";
import { createCredentialVault } from "../src/credential-vault.ts";
import { resolveEnigmaPaths } from "../src/paths.ts";
import { createUnixSocketHandler } from "../src/server.ts";

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

/**
 * Every connectEnigmaClient(paths) call below must pass an explicit fallback
 * inside the test's own isolated tmp dir -- omitting it defaults to the real
 * ENIGMA_SYSTEM_RUNTIME_HANDLE (/run/enigma/handle.json + admin.sock), which
 * is a genuinely live path on any machine running the real Enigma system
 * service. Confirmed live: with that service upgraded to Unix-socket
 * support and this machine's own uid trusted as its admin, tests silently
 * connected to and read from the real production vault instead of their
 * own fixture server -- one test's own assertion was too narrow to even
 * notice. A definitely-nonexistent fallback guarantees isolation regardless
 * of what happens to be running on the host.
 */
function unreachableFallback(dir: string): string {
	return join(dir, "no-such-fallback", "handle.json");
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

			const client = connectEnigmaClient(paths, unreachableFallback(dir));
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

describe("connectEnigmaClient: listClients()", () => {
	it("calls GET /clients and returns the parsed roster", async () => {
		const { dir, paths } = tmpEnigmaPaths();
		let server: ReturnType<typeof Bun.serve> | undefined;
		try {
			mkdirSync(join(paths.token, ".."), { recursive: true });
			writeFileSync(paths.token, "a".repeat(64));
			server = fixtureServer((request) => {
				if (new URL(request.url).pathname !== "/clients") return new Response("not found", { status: 404 });
				if (request.headers.get("authorization") !== `Bearer ${"a".repeat(64)}`) return new Response("unauthorized", { status: 401 });
				return new Response(JSON.stringify([{ name: "pipes", backends: ["github"] }]), { headers: { "content-type": "application/json" } });
			});
			writeHandle(paths.handle, server.port);

			const client = connectEnigmaClient(paths, unreachableFallback(dir));
			expect(await client.listClients()).toEqual([{ name: "pipes", backends: ["github"] }]);
		} finally {
			server?.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("connectEnigmaClient: health() -- found live as a real bug, a third copy of this exact discovery logic", () => {
	it("health() goes through the same fixed handle discovery as every other admin operation, via the system-wide fallback", async () => {
		const { dir, paths } = tmpEnigmaPaths();
		let server: ReturnType<typeof Bun.serve> | undefined;
		try {
			mkdirSync(join(paths.token, ".."), { recursive: true });
			writeFileSync(paths.token, "e".repeat(64));
			server = fixtureServer((request) => {
				if (new URL(request.url).pathname !== "/health") return new Response("not found", { status: 404 });
				return new Response(JSON.stringify({ ok: true, version: "0.12.0" }), { headers: { "content-type": "application/json" } });
			});
			const fallbackHandlePath = join(dir, "system-wide", "handle.json");
			writeHandle(fallbackHandlePath, server.port);
			// paths.handle deliberately left unwritten -- proves health() uses the fallback too, not a second unfixed copy.

			const client = connectEnigmaClient(paths, fallbackHandlePath);
			expect(await client.health()).toEqual({ ok: true, version: "0.12.0" });
		} finally {
			server?.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("connectEnigmaClient: Unix-socket transport, no token needed at all", () => {
	it("authenticates purely via SO_PEERCRED as admin, over a real admin.sock, with zero token file present", async () => {
		const { dir, paths } = tmpEnigmaPaths();
		const vaultDir = join(dir, "vault");
		mkdirSync(vaultDir, { recursive: true });
		const vault = createCredentialVault({ dir: vaultDir, masterKey: randomBytes(32) });
		const clients = createClientRegistry(join(dir, "clients.json"));
		const myUid = process.getuid?.();
		expect(myUid).toBeDefined();

		const socketPath = join(paths.handle, "..", "admin.sock");
		mkdirSync(join(paths.handle, ".."), { recursive: true });
		const unixServer = serveUnixRpc({
			path: socketPath,
			handler: createUnixSocketHandler({ vault, token: "unused-admin-token", clients }, { adminUid: myUid }),
		});
		try {
			// Deliberately no handle.json, no token file at all -- proves the Unix-socket
			// path needs neither to succeed for an admin-uid caller. The fallback is still
			// pinned to this test's own tmp dir: the primary admin.sock above must be what
			// wins, not an accidental real fallback.
			const client = connectEnigmaClient(paths, unreachableFallback(dir));
			expect(await client.listCredentialKeys()).toEqual([]);
		} finally {
			unixServer.stop();
			try {
				unlinkSync(socketPath);
			} catch {}
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("falls back to the TCP+bearer-token path when a socket exists but this process's own uid isn't trusted as admin over it (ENIGMA_ADMIN_UID unset -- the common case for an operator who already has a real admin token)", async () => {
		const { dir, paths } = tmpEnigmaPaths();
		const vaultDir = join(dir, "vault");
		mkdirSync(vaultDir, { recursive: true });
		const vault = createCredentialVault({ dir: vaultDir, masterKey: randomBytes(32) });
		const clients = createClientRegistry(join(dir, "clients.json"));

		// A real Unix socket exists (as it always does once the daemon starts one), but with no
		// adminUid configured -- this process's own uid is never trusted as admin over it, exactly
		// the default state for an operator who hasn't opted into ENIGMA_ADMIN_UID yet.
		const socketPath = join(paths.handle, "..", "admin.sock");
		mkdirSync(join(paths.handle, ".."), { recursive: true });
		const realAdminToken = "a".repeat(64);
		const unixServer = serveUnixRpc({ path: socketPath, handler: createUnixSocketHandler({ vault, token: realAdminToken, clients }) });

		// A live TCP server the operator's own real admin token still works against.
		mkdirSync(join(paths.token, ".."), { recursive: true });
		writeFileSync(paths.token, realAdminToken);
		const tcpServer = fixtureServer((request) =>
			request.headers.get("authorization") === `Bearer ${realAdminToken}`
				? new Response(JSON.stringify(["tcp-token-still-works"]), { headers: { "content-type": "application/json" } })
				: new Response("unauthorized", { status: 401 }),
		);
		writeHandle(paths.handle, tcpServer.port);

		try {
			const client = connectEnigmaClient(paths, unreachableFallback(dir));
			expect(await client.listCredentialKeys()).toEqual(["tcp-token-still-works"]);
		} finally {
			unixServer.stop();
			tcpServer.stop(true);
			try {
				unlinkSync(socketPath);
			} catch {}
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("falls through to the TCP+bearer-token path when no admin.sock exists (older Enigma, or none running)", async () => {
		const { dir, paths } = tmpEnigmaPaths();
		let server: ReturnType<typeof Bun.serve> | undefined;
		try {
			mkdirSync(join(paths.token, ".."), { recursive: true });
			writeFileSync(paths.token, "f".repeat(64));
			server = fixtureServer((request) =>
				request.headers.get("authorization") === `Bearer ${"f".repeat(64)}`
					? new Response(JSON.stringify(["tcp-fallback"]), { headers: { "content-type": "application/json" } })
					: new Response("unauthorized", { status: 401 }),
			);
			writeHandle(paths.handle, server.port);
			// Deliberately no admin.sock written -- proves the fallback still works end to end.
			// (The *socket* fallback is real system state either way; unreachableFallback here
			// only pins the *handle* fallback this specific assertion cares about.)

			const client = connectEnigmaClient(paths, unreachableFallback(dir));
			expect(await client.listCredentialKeys()).toEqual(["tcp-fallback"]);
		} finally {
			server?.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("connectEnigmaClient: admin token resolution never mints a throwaway token", () => {
	it("throws a clear, distinguishing error when a handle is found but no token exists at the resolved path -- never silently mints one", () => {
		const { dir, paths } = tmpEnigmaPaths();
		try {
			writeHandle(paths.handle, 1);
			expect(() => connectEnigmaClient(paths, unreachableFallback(dir))).toThrow(/admin token/i);
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

			const keys = await connectEnigmaClient(paths, unreachableFallback(dir)).listCredentialKeys();
			expect(keys).toEqual([]); // proves this really hit the isolated fixture, not a silently-corrupted real backend
			expect(readFileSync(paths.token, "utf8")).toBe(`${realToken}\n`);
		} finally {
			server?.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
