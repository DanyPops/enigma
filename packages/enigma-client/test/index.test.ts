import { describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { serveUnixRpc } from "@danypops/daemon-kit/unix-rpc-server";
import { resolveAdminSocketPath, resolveHandle, tryEnigmaAccessToken, tryEnigmaCredential, tryEnigmaWhoAmI } from "../src/index.ts";

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

describe("resolveHandle: system-wide fallback for a production Enigma not scoped to any one consumer's uid", () => {
	it("prefers the primary (caller's own XDG_RUNTIME_DIR-scoped) path when it has a handle", () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-client-handle-"));
		try {
			const primary = join(dir, "primary", "handle.json");
			const fallback = join(dir, "fallback", "handle.json");
			mkdirSync(join(dir, "primary"), { recursive: true });
			mkdirSync(join(dir, "fallback"), { recursive: true });
			writeFileSync(primary, JSON.stringify({ host: "127.0.0.1", port: 1111, pid: 1 }));
			writeFileSync(fallback, JSON.stringify({ host: "127.0.0.1", port: 2222, pid: 2 }));

			expect(resolveHandle(primary, fallback)?.port).toBe(1111);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("falls back to the system-wide path when the primary has nothing -- the real production Enigma layout", () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-client-handle-"));
		try {
			const primary = join(dir, "primary", "handle.json"); // deliberately never written, as for a normal user session
			const fallback = join(dir, "fallback", "handle.json");
			mkdirSync(join(dir, "fallback"), { recursive: true });
			writeFileSync(fallback, JSON.stringify({ host: "127.0.0.1", port: 2222, pid: 2 }));

			expect(resolveHandle(primary, fallback)?.port).toBe(2222);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("resolves null when neither path has a handle", () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-client-handle-"));
		try {
			expect(resolveHandle(join(dir, "a", "handle.json"), join(dir, "b", "handle.json"))).toBeNull();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("resolveAdminSocketPath", () => {
	it("resolves undefined when no socket exists at either candidate directory", () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-client-socket-"));
		try {
			expect(resolveAdminSocketPath(join(dir, "primary", "handle.json"), join(dir, "fallback", "handle.json"))).toBeUndefined();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("prefers the primary directory's socket over the fallback's", () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-client-socket-"));
		try {
			mkdirSync(join(dir, "primary"), { recursive: true });
			mkdirSync(join(dir, "fallback"), { recursive: true });
			writeFileSync(join(dir, "primary", "admin.sock"), "");
			writeFileSync(join(dir, "fallback", "admin.sock"), "");
			expect(resolveAdminSocketPath(join(dir, "primary", "handle.json"), join(dir, "fallback", "handle.json"))).toBe(join(dir, "primary", "admin.sock"));
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("falls back to the system-wide socket when only it exists", () => {
		const dir = mkdtempSync(join(tmpdir(), "enigma-client-socket-"));
		try {
			mkdirSync(join(dir, "fallback"), { recursive: true });
			writeFileSync(join(dir, "fallback", "admin.sock"), "");
			expect(resolveAdminSocketPath(join(dir, "primary", "handle.json"), join(dir, "fallback", "handle.json"))).toBe(join(dir, "fallback", "admin.sock"));
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("tryEnigmaCredential over the Unix-socket transport", () => {
	it("fetches a real credential over a real Unix socket, needing no token at all -- SO_PEERCRED, not a bearer header, is the identity proof", async () => {
		const { dir, env } = tmpXdg();
		const handleDir = join(env.XDG_RUNTIME_DIR, "enigma");
		mkdirSync(handleDir, { recursive: true });
		const socketPath = join(handleDir, "admin.sock");
		const server = serveUnixRpc({
			path: socketPath,
			handler: async (request) => {
				// No Authorization header at all is sent over this transport -- confirms
				// the client never fabricates or forwards a bearer credential here.
				expect(request.headers.get("authorization")).toBeNull();
				if (new URL(request.url).pathname === "/creds/github") {
					return new Response(JSON.stringify({ accessToken: "unix-socket-token" }), { headers: { "content-type": "application/json" } });
				}
				return new Response("not found", { status: 404 });
			},
		});
		try {
			// Deliberately no handle.json and no token file at all -- the Unix socket
			// path never needs either to succeed.
			const result = await tryEnigmaCredential("github", { env });
			expect(result).toEqual({ accessToken: "unix-socket-token" });

			const bare = await tryEnigmaAccessToken("github", { env });
			expect(bare).toBe("unix-socket-token");
		} finally {
			server.stop();
			try {
				unlinkSync(socketPath);
			} catch {}
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("prefers the Unix socket over a simultaneously-configured TCP handle + token", async () => {
		const { dir, env } = tmpXdg();
		const handleDir = join(env.XDG_RUNTIME_DIR, "enigma");
		const stateDir = join(env.XDG_STATE_HOME, "enigma");
		mkdirSync(handleDir, { recursive: true });
		mkdirSync(stateDir, { recursive: true });

		// A live, correctly-configured TCP+bearer-token path that would happily answer --
		// proves the socket is genuinely preferred, not just the only reachable option.
		const tcpServer = Bun.serve({ port: 0, fetch: () => new Response(JSON.stringify({ accessToken: "tcp-token" }), { headers: { "content-type": "application/json" } }) });
		writeFileSync(join(handleDir, "handle.json"), JSON.stringify({ host: "127.0.0.1", port: tcpServer.port, pid: process.pid }));
		writeFileSync(join(stateDir, "token"), "fixture-enigma-bearer\n");

		const socketPath = join(handleDir, "admin.sock");
		const unixServer = serveUnixRpc({
			path: socketPath,
			handler: async () => new Response(JSON.stringify({ accessToken: "unix-token" }), { headers: { "content-type": "application/json" } }),
		});
		try {
			const result = await tryEnigmaCredential("github", { env });
			expect(result).toEqual({ accessToken: "unix-token" });
		} finally {
			unixServer.stop();
			tcpServer.stop(true);
			try {
				unlinkSync(socketPath);
			} catch {}
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("falls through to the TCP+bearer-token path when no Unix socket exists (older Enigma, or none running)", async () => {
		const { dir, env } = tmpXdg();
		const handleDir = join(env.XDG_RUNTIME_DIR, "enigma");
		const stateDir = join(env.XDG_STATE_HOME, "enigma");
		mkdirSync(handleDir, { recursive: true });
		mkdirSync(stateDir, { recursive: true });

		const server = Bun.serve({
			port: 0,
			fetch: (request) => (request.headers.get("authorization") === "Bearer fixture-enigma-bearer" ? new Response(JSON.stringify({ accessToken: "tcp-fallback-token" }), { headers: { "content-type": "application/json" } }) : new Response("unauthorized", { status: 401 })),
		});
		writeFileSync(join(handleDir, "handle.json"), JSON.stringify({ host: "127.0.0.1", port: server.port, pid: process.pid }));
		writeFileSync(join(stateDir, "token"), "fixture-enigma-bearer\n");
		// Deliberately no admin.sock written -- proves the fallback still works end to end.
		try {
			const result = await tryEnigmaCredential("github", { env });
			expect(result).toEqual({ accessToken: "tcp-fallback-token" });
		} finally {
			server.stop(true);
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("resolves undefined, never throws, when the Unix socket file exists but nothing is listening on it (stale leftover)", async () => {
		const { dir, env } = tmpXdg();
		const handleDir = join(env.XDG_RUNTIME_DIR, "enigma");
		mkdirSync(handleDir, { recursive: true });
		writeFileSync(join(handleDir, "admin.sock"), ""); // a plain leftover file, not a live listener
		try {
			expect(await tryEnigmaCredential("github", { env })).toBeUndefined();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("an explicitly passed fetchImpl always wins, even when a real Unix socket is present -- an explicit transport override must never be silently superseded by auto-detection", async () => {
		const { dir, env } = tmpXdg();
		const handleDir = join(env.XDG_RUNTIME_DIR, "enigma");
		mkdirSync(handleDir, { recursive: true });
		const socketPath = join(handleDir, "admin.sock");
		// A real, live Unix socket that would happily answer -- proves the override is genuine, not just untested absence.
		const unixServer = serveUnixRpc({ path: socketPath, handler: async () => new Response(JSON.stringify({ accessToken: "unix-token" }), { headers: { "content-type": "application/json" } }) });
		try {
			let calls = 0;
			const fetchImpl: typeof fetch = (async () => {
				calls++;
				return new Response(JSON.stringify({ accessToken: "injected-token" }), { headers: { "content-type": "application/json" } });
			}) as typeof fetch;

			const result = await tryEnigmaCredential("github", { env, fetchImpl });
			expect(result).toEqual({ accessToken: "injected-token" });
			expect(calls).toBe(1);
		} finally {
			unixServer.stop();
			try {
				unlinkSync(socketPath);
			} catch {}
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("tryEnigmaWhoAmI over the Unix-socket transport", () => {
	it("resolves this client's real scope over the socket, no token involved", async () => {
		const { dir, env } = tmpXdg();
		const handleDir = join(env.XDG_RUNTIME_DIR, "enigma");
		mkdirSync(handleDir, { recursive: true });
		const socketPath = join(handleDir, "admin.sock");
		const server = serveUnixRpc({
			path: socketPath,
			handler: async (request) => (new URL(request.url).pathname === "/whoami" ? new Response(JSON.stringify({ name: "pipes", backends: ["github", "gitlab"] }), { headers: { "content-type": "application/json" } }) : new Response("not found", { status: 404 })),
		});
		try {
			expect(await tryEnigmaWhoAmI({ env })).toEqual({ name: "pipes", backends: ["github", "gitlab"] });
		} finally {
			server.stop();
			try {
				unlinkSync(socketPath);
			} catch {}
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
