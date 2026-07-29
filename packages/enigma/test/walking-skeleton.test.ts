/**
 * Exercises the real shipped `enigma` CLI as an actual subprocess against
 * real temp XDG paths — login (writes a real encrypted credential file),
 * a real HTTP health check, then a real SIGTERM. No mocks for the spawn,
 * the encryption, or the HTTP round-trip.
 */
import { describe, expect, it } from "bun:test";
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI_PATH = join(import.meta.dir, "..", "src", "cli.ts");

function tmpDir(): string {
	return mkdtempSync(join(tmpdir(), "enigma-walking-skeleton-"));
}

interface XdgEnv {
	[key: string]: string;
	PATH: string;
	XDG_STATE_HOME: string;
	XDG_DATA_HOME: string;
	XDG_RUNTIME_DIR: string;
	XDG_CONFIG_HOME: string;
	ENIGMA_MASTER_KEY_PROVIDER: string;
}

/** File mode is explicit so isolated subprocess tests never depend on a desktop session. */
function xdgEnv(dir: string): XdgEnv {
	return {
		PATH: process.env.PATH ?? "",
		XDG_STATE_HOME: join(dir, "state"),
		XDG_DATA_HOME: join(dir, "data"),
		XDG_RUNTIME_DIR: join(dir, "run"),
		XDG_CONFIG_HOME: join(dir, "config"),
		ENIGMA_MASTER_KEY_PROVIDER: "file",
	};
}

async function runCli(args: string[], env: Record<string, string>): Promise<{ code: number; stdout: string; stderr: string }> {
	const proc = Bun.spawn(["bun", CLI_PATH, ...args], { env, stdout: "pipe", stderr: "pipe" });
	const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
	return { code, stdout, stderr };
}

async function waitFor(predicate: () => boolean, timeoutMs = 5_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (predicate()) return;
		await new Promise((resolve) => setTimeout(resolve, 50));
	}
	throw new Error("waitFor timed out");
}

describe("enigma walking skeleton (real CLI subprocess)", () => {
	it("serve boots and answers a real HTTP health check", async () => {
		const dir = tmpDir();
		let env: XdgEnv | undefined;
		try {
			env = xdgEnv(dir);
			const proc = Bun.spawn(["bun", CLI_PATH, "serve"], { env, stdout: "ignore", stderr: "pipe" });
			try {
				const handlePath = join(env!.XDG_RUNTIME_DIR, "enigma", "handle.json");
				await waitFor(() => {
					try {
						JSON.parse(readFileSync(handlePath, "utf8"));
						return true;
					} catch {
						return false;
					}
				});
				const { code, stdout } = await runCli(["health"], env);
				expect(code).toBe(0);
				expect(JSON.parse(stdout).ok).toBe(true);
			} finally {
				proc.kill("SIGTERM");
				await proc.exited;
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("writes its handle file world-readable -- Enigma is a cross-user system service, unlike a same-user daemon's owner-only handle", async () => {
		const dir = tmpDir();
		let env: XdgEnv | undefined;
		try {
			env = xdgEnv(dir);
			const proc = Bun.spawn(["bun", CLI_PATH, "serve"], { env, stdout: "ignore", stderr: "pipe" });
			try {
				const handlePath = join(env!.XDG_RUNTIME_DIR, "enigma", "handle.json");
				await waitFor(() => existsSync(handlePath));
				expect(statSync(handlePath).mode & 0o777).toBe(0o644);
			} finally {
				proc.kill("SIGTERM");
				await proc.exited;
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("fails closed without consulting a file key when the pinned Secret Service is unavailable", async () => {
		const dir = tmpDir();
		try {
			const env = { ...xdgEnv(dir), ENIGMA_MASTER_KEY_PROVIDER: "secret-service" };
			const stateDir = join(env.XDG_STATE_HOME, "enigma");
			mkdirSync(stateDir, { recursive: true, mode: 0o700 });
			const fileKey = randomBytes(32).toString("base64");
			writeFileSync(join(stateDir, "master-key.json"), `${JSON.stringify({ version: 1, provider: "secret-service" })}\n`, { mode: 0o600 });
			writeFileSync(join(stateDir, ".master"), `${fileKey}\n`, { mode: 0o600 });

			const result = await runCli(["serve"], env);
			expect(result.code).toBe(1);
			expect(result.stderr).toContain("master key secret-service failure");
			expect(result.stderr).not.toContain(fileKey);
			expect(result.stderr).not.toContain("master-key.ts");
			expect(readFileSync(join(stateDir, ".master"), "utf8")).toBe(`${fileKey}\n`);
			expect(existsSync(join(env.XDG_RUNTIME_DIR, "enigma", "handle.json"))).toBe(false);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("login jenkins stores a real encrypted credential that a live daemon can then serve", async () => {
		const dir = tmpDir();
		let env: XdgEnv | undefined;
		try {
			env = { ...xdgEnv(dir), JENKINS_URL: "https://jenkins.example.com", JENKINS_USER: "bot", JENKINS_API_TOKEN: "real-tok-123" };
			const login = await runCli(["login", "jenkins"], env);
			expect(login.code).toBe(0);
			expect(login.stdout).toContain("Jenkins credentials saved");

			const credentialFile = join(env.XDG_STATE_HOME, "enigma", "credentials", "jenkins.json");
			const onDisk = readFileSync(credentialFile, "utf8");
			expect(onDisk).not.toContain("real-tok-123"); // encrypted at rest, not plaintext

			const proc = Bun.spawn(["bun", CLI_PATH, "serve"], { env, stdout: "ignore", stderr: "pipe" });
			try {
				await waitFor(() => {
					try {
						JSON.parse(readFileSync(join(env!.XDG_RUNTIME_DIR, "enigma", "handle.json"), "utf8"));
						return true;
					} catch {
						return false;
					}
				});
				const list = await runCli(["list"], env);
				expect(JSON.parse(list.stdout)).toEqual(["jenkins"]);
			} finally {
				proc.kill("SIGTERM");
				await proc.exited;
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("login --as stores a second account for the same platform independently, under a distinct alias", async () => {
		const dir = tmpDir();
		let env: XdgEnv | undefined;
		try {
			env = { ...xdgEnv(dir), JENKINS_URL: "https://jenkins.example.com", JENKINS_USER: "bot", JENKINS_API_TOKEN: "first-account-tok" };
			const first = await runCli(["login", "jenkins"], env);
			expect(first.code).toBe(0);
			expect(first.stdout).toContain("Jenkins credentials saved.");

			const secondEnv = { ...env, JENKINS_URL: "https://staging.jenkins.example.com", JENKINS_USER: "staging-bot", JENKINS_API_TOKEN: "second-account-tok" };
			const second = await runCli(["login", "jenkins", "--as", "jenkins-staging"], secondEnv);
			expect(second.code).toBe(0);
			expect(second.stdout).toContain('Jenkins credentials saved (stored as "jenkins-staging").');

			const credentialsDir = join(env.XDG_STATE_HOME, "enigma", "credentials");
			expect(existsSync(join(credentialsDir, "jenkins.json"))).toBe(true);
			expect(existsSync(join(credentialsDir, "jenkins-staging.json"))).toBe(true);
			// Neither login overwrote the other -- both encrypted files exist distinctly, and neither
			// stores the other account's real token (encrypted at rest either way).
			const firstOnDisk = readFileSync(join(credentialsDir, "jenkins.json"), "utf8");
			const secondOnDisk = readFileSync(join(credentialsDir, "jenkins-staging.json"), "utf8");
			expect(firstOnDisk).not.toContain("first-account-tok");
			expect(firstOnDisk).not.toContain("second-account-tok");
			expect(secondOnDisk).not.toContain("second-account-tok");
			expect(secondOnDisk).not.toContain("first-account-tok");

			const proc = Bun.spawn(["bun", CLI_PATH, "serve"], { env, stdout: "ignore", stderr: "pipe" });
			try {
				await waitFor(() => existsSync(join(env!.XDG_RUNTIME_DIR, "enigma", "handle.json")));
				const list = await runCli(["list"], env);
				expect(JSON.parse(list.stdout).sort()).toEqual(["jenkins", "jenkins-staging"]);
			} finally {
				proc.kill("SIGTERM");
				await proc.exited;
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("backend-name casing is normalized end to end through the real CLI: login, client registration, and a live HTTP fetch all agree despite mismatched casing at each step", async () => {
		const dir = tmpDir();
		let env: XdgEnv | undefined;
		try {
			env = { ...xdgEnv(dir), ENIGMA_APIKEY_VALUE: "widget-secret-123" };
			const login = await runCli(["login", "apikey", "--name", "WidgetApi", "--env-var", "WIDGET_API_KEY"], env);
			expect(login.code).toBe(0);
			expect(login.stdout).toContain('API key saved for backend "widgetapi".');

			const credentialsDir = join(env.XDG_STATE_HOME, "enigma", "credentials");
			expect(existsSync(join(credentialsDir, "widgetapi.json"))).toBe(true);
			expect(existsSync(join(credentialsDir, "WidgetApi.json"))).toBe(false);

			// client add now tries a running daemon first (POST /clients) -- started before add,
			// unlike this test's own pre-RPC ordering, so its own admin.sock exists at this
			// process's primary XDG_RUNTIME_DIR path before any fallback to a host-wide Enigma
			// is even considered.
			const proc = Bun.spawn(["bun", CLI_PATH, "serve"], { env, stdout: "ignore", stderr: "pipe" });
			try {
				const handlePath = join(env!.XDG_RUNTIME_DIR, "enigma", "handle.json");
				await waitFor(() => existsSync(handlePath));
				const handle = JSON.parse(readFileSync(handlePath, "utf8")) as { host: string; port: number };
				const baseUrl = `http://${handle.host}:${handle.port}`;

				const add = await runCli(["client", "add", "acme-consumer", "--backends", "WIDGETAPI"], env);
				expect(add.code).toBe(0);
				const clientToken = add.stdout.trim().split("\n").pop() ?? "";
				expect(clientToken.length).toBeGreaterThan(0);

				const whoami = await fetch(`${baseUrl}/whoami`, { headers: { authorization: `Bearer ${clientToken}` } });
				expect(whoami.status).toBe(200);
				expect(await whoami.json()).toEqual({ name: "acme-consumer", backends: ["widgetapi"] });

				const creds = await fetch(`${baseUrl}/creds/WidgetApi`, { headers: { authorization: `Bearer ${clientToken}` } });
				expect(creds.status).toBe(200);
				expect(await creds.json()).toEqual({ accessToken: "widget-secret-123", extra: { envVarName: "WIDGET_API_KEY" } });
			} finally {
				proc.kill("SIGTERM");
				await proc.exited;
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("client add --uid registers over the real running daemon's admin RPC, and the bound uid is stored correctly", async () => {
		const dir = tmpDir();
		let env: (XdgEnv & { ENIGMA_ADMIN_UID: string }) | undefined;
		try {
			const myUid = process.getuid?.();
			expect(myUid).toBeDefined();
			// This test process's own uid must be this daemon's trusted admin for client
			// add --uid to actually exercise the new POST /clients RPC path rather than
			// falling back to local-file registration on an unauthorized 401. Binding the
			// *registered client* to this same uid (a separate, later concern -- which real
			// OS process actually authenticates as "acme-consumer" over the socket) is
			// covered by createUnixSocketHandler's own server.ts unit tests, not here: this
			// one real test process's uid can only ever play one identity role at a time
			// over one real connection, and it's already spent being trusted as admin.
			env = { ...xdgEnv(dir), ENIGMA_ADMIN_UID: String(myUid) };

			const proc = Bun.spawn(["bun", CLI_PATH, "serve"], { env, stdout: "ignore", stderr: "pipe" });
			try {
				const socketPath = join(env.XDG_RUNTIME_DIR, "enigma", "admin.sock");
				await waitFor(() => existsSync(socketPath));

				const add = await runCli(["client", "add", "acme-consumer", "--backends", "WIDGETAPI", "--uid", "999999"], env);
				expect(add.code).toBe(0);
				expect(add.stdout).toContain("via the running daemon");

				const list = await runCli(["client", "list"], env);
				expect(list.code).toBe(0);
				expect(JSON.parse(list.stdout)).toEqual([{ name: "acme-consumer", backends: ["widgetapi"], createdAt: expect.any(String), uid: 999999 }]);
			} finally {
				proc.kill("SIGTERM");
				await proc.exited;
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("a real client fetches a real credential over the Unix-socket transport with zero bearer token, authenticated purely by its real OS uid", async () => {
		const dir = tmpDir();
		let env: (XdgEnv & { ENIGMA_ADMIN_UID: string }) | undefined;
		try {
			const myUid = process.getuid?.();
			expect(myUid).toBeDefined();
			env = { ...xdgEnv(dir), ENIGMA_APIKEY_VALUE: "widget-secret-123", ENIGMA_ADMIN_UID: String(myUid) };

			const login = await runCli(["login", "apikey", "--name", "WidgetApi", "--env-var", "WIDGET_API_KEY"], env);
			expect(login.code).toBe(0);

			const proc = Bun.spawn(["bun", CLI_PATH, "serve"], { env, stdout: "ignore", stderr: "pipe" });
			try {
				const socketPath = join(env.XDG_RUNTIME_DIR, "enigma", "admin.sock");
				await waitFor(() => existsSync(socketPath));

				// Raw client speaking unix-rpc-server's own newline-delimited JSON framing directly --
				// no Authorization header at all, proving identity comes only from the real connecting
				// process's own kernel-verified uid (this test process's own, running as admin here).
				const { promise, resolve } = Promise.withResolvers<{ status: number; body: string | null }>();
				let buffered = "";
				const client = await Bun.connect({
					unix: socketPath,
					socket: {
						open(socket) {
							socket.write(`${JSON.stringify({ method: "GET", path: "/creds/WidgetApi" })}\n`);
						},
						data(_socket, chunk) {
							buffered += chunk.toString("utf8");
							const newlineIndex = buffered.indexOf("\n");
							if (newlineIndex !== -1) resolve(JSON.parse(buffered.slice(0, newlineIndex)));
						},
						close() {},
					},
				});
				const response = await promise;
				client.end();

				expect(response.status).toBe(200);
				expect(JSON.parse(response.body ?? "null")).toEqual({ accessToken: "widget-secret-123", extra: { envVarName: "WIDGET_API_KEY" } });
			} finally {
				proc.kill("SIGTERM");
				await proc.exited;
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("pins Secret Service across separate login and daemon processes when a desktop service is available", async () => {
		const dbusAddress = process.env.DBUS_SESSION_BUS_ADDRESS;
		if (!dbusAddress) return;
		const probe = spawnSync("/usr/bin/secret-tool", ["lookup", "service", "__enigma_probe_missing__", "username", "master"], { maxBuffer: 4096 });
		if (probe.error || probe.status !== 1 || probe.stderr.length !== 0) return;

		const dir = tmpDir();
		const service = `danypops.enigma.test.${randomUUID()}`;
		const account = "master";
		const env: XdgEnv = {
			...xdgEnv(dir),
			DBUS_SESSION_BUS_ADDRESS: dbusAddress,
			ENIGMA_MASTER_KEY_PROVIDER: "secret-service",
			ENIGMA_KEYRING_SERVICE: service,
			ENIGMA_KEYRING_ACCOUNT: account,
			JENKINS_URL: "https://jenkins.example.com",
			JENKINS_USER: "fixture-user",
			JENKINS_API_TOKEN: "fixture-token",
		};
		if (process.env.HOME) env.HOME = process.env.HOME;

		try {
			const login = await runCli(["login", "jenkins"], env);
			expect(login.code).toBe(0);
			const stateDir = join(env.XDG_STATE_HOME, "enigma");
			expect(JSON.parse(readFileSync(join(stateDir, "master-key.json"), "utf8"))).toEqual({ version: 1, provider: "secret-service" });
			expect(existsSync(join(stateDir, ".master"))).toBe(false);

			const proc = Bun.spawn(["bun", CLI_PATH, "serve"], { env, stdout: "pipe", stderr: "pipe" });
			try {
				await waitFor(() => existsSync(join(env.XDG_RUNTIME_DIR, "enigma", "handle.json")));
				const list = await runCli(["list"], env);
				expect(list.code).toBe(0);
				expect(JSON.parse(list.stdout)).toEqual(["jenkins"]);
			} finally {
				proc.kill("SIGTERM");
				const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
				await proc.exited;
				expect(stdout).not.toContain("fixture-token");
				expect(stderr).not.toContain("fixture-token");
			}
		} finally {
			spawnSync("/usr/bin/secret-tool", ["clear", "service", service, "username", account], { maxBuffer: 4096 });
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("ENIGMA_POLKIT_ENABLED wires a real pkcheck call into a real running daemon -- denies gracefully (falls back to local-file registration) since no .policy is actually installed on this machine, without crashing the daemon or the CLI", async () => {
		const dir = tmpDir();
		let env: XdgEnv & { ENIGMA_POLKIT_ENABLED: string };
		try {
			// Deliberately no ENIGMA_ADMIN_UID: this test process's own real uid must not
			// already be trusted as admin, so client add is forced through the polkit path
			// instead of short-circuiting on the existing admin-uid check.
			env = { ...xdgEnv(dir), ENIGMA_POLKIT_ENABLED: "1" };

			const proc = Bun.spawn(["bun", CLI_PATH, "serve"], { env, stdout: "ignore", stderr: "pipe" });
			try {
				const socketPath = join(env.XDG_RUNTIME_DIR, "enigma", "admin.sock");
				await waitFor(() => existsSync(socketPath));

				// No real com.danypops.enigma.manage-clients policy is installed on this machine
				// (that's a real, separate root-owned step -- see contrib/polkit/), so the real
				// pkcheck call genuinely denies here. Proves the wiring doesn't crash the daemon
				// or hang the CLI, and that clientMain's own fallback still lands correctly.
				const add = await runCli(["client", "add", "acme-consumer", "--backends", "WIDGETAPI"], env);
				expect(add.code).toBe(0);
				expect(add.stdout).not.toContain("via the running daemon");

				const credentialsDir = join(env.XDG_STATE_HOME, "enigma", "clients.json");
				expect(existsSync(credentialsDir)).toBe(true);
			} finally {
				proc.kill("SIGTERM");
				await proc.exited;
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
