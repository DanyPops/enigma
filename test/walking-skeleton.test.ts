/**
 * Exercises the real shipped `enigma` CLI as an actual subprocess against
 * real temp XDG paths — login (writes a real encrypted credential file),
 * then supervisor (spawns a real fixture daemon with that credential
 * injected as real env), then a real HTTP health check, then a real
 * SIGTERM proving the documented shutdown contract end to end. No mocks
 * for the spawn, the encryption, or the HTTP round-trip.
 */
import { describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI_PATH = join(import.meta.dir, "..", "src", "cli.ts");
const FIXTURE = join(import.meta.dir, "fixtures", "fake-daemon.ts");

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
	ENIGMA_DISABLE_KEYRING: string;
}

/**
 * Forces the deterministic file-based master-key fallback rather than the
 * real OS keyring. Confirmed directly during development: under a fully
 * replaced (not merged) subprocess environment — no DBUS_SESSION_BUS_ADDRESS,
 * a custom XDG_RUNTIME_DIR — the real Secret Service session can't be found
 * consistently, so the keyring backend silently resolves to a different,
 * non-persistent key on every subprocess invocation. The file fallback is
 * fully under this test's control (an isolated temp dir) and has none of
 * that nondeterminism.
 */
function xdgEnv(dir: string): XdgEnv {
	return {
		PATH: process.env.PATH ?? "",
		XDG_STATE_HOME: join(dir, "state"),
		XDG_DATA_HOME: join(dir, "data"),
		XDG_RUNTIME_DIR: join(dir, "run"),
		XDG_CONFIG_HOME: join(dir, "config"),
		ENIGMA_DISABLE_KEYRING: "1",
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

function readLog(path: string): string[] {
	try {
		return readFileSync(path, "utf8").split("\n").filter(Boolean);
	} catch {
		return [];
	}
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

	it("supervisor spawns two configured units, each with its own credential injected as real env, and SIGTERM propagates to both children, with no raw token ever printed to enigma's own output", async () => {
		const dir = tmpDir();
		let env: XdgEnv | undefined;
		try {
			env = { ...xdgEnv(dir), JENKINS_URL: "https://jenkins.example.com", JENKINS_USER: "bot", JENKINS_API_TOKEN: "supervised-real-tok" };
			expect((await runCli(["login", "jenkins"], env)).code).toBe(0);

			// Seed a second backend directly so this test doesn't need a live GitHub device flow
			// just to prove two-unit spawning — the device flow itself is covered by login-command.test.ts.
			// Uses the file-based master key directly (skipping the keyring path entirely, matching
			// ENIGMA_DISABLE_KEYRING=1 in the subprocess env below) so this in-process write and the
			// supervisor subprocess's read are guaranteed to resolve the identical master key.
			const { createCredentialVault } = await import("../src/credential-vault.ts");
			const { getOrCreateMasterKeyFromFile } = await import("../src/master-key.ts");
			const { resolveEnigmaExtraPaths, resolveEnigmaPaths } = await import("../src/paths.ts");
			const extra = resolveEnigmaExtraPaths(resolveEnigmaPaths({ env }));
			createCredentialVault({
				dir: extra.credentialsDir,
				masterKey: getOrCreateMasterKeyFromFile(extra.masterKeyFile),
			}).save("github", { accessToken: "second-unit-real-tok" });

			const logPathA = join(dir, "child-log-a.txt");
			const logPathB = join(dir, "child-log-b.txt");
			const configPath = join(dir, "daemons.json");
			writeFileSync(
				configPath,
				JSON.stringify({
					units: [
						{ name: "unit-a", bin: "bun", args: [FIXTURE, logPathA], backends: ["jenkins"], restart: "no" },
						{ name: "unit-b", bin: "bun", args: [FIXTURE, logPathB], backends: ["github"], restart: "no" },
					],
				}),
			);

			const proc = Bun.spawn(["bun", CLI_PATH, "supervisor", "--config", configPath], { env, stdout: "pipe", stderr: "pipe" });
			try {
				await waitFor(() => readLog(logPathA).some((l) => l.startsWith("start:")) && readLog(logPathB).some((l) => l.startsWith("start:")));
				const lineA = readLog(logPathA).find((l) => l.startsWith("start:")) ?? "";
				const lineB = readLog(logPathB).find((l) => l.startsWith("start:")) ?? "";
				expect(lineA).toContain("JENKINS_API_TOKEN=supervised-real-tok");
				expect(lineA).toContain("JENKINS_USER=bot");
				expect(lineB).toContain("GITHUB_TOKEN=second-unit-real-tok");

				// Real HTTP health check against the same process that's also supervising.
				await waitFor(() => {
					try {
						JSON.parse(readFileSync(join(env!.XDG_RUNTIME_DIR, "enigma", "handle.json"), "utf8"));
						return true;
					} catch {
						return false;
					}
				});
				const health = await runCli(["health"], env);
				expect(JSON.parse(health.stdout).ok).toBe(true);
			} finally {
				proc.kill("SIGTERM");
				const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
				await proc.exited;
				// Documented shutdown contract: every spawned child gets SIGTERM too.
				await waitFor(() => readLog(logPathA).includes("sigterm") && readLog(logPathB).includes("sigterm"));
				// The raw credential values must never appear in enigma's own process output.
				expect(stdout).not.toContain("supervised-real-tok");
				expect(stdout).not.toContain("second-unit-real-tok");
				expect(stderr).not.toContain("supervised-real-tok");
				expect(stderr).not.toContain("second-unit-real-tok");
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
