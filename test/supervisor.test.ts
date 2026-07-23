/**
 * Real subprocess spawns via a fixture daemon — restart policy, freshness-
 * triggered restarts, and the shutdown contract all need to be observed
 * against actual child processes, not asserted against a mock scheduler.
 */
import { describe, expect, it } from "bun:test";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { SupervisorConfig } from "@danypops/daemon-kit/supervisor";
import { createCredentialVault } from "../src/credential-vault.ts";
import { runSupervisor } from "../src/supervisor.ts";

const FIXTURE = join(import.meta.dir, "fixtures", "fake-daemon.ts");

function tmpDir(): string {
	return mkdtempSync(join(tmpdir(), "enigma-supervisor-"));
}

async function waitFor(predicate: () => boolean, timeoutMs = 3_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (predicate()) return;
		await new Promise((resolve) => setTimeout(resolve, 20));
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

describe("runSupervisor", () => {
	it("spawns a unit with its credentials resolved into real child env under the right mapped var name", async () => {
		const dir = tmpDir();
		try {
			const logPath = join(dir, "log.txt");
			const vault = createCredentialVault({ dir: join(dir, "creds"), masterKey: randomBytes(32) });
			vault.save("github", { accessToken: "injected-gh-token" });

			const config: SupervisorConfig = { units: [{ name: "probe", bin: "bun", args: [FIXTURE, logPath], backends: ["github"] }] };
			const supervisor = runSupervisor(config, vault);
			try {
				await waitFor(() => readLog(logPath).length > 0);
				expect(readLog(logPath)[0]).toContain(`"GITHUB_TOKEN":"injected-gh-token"`);
			} finally {
				await supervisor.stop();
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("maps a jenkins credential's extra fields to all three env vars a Jenkins consumer daemon needs", async () => {
		const dir = tmpDir();
		try {
			const logPath = join(dir, "log.txt");
			const vault = createCredentialVault({ dir: join(dir, "creds"), masterKey: randomBytes(32) });
			vault.save("jenkins", { accessToken: "jenkins-api-tok", extra: { username: "bot", url: "https://jenkins.example.com" } });

			const config: SupervisorConfig = { units: [{ name: "probe", bin: "bun", args: [FIXTURE, logPath], backends: ["jenkins"] }] };
			const supervisor = runSupervisor(config, vault);
			try {
				await waitFor(() => readLog(logPath).length > 0);
				const line = readLog(logPath)[0] ?? "";
				expect(line).toContain(`"JENKINS_API_TOKEN":"jenkins-api-tok"`);
				expect(line).toContain(`"JENKINS_USER":"bot"`);
				expect(line).toContain(`"JENKINS_URL":"https://jenkins.example.com"`);
			} finally {
				await supervisor.stop();
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("restart: always relaunches after a clean exit", async () => {
		const dir = tmpDir();
		try {
			const logPath = join(dir, "log.txt");
			const vault = createCredentialVault({ dir: join(dir, "creds"), masterKey: randomBytes(32) });
			const config: SupervisorConfig = {
				units: [{ name: "probe", bin: "bun", args: [FIXTURE, logPath], backends: [], env: { EXIT_CODE: "0" }, restart: "always" }],
			};
			const supervisor = runSupervisor(config, vault);
			try {
				await waitFor(() => readLog(logPath).filter((l) => l.startsWith("start:")).length >= 2, 4_000);
			} finally {
				await supervisor.stop();
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("restart: on-failure does not relaunch after a clean (code 0) exit", async () => {
		const dir = tmpDir();
		try {
			const logPath = join(dir, "log.txt");
			const vault = createCredentialVault({ dir: join(dir, "creds"), masterKey: randomBytes(32) });
			const config: SupervisorConfig = {
				units: [{ name: "probe", bin: "bun", args: [FIXTURE, logPath], backends: [], env: { EXIT_CODE: "0" }, restart: "on-failure" }],
			};
			const supervisor = runSupervisor(config, vault);
			try {
				await waitFor(() => readLog(logPath).some((l) => l.startsWith("start:")));
				await new Promise((resolve) => setTimeout(resolve, 200));
				expect(readLog(logPath).filter((l) => l.startsWith("start:")).length).toBe(1);
			} finally {
				await supervisor.stop();
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("restart: on-failure relaunches after a nonzero exit", async () => {
		const dir = tmpDir();
		try {
			const logPath = join(dir, "log.txt");
			const vault = createCredentialVault({ dir: join(dir, "creds"), masterKey: randomBytes(32) });
			const config: SupervisorConfig = {
				units: [{ name: "probe", bin: "bun", args: [FIXTURE, logPath], backends: [], env: { EXIT_CODE: "1" }, restart: "on-failure" }],
			};
			const supervisor = runSupervisor(config, vault);
			try {
				await waitFor(() => readLog(logPath).filter((l) => l.startsWith("start:")).length >= 2, 4_000);
			} finally {
				await supervisor.stop();
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("default restart policy (no) does not relaunch at all", async () => {
		const dir = tmpDir();
		try {
			const logPath = join(dir, "log.txt");
			const vault = createCredentialVault({ dir: join(dir, "creds"), masterKey: randomBytes(32) });
			const config: SupervisorConfig = { units: [{ name: "probe", bin: "bun", args: [FIXTURE, logPath], backends: [], env: { EXIT_CODE: "1" } }] };
			const supervisor = runSupervisor(config, vault);
			try {
				await waitFor(() => readLog(logPath).some((l) => l.startsWith("start:")));
				await new Promise((resolve) => setTimeout(resolve, 200));
				expect(readLog(logPath).filter((l) => l.startsWith("start:")).length).toBe(1);
			} finally {
				await supervisor.stop();
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("restarts a unit with fresh env once its credential nears expiry, even with restart: no", async () => {
		const dir = tmpDir();
		try {
			const logPath = join(dir, "log.txt");
			const vault = createCredentialVault({ dir: join(dir, "creds"), masterKey: randomBytes(32) });
			// Already expired: isTokenFresh returns false immediately.
			vault.save("github", { accessToken: "stale", expiresAt: new Date(Date.now() - 1_000).toISOString() });

			const config: SupervisorConfig = { units: [{ name: "probe", bin: "bun", args: [FIXTURE, logPath], backends: ["github"], restart: "no" }] };
			const supervisor = runSupervisor(config, vault, { freshnessCheckMs: 50 });
			try {
				await waitFor(() => readLog(logPath).filter((l) => l.startsWith("start:")).length >= 2, 4_000);
				expect(readLog(logPath)).toContain("sigterm");
			} finally {
				await supervisor.stop();
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("scrubs an arbitrarily-named generic OIDC backend's credential from a unit that never requested it — the same leak class this scrub mechanism was built to close, now verified for the generic path too", async () => {
		const dir = tmpDir();
		try {
			const logPathA = join(dir, "log-a.txt");
			const logPathB = join(dir, "log-b.txt");
			const vault = createCredentialVault({ dir: join(dir, "creds"), masterKey: randomBytes(32) });
			vault.save("my-company-sso", { accessToken: "sso-secret-value", extra: { envVarName: "MY_COMPANY_SSO_TOKEN" } });

			const config: SupervisorConfig = {
				units: [
					{ name: "unit-a", bin: "bun", args: [FIXTURE, logPathA], backends: ["my-company-sso"], restart: "no" },
					{ name: "unit-b", bin: "bun", args: [FIXTURE, logPathB], backends: [], restart: "no" },
				],
			};
			const supervisor = runSupervisor(config, vault);
			try {
				await waitFor(() => readLog(logPathA).some((l) => l.startsWith("start:")) && readLog(logPathB).some((l) => l.startsWith("start:")));
				const lineA = readLog(logPathA).find((l) => l.startsWith("start:")) ?? "";
				const lineB = readLog(logPathB).find((l) => l.startsWith("start:")) ?? "";
				expect(lineA).toContain(`"MY_COMPANY_SSO_TOKEN":"sso-secret-value"`);
				// unit-b never requested this backend — the arbitrary var name must be blanked, not absent-or-ambient.
				expect(JSON.parse(lineB.slice("start:".length)).MY_COMPANY_SSO_TOKEN).toBe("");
				expect(lineB).not.toContain("sso-secret-value");
			} finally {
				await supervisor.stop();
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("stop() sends SIGTERM to every child and resolves only once they've all exited", async () => {
		const dir = tmpDir();
		try {
			const logPath = join(dir, "log.txt");
			const vault = createCredentialVault({ dir: join(dir, "creds"), masterKey: randomBytes(32) });
			const config: SupervisorConfig = { units: [{ name: "probe", bin: "bun", args: [FIXTURE, logPath], backends: [] }] };
			const supervisor = runSupervisor(config, vault);
			await waitFor(() => readLog(logPath).some((l) => l.startsWith("start:")));

			await supervisor.stop();
			expect(readLog(logPath)).toContain("sigterm");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
