/**
 * showMain, tested directly rather than as a real subprocess: it's a thin
 * wrapper (connect -> getCredentials -> print), and cli.ts's own top-level
 * dispatch is guarded behind import.meta.main specifically so importing
 * this one exported function never also runs the CLI against whatever
 * argv this test file's own process happens to have.
 */
import { describe, expect, it } from "bun:test";
import type { EnigmaAdminClient } from "../src/client.ts";
import { showMain } from "../src/cli.ts";

function fakeClient(overrides: Partial<EnigmaAdminClient> = {}): EnigmaAdminClient {
	return {
		listCredentialKeys: async () => [],
		getCredentials: async () => undefined,
		rotateCredential: async () => {},
		revokeCredential: async () => {},
		listClients: async () => [],
		health: async () => ({ ok: true, version: "test" }),
		...overrides,
	};
}

function captureConsole(): { logs: string[]; errors: string[]; restore: () => void } {
	const logs: string[] = [];
	const errors: string[] = [];
	const originalLog = console.log;
	const originalError = console.error;
	console.log = (msg: string) => logs.push(msg);
	console.error = (msg: string) => errors.push(msg);
	return {
		logs,
		errors,
		restore: () => {
			console.log = originalLog;
			console.error = originalError;
		},
	};
}

describe("showMain", () => {
	it("prints the real, decrypted credential as JSON to stdout, with a warning on stderr first", async () => {
		const client = fakeClient({ getCredentials: async (backend) => (backend === "github" ? { accessToken: "ghp_real_value" } : undefined) });
		const { logs, errors, restore } = captureConsole();
		try {
			await showMain("github", () => client);
		} finally {
			restore();
		}
		expect(JSON.parse(logs[0]!)).toEqual({ accessToken: "ghp_real_value" });
		expect(errors[0]).toContain("github");
		expect(errors[0]).toContain("shell history");
	});

	it("exits with an error, printing nothing to stdout, when no credential is stored for the backend", async () => {
		const client = fakeClient();
		const { logs, errors, restore } = captureConsole();
		const originalExit = process.exit;
		let exitCode: number | undefined;
		// biome-ignore lint: test-only override of process.exit to observe the code without actually terminating the test runner
		process.exit = ((code?: number) => {
			exitCode = code;
			throw new Error("exit");
		}) as never;
		try {
			await showMain("nothing-here", () => client);
		} catch {
			// expected -- our fake process.exit throws to unwind instead of terminating
		} finally {
			process.exit = originalExit;
			restore();
		}
		expect(exitCode).toBe(1);
		expect(logs).toEqual([]);
		expect(errors[0]).toContain("nothing-here");
	});
});
