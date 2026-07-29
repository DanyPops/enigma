import { describe, expect, it } from "bun:test";
import type { ExecFileException } from "node:child_process";
import { createPkcheckAuthorizer, ENIGMA_MANAGE_CLIENTS_ACTION_ID, readProcessStartTime } from "../src/polkit-check.ts";

describe("readProcessStartTime", () => {
	it("reads a real, positive start-time for this test's own real running process", () => {
		const startTime = readProcessStartTime(process.pid);
		expect(startTime).toBeDefined();
		expect(startTime).toBeGreaterThan(0);
		expect(Number.isInteger(startTime)).toBe(true);
	});

	it("resolves undefined, never throws, for a pid that doesn't exist", () => {
		// A pid this large is never a real process on any real system.
		expect(readProcessStartTime(999_999_999)).toBeUndefined();
	});
});

describe("createPkcheckAuthorizer", () => {
	function fakeExecFile(behavior: { error: ExecFileException | null }): typeof import("node:child_process").execFile {
		return ((_file: string, _args: string[], callback: (error: ExecFileException | null) => void) => {
			callback(behavior.error);
			// biome-ignore lint/suspicious/noExplicitAny: matching execFile's own real return type isn't needed for this fake
			return {} as any;
		}) as typeof import("node:child_process").execFile;
	}

	it("resolves true when pkcheck exits 0 (authorized)", async () => {
		const authorize = createPkcheckAuthorizer({ execFileImpl: fakeExecFile({ error: null }) });
		const result = await authorize({ pid: process.pid, uid: 1000, gid: 1000 }, ENIGMA_MANAGE_CLIENTS_ACTION_ID);
		expect(result).toBe(true);
	});

	it("resolves false when pkcheck exits non-zero (not authorized, no agent, dismissed, or malformed)", async () => {
		const error = new Error("Command failed") as ExecFileException;
		error.code = 1;
		const authorize = createPkcheckAuthorizer({ execFileImpl: fakeExecFile({ error }) });
		const result = await authorize({ pid: process.pid, uid: 1000, gid: 1000 }, ENIGMA_MANAGE_CLIENTS_ACTION_ID);
		expect(result).toBe(false);
	});

	it("resolves false, never throws, when pkcheck itself isn't installed (ENOENT-shaped spawn failure)", async () => {
		const error = new Error("spawn pkcheck ENOENT") as ExecFileException;
		error.code = "ENOENT";
		const authorize = createPkcheckAuthorizer({ execFileImpl: fakeExecFile({ error }) });
		const result = await authorize({ pid: process.pid, uid: 1000, gid: 1000 }, ENIGMA_MANAGE_CLIENTS_ACTION_ID);
		expect(result).toBe(false);
	});

	it("resolves false, never throws, when the peer's pid has already exited (no start-time to build a safe subject from) -- never even attempts to spawn pkcheck in that case", async () => {
		let execFileWasCalled = false;
		const execFileImpl = (() => {
			execFileWasCalled = true;
		}) as unknown as typeof import("node:child_process").execFile;
		const authorize = createPkcheckAuthorizer({ execFileImpl });
		const result = await authorize({ pid: 999_999_999, uid: 1000, gid: 1000 }, ENIGMA_MANAGE_CLIENTS_ACTION_ID);
		expect(result).toBe(false);
		expect(execFileWasCalled).toBe(false);
	});

	it("passes pid,start-time,uid -- never bare pid or pid,start-time -- matching pkcheck's own documented race-condition warning", async () => {
		let seenArgs: string[] | undefined;
		const execFileImpl = ((_file: string, args: string[], callback: (error: ExecFileException | null) => void) => {
			seenArgs = args;
			callback(null);
			// biome-ignore lint/suspicious/noExplicitAny: matching execFile's own real return type isn't needed for this fake
			return {} as any;
		}) as typeof import("node:child_process").execFile;
		const authorize = createPkcheckAuthorizer({ execFileImpl });
		await authorize({ pid: process.pid, uid: 4217278, gid: 4217278 }, ENIGMA_MANAGE_CLIENTS_ACTION_ID);
		expect(seenArgs).toBeDefined();
		const processIndex = seenArgs!.indexOf("--process");
		expect(processIndex).toBeGreaterThanOrEqual(0);
		const subject = seenArgs![processIndex + 1]!;
		const parts = subject.split(",");
		expect(parts).toHaveLength(3);
		expect(parts[0]).toBe(String(process.pid));
		expect(parts[2]).toBe("4217278");
		expect(Number.isInteger(Number(parts[1]))).toBe(true);
	});

	it("passes the given action id through to --action-id", async () => {
		let seenArgs: string[] | undefined;
		const execFileImpl = ((_file: string, args: string[], callback: (error: ExecFileException | null) => void) => {
			seenArgs = args;
			callback(null);
			// biome-ignore lint/suspicious/noExplicitAny: matching execFile's own real return type isn't needed for this fake
			return {} as any;
		}) as typeof import("node:child_process").execFile;
		const authorize = createPkcheckAuthorizer({ execFileImpl });
		await authorize({ pid: process.pid, uid: 1000, gid: 1000 }, "com.example.custom-action");
		const actionIndex = seenArgs!.indexOf("--action-id");
		expect(seenArgs![actionIndex + 1]).toBe("com.example.custom-action");
	});
});

describe("createPkcheckAuthorizer: real pkcheck binary integration", () => {
	it("resolves false for a bogus, definitely-unregistered action id against the real installed pkcheck -- no custom .policy install needed to prove the real subprocess plumbing (argv shape, exit-code parsing) works end to end", async () => {
		const authorize = createPkcheckAuthorizer();
		const result = await authorize({ pid: process.pid, uid: process.getuid?.() ?? 0, gid: process.getgid?.() ?? 0 }, "com.danypops.enigma.definitely-not-a-real-registered-action");
		expect(result).toBe(false);
	});
});
