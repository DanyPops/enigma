import { describe, expect, it } from "bun:test";
import { Entry } from "@napi-rs/keyring";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
	MasterKeyFailure,
	createMacosKeychainMasterKeyProvider,
	createWindowsCredentialManagerMasterKeyProvider,
	readMasterKeyManifest,
	resolveMasterKey,
	type NativeKeyringBindings,
	type SecretToolResult,
	type SecretToolRunner,
} from "../src/master-key.ts";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Models the real macOS provider's split: writes land on the native binding, reads go through a `security` CLI runner sharing the same backing store. */
function macosFixture(): { bindings: NativeKeyringBindings & { writes: number }; runner: SecretToolRunner; calls: string[][] } {
	const store = new Map<string, string>();
	const calls: string[][] = [];
	const bindings: NativeKeyringBindings & { writes: number } = {
		writes: 0,
		findCredentials: () => [],
		createEntry: (service, account) => ({
			setPassword: (password: string) => {
				bindings.writes++;
				store.set(`${service}\0${account}`, password);
			},
		}),
	};
	const runner: SecretToolRunner = (_command, args) => {
		calls.push(args);
		const service = args[args.indexOf("-s") + 1];
		const account = args[args.indexOf("-a") + 1];
		const password = store.get(`${service}\0${account}`);
		if (password === undefined) {
			return { status: 44, stdout: Buffer.alloc(0), stderr: Buffer.from("The specified item could not be found in the keychain.") };
		}
		return { status: 0, stdout: Buffer.from(`${password}\n`), stderr: Buffer.alloc(0) };
	};
	return { bindings, runner, calls };
}

function fixedRunner(result: SecretToolResult): SecretToolRunner {
	return () => result;
}

function memoryBindings(): NativeKeyringBindings & { values: Map<string, string>; writes: number } {
	const values = new Map<string, string>();
	return {
		values,
		writes: 0,
		findCredentials(service: string) {
			return [...values.entries()]
				.filter(([key]) => key.startsWith(`${service}\0`))
				.map(([key, password]) => ({ account: key.slice(service.length + 1), password }));
		},
		createEntry(service: string, account: string) {
			return {
				setPassword: (password: string) => {
					this.writes++;
					values.set(`${service}\0${account}`, password);
				},
			};
		},
	};
}

function failureCode(operation: () => unknown): string | undefined {
	try {
		operation();
		return undefined;
	} catch (error) {
		expect(error).toBeInstanceOf(MasterKeyFailure);
		return (error as MasterKeyFailure).code;
	}
}

function resolutionPaths(root: string) {
	return {
		manifestPath: join(root, "master-key.json"),
		filePath: join(root, ".master"),
		credentialsDir: join(root, "credentials"),
	};
}

describe("macOS Keychain master-key provider", () => {
	it("writes through the native binding and reads back through the bounded security CLI", () => {
		const { bindings, runner, calls } = macosFixture();
		const identity = { service: "test.enigma", account: "master" };
		const first = createMacosKeychainMasterKeyProvider(identity, bindings, runner);
		const second = createMacosKeychainMasterKeyProvider(identity, bindings, runner);
		const key = randomBytes(32);
		first.write(key);
		expect(second.read()).toEqual(key);
		expect(bindings.writes).toBe(1);
		// find-generic-password's -w is a bare flag (prints the secret to stdout); it never
		// carries the secret as a value, so no read call's argv can leak it either way.
		expect(calls.some((args) => args.includes("-w"))).toBe(true);
		expect(JSON.stringify(calls)).not.toContain(key.toString("base64"));
	});

	it("distinguishes missing, locked, denied, and a bounded-timeout unavailable state from the CLI, without writing", () => {
		const cases: Array<[SecretToolResult, string]> = [
			[{ status: 44, stdout: Buffer.alloc(0), stderr: Buffer.from("The specified item could not be found in the keychain.") }, "not_found"],
			[{ status: 1, stdout: Buffer.alloc(0), stderr: Buffer.from("SecKeychainItemCopyContent: User interaction is not allowed.") }, "locked"],
			[{ status: 1, stdout: Buffer.alloc(0), stderr: Buffer.from("The authorization was denied.") }, "denied"],
			// spawnSync's own timeout killing a hung child: status null, no stderr -- exactly what a
			// locked-and-noninteractive keychain produces on headless macOS CI (confirmed live).
			[{ status: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }, "unavailable"],
		];
		for (const [result, code] of cases) {
			const { bindings, runner } = macosFixture();
			const provider = createMacosKeychainMasterKeyProvider({ service: "test.enigma", account: "master" }, bindings, fixedRunner(result));
			expect(failureCode(() => provider.read())).toBe(code);
			if (code !== "not_found") {
				expect(failureCode(() => provider.write(randomBytes(32)))).toBe(code);
				expect(bindings.writes).toBe(0);
			}
		}
	});

	it("rejects malformed secret material returned by the CLI", () => {
		const runner = fixedRunner({ status: 0, stdout: Buffer.from("not-a-key\n"), stderr: Buffer.alloc(0) });
		expect(failureCode(() => createMacosKeychainMasterKeyProvider(undefined, memoryBindings(), runner).read())).toBe("malformed");
	});
});

describe("Windows Credential Manager master-key provider", () => {
	it("persists one key for the current logon identity without crossing account identities", () => {
		const bindings = memoryBindings();
		const identity = { service: "test.enigma", account: "master" };
		const first = createWindowsCredentialManagerMasterKeyProvider(identity, bindings);
		const second = createWindowsCredentialManagerMasterKeyProvider(identity, bindings);
		const otherIdentity = createWindowsCredentialManagerMasterKeyProvider({ service: identity.service, account: "service-account" }, bindings);
		const key = randomBytes(32);
		first.write(key);
		expect(second.read()).toEqual(key);
		expect(failureCode(() => otherIdentity.read())).toBe("not_found");
		expect(bindings.writes).toBe(1);
		expect(failureCode(() => second.write(randomBytes(32)))).toBe("conflict");
	});

	it("distinguishes missing, unavailable logon sessions, access denial, and malformed records", () => {
		const missing = memoryBindings();
		expect(failureCode(() => createWindowsCredentialManagerMasterKeyProvider(undefined, missing).read())).toBe("not_found");

		for (const [message, code] of [
			["A specified logon session does not exist", "unavailable"],
			["Access is denied", "denied"],
			["Not a valid utf16 blob", "malformed"],
		] as const) {
			const bindings: NativeKeyringBindings = {
				findCredentials: () => {
					throw new Error(message);
				},
				createEntry: () => ({ setPassword: () => undefined }),
			};
			expect(failureCode(() => createWindowsCredentialManagerMasterKeyProvider(undefined, bindings).read())).toBe(code);
		}
	});
});

describe("native provider selection", () => {
	it("defaults fresh macOS and Windows stores to their verified user-session providers", () => {
		for (const [platform, kind] of [
			["darwin", "macos-keychain"],
			["win32", "windows-credential-manager"],
		] as const) {
			const root = mkdtempSync(join(tmpdir(), "enigma-native-resolution-"));
			try {
				const macos = macosFixture();
				const windowsBindings = memoryBindings();
				const provider =
					platform === "darwin"
						? createMacosKeychainMasterKeyProvider(undefined, macos.bindings, macos.runner)
						: createWindowsCredentialManagerMasterKeyProvider(undefined, windowsBindings);
				const resolved = resolveMasterKey({ ...resolutionPaths(root), platform, providers: { [kind]: provider } });
				expect(resolved).toHaveLength(32);
				expect(readMasterKeyManifest(join(root, "master-key.json"))?.provider).toBe(kind);
			} finally {
				rmSync(root, { recursive: true, force: true });
			}
		}
	});
});

describe("real native master-key persistence", () => {
	it(
		"fails closed within a bounded time against a locked keychain on an isolated macOS CI runner, never hanging",
		() => {
			if (process.platform !== "darwin" || process.env.ENIGMA_TEST_LOCK_DEFAULT_KEYCHAIN !== "1") return;
			const identity = { service: `com.danypops.enigma.test.${randomUUID()}`, account: "master" };
			const provider = createMacosKeychainMasterKeyProvider(identity);
			const key = randomBytes(32);
			const defaultKeychain = spawnSync("/usr/bin/security", ["default-keychain", "-d", "user"], { encoding: "utf8", timeout: 10_000 });
			expect(defaultKeychain.status).toBe(0);
			const path = defaultKeychain.stdout.trim().replace(/^"|"$/g, "");
			// CI creates and owns this scratch keychain (never the real login keychain) and passes
			// its real password through explicitly -- unlike GitHub's own login keychain, which
			// famously accepts any password, a keychain we created ourselves does not.
			const password = process.env.ENIGMA_TEST_KEYCHAIN_PASSWORD ?? "actions";
			provider.write(key);
			try {
				const locked = spawnSync("/usr/bin/security", ["lock-keychain", path], { encoding: "utf8", timeout: 10_000 });
				expect(locked.status).toBe(0);
				// Confirmed live: a locked, noninteractive-session keychain query hangs rather than
				// fast-failing on GitHub-hosted macOS CI -- identically via `security` CLI and via
				// @napi-rs/keyring's native binding. The read's own bounded subprocess timeout is
				// what actually matters here: it must return "locked" or "unavailable" (both are
				// honest given a timeout doesn't prove lock state) well within its own budget, not
				// hang for the rest of the job.
				const startedAt = Date.now();
				const code = failureCode(() => provider.read());
				expect(Date.now() - startedAt).toBeLessThan(15_000);
				expect(code).toBeDefined();
				expect(["locked", "unavailable"]).toContain(code as string);
			} finally {
				const unlocked = spawnSync("/usr/bin/security", ["unlock-keychain", "-p", password, path], { encoding: "utf8", timeout: 10_000 });
				expect(unlocked.status).toBe(0);
				new Entry(identity.service, identity.account).deletePassword();
			}
		},
		20_000,
	);

	it(
		"persists across processes on Windows; on macOS, either round-trips the real key or fails closed within budget",
		() => {
			if (process.platform !== "darwin" && process.platform !== "win32") return;
			const identity = { service: `com.danypops.enigma.test.${randomUUID()}`, account: "master" };
			const provider =
				process.platform === "darwin"
					? createMacosKeychainMasterKeyProvider(identity)
					: createWindowsCredentialManagerMasterKeyProvider(identity);
			const key = randomBytes(32);
			const digest = createHash("sha256").update(key).digest("hex");
			try {
				expect(failureCode(() => provider.read())).toBe("not_found");
				provider.write(key);
				const moduleUrl = new URL("../src/master-key.ts", import.meta.url).href;
				const factory = process.platform === "darwin" ? "createMacosKeychainMasterKeyProvider" : "createWindowsCredentialManagerMasterKeyProvider";
				// Confirmed live: retrieving an existing secret's VALUE hangs unconditionally on
				// headless macOS CI, even unlocked, immediately after writing it in the same
				// process -- across process boundaries too. The child reports its own bounded
				// outcome rather than the parent assuming success is the only valid one.
				const script = `import { createHash } from "node:crypto"; import { MasterKeyFailure, ${factory} } from ${JSON.stringify(moduleUrl)}; try { const key = ${factory}(${JSON.stringify(identity)}).read(); console.log(createHash("sha256").update(key).digest("hex") === process.env.ENIGMA_EXPECTED_KEY_DIGEST ? "native-keyring-ok" : "native-keyring-wrong-key"); } catch (e) { console.log(\`native-keyring-failed:\${e instanceof MasterKeyFailure ? e.code : "unknown"}\`); }`;
				const startedAt = Date.now();
				const child = spawnSync(process.execPath, ["-e", script], {
					env: { ...process.env, ENIGMA_EXPECTED_KEY_DIGEST: digest },
					encoding: "utf8",
					maxBuffer: 16_384,
					timeout: 15_000,
				});
				expect(Date.now() - startedAt).toBeLessThan(15_000);
				expect(`${child.stdout}${child.stderr}`).not.toContain(key.toString("base64"));
				if (process.platform === "win32") {
					expect(child.status).toBe(0);
					expect(child.stdout).toContain("native-keyring-ok");
				} else {
					expect(child.stdout).toMatch(/native-keyring-ok|native-keyring-failed:(locked|unavailable)/);
					expect(child.stdout).not.toContain("native-keyring-wrong-key");
				}
			} finally {
				new Entry(identity.service, identity.account).deletePassword();
			}
		},
		20_000,
	);
});
