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
	type KeyringIdentity,
	type NativeKeyringBindings,
} from "../src/master-key.ts";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
	it("persists one key through native bindings without placing it in probe arguments", () => {
		const bindings = memoryBindings();
		const identity = { service: "test.enigma", account: "master" };
		const probes: KeyringIdentity[] = [];
		const probe = (candidate: KeyringIdentity) => {
			probes.push(candidate);
			return "not_found" as const;
		};
		const first = createMacosKeychainMasterKeyProvider(identity, bindings, probe);
		const second = createMacosKeychainMasterKeyProvider(identity, bindings, probe);
		const key = randomBytes(32);
		first.write(key);
		expect(second.read()).toEqual(key);
		expect(bindings.writes).toBe(1);
		expect(JSON.stringify(probes)).not.toContain(key.toString("base64"));
	});

	it("distinguishes missing, locked, denied, and unavailable state without writing", () => {
		for (const state of ["not_found", "locked", "denied", "unavailable"] as const) {
			const bindings = memoryBindings();
			const provider = createMacosKeychainMasterKeyProvider({ service: "test.enigma", account: "master" }, bindings, () => state);
			expect(failureCode(() => provider.read())).toBe(state);
			if (state !== "not_found") {
				expect(failureCode(() => provider.write(randomBytes(32)))).toBe(state);
				expect(bindings.writes).toBe(0);
			}
		}
	});

	it("rejects duplicate and malformed native records", () => {
		const duplicate: NativeKeyringBindings = {
			findCredentials: () => [
				{ account: "master", password: randomBytes(32).toString("base64") },
				{ account: "master", password: randomBytes(32).toString("base64") },
			],
			createEntry: () => ({ setPassword: () => undefined }),
		};
		const malformed: NativeKeyringBindings = {
			findCredentials: () => [{ account: "master", password: "not-a-key" }],
			createEntry: () => ({ setPassword: () => undefined }),
		};
		expect(failureCode(() => createMacosKeychainMasterKeyProvider(undefined, duplicate, () => "not_found").read())).toBe("ambiguous");
		expect(failureCode(() => createMacosKeychainMasterKeyProvider(undefined, malformed, () => "not_found").read())).toBe("malformed");
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
				const bindings = memoryBindings();
				const provider =
					platform === "darwin"
						? createMacosKeychainMasterKeyProvider(undefined, bindings, () => "not_found")
						: createWindowsCredentialManagerMasterKeyProvider(undefined, bindings);
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
	it("reports a locked login keychain distinctly on an isolated macOS CI runner", () => {
		if (process.platform !== "darwin" || process.env.ENIGMA_TEST_LOCK_DEFAULT_KEYCHAIN !== "1") return;
		const identity = { service: `com.danypops.enigma.test.${randomUUID()}`, account: "master" };
		const provider = createMacosKeychainMasterKeyProvider(identity);
		const key = randomBytes(32);
		const defaultKeychain = spawnSync("/usr/bin/security", ["default-keychain", "-d", "user"], { encoding: "utf8", timeout: 10_000 });
		expect(defaultKeychain.status).toBe(0);
		const path = defaultKeychain.stdout.trim().replace(/^"|"$/g, "");
		provider.write(key);
		try {
			const locked = spawnSync("/usr/bin/security", ["lock-keychain", path], { encoding: "utf8", timeout: 10_000 });
			expect(locked.status).toBe(0);
			expect(failureCode(() => provider.read())).toBe("locked");
		} finally {
			const unlocked = spawnSync("/usr/bin/security", ["unlock-keychain", "-p", "actions", path], { encoding: "utf8", timeout: 10_000 });
			expect(unlocked.status).toBe(0);
			new Entry(identity.service, identity.account).deletePassword();
		}
	});

	it("persists across processes and reports a distinct missing item on macOS or Windows", () => {
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
			const script = `import { createHash } from "node:crypto"; import { ${factory} } from ${JSON.stringify(moduleUrl)}; const key = ${factory}(${JSON.stringify(identity)}).read(); if (createHash("sha256").update(key).digest("hex") !== process.env.ENIGMA_EXPECTED_KEY_DIGEST) process.exit(2); console.log("native-keyring-ok")`;
			const child = spawnSync(process.execPath, ["-e", script], {
				env: { ...process.env, ENIGMA_EXPECTED_KEY_DIGEST: digest },
				encoding: "utf8",
				maxBuffer: 16_384,
				timeout: 15_000,
			});
			expect(child.status).toBe(0);
			expect(child.stdout).toContain("native-keyring-ok");
			expect(`${child.stdout}${child.stderr}`).not.toContain(key.toString("base64"));
		} finally {
			new Entry(identity.service, identity.account).deletePassword();
		}
	});
});
