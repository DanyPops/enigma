import { describe, expect, it } from "bun:test";
import { randomBytes, randomUUID } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { createCredentialVault } from "../src/credential-vault.ts";
import {
	MasterKeyFailure,
	createFileMasterKeyProvider,
	createSecretServiceMasterKeyProvider,
	createSystemdCredentialMasterKeyProvider,
	readMasterKeyManifest,
	resolveMasterKey,
	selectUniqueLegacyKey,
	type MasterKeyProvider,
} from "../src/master-key.ts";

function tmpDir(): string {
	return mkdtempSync(join(tmpdir(), "enigma-master-key-"));
}

function fakeProvider(kind: MasterKeyProvider["kind"], initial?: Buffer): MasterKeyProvider & { reads: number; writes: number } {
	let stored = initial;
	return {
		kind,
		reads: 0,
		writes: 0,
		read(): Buffer {
			this.reads++;
			if (!stored) throw new MasterKeyFailure("not_found", kind);
			return Buffer.from(stored);
		},
		write(key: Buffer): void {
			this.writes++;
			if (stored && !stored.equals(key)) throw new MasterKeyFailure("conflict", kind);
			stored = Buffer.from(key);
		},
	};
}

function paths(dir: string): { manifestPath: string; filePath: string; credentialsDir: string } {
	return {
		manifestPath: join(dir, "master-key.json"),
		filePath: join(dir, ".master"),
		credentialsDir: join(dir, "credentials"),
	};
}

describe("file master-key provider", () => {
	it("creates an owner-only key without overwriting a different existing key", () => {
		const dir = tmpDir();
		try {
			const path = join(dir, ".master");
			const provider = createFileMasterKeyProvider(path);
			const key = randomBytes(32);
			provider.write(key);
			expect(provider.read()).toEqual(key);
			// Windows has no POSIX permission bits; ownership isolation there comes
			// from the per-user profile ACL on the containing directory instead.
			if (process.platform !== "win32") expect((statSync(path).mode & 0o777).toString(8)).toBe("600");
			expect(() => provider.write(randomBytes(32))).toThrow(MasterKeyFailure);
			expect(provider.read()).toEqual(key);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("rejects malformed key material", () => {
		const dir = tmpDir();
		try {
			const path = join(dir, ".master");
			writeFileSync(path, "not-a-32-byte-key\n", { mode: 0o600 });
			expect(() => createFileMasterKeyProvider(path).read()).toThrow(MasterKeyFailure);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("master-key resolution", () => {
	it("defaults a fresh Linux store to Secret Service and records only provider metadata", () => {
		const dir = tmpDir();
		try {
			const extra = paths(dir);
			const secretService = fakeProvider("secret-service");
			const file = fakeProvider("file");
			const key = resolveMasterKey({ ...extra, platform: "linux", providers: { "secret-service": secretService, file } });
			expect(key).toHaveLength(32);
			expect(secretService.writes).toBe(1);
			expect(file.reads + file.writes).toBe(0);
			expect(readMasterKeyManifest(extra.manifestPath)).toEqual({ version: 1, provider: "secret-service" });
			expect(readFileSync(extra.manifestPath, "utf8")).not.toContain(key.toString("base64"));
			if (process.platform !== "win32") expect((statSync(extra.manifestPath).mode & 0o777).toString(8)).toBe("600");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("uses the file provider only when explicitly requested", () => {
		const dir = tmpDir();
		try {
			const extra = paths(dir);
			const secretService = fakeProvider("secret-service");
			const file = fakeProvider("file");
			resolveMasterKey({ ...extra, platform: "linux", requestedProvider: "file", providers: { "secret-service": secretService, file } });
			expect(file.writes).toBe(1);
			expect(secretService.reads + secretService.writes).toBe(0);
			expect(readMasterKeyManifest(extra.manifestPath)?.provider).toBe("file");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("pins a pre-provisioned systemd credential and never tries to create it", () => {
		const dir = tmpDir();
		try {
			const extra = paths(dir);
			const systemdCredential = fakeProvider("systemd-credential", randomBytes(32));
			const file = fakeProvider("file", randomBytes(32));
			resolveMasterKey({
				...extra,
				platform: "linux",
				requestedProvider: "systemd-credential",
				providers: { "systemd-credential": systemdCredential, file },
			});
			expect(systemdCredential.writes).toBe(0);
			expect(file.reads + file.writes).toBe(0);
			expect(readMasterKeyManifest(extra.manifestPath)?.provider).toBe("systemd-credential");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("never consults another provider when the pinned provider is unavailable", () => {
		const dir = tmpDir();
		try {
			const extra = paths(dir);
			mkdirSync(dir, { recursive: true });
			writeFileSync(extra.manifestPath, `${JSON.stringify({ version: 1, provider: "secret-service" })}\n`, { mode: 0o600 });
			const secretService = fakeProvider("secret-service");
			secretService.read = () => {
				secretService.reads++;
				throw new MasterKeyFailure("unavailable", "secret-service");
			};
			const file = fakeProvider("file", randomBytes(32));
			expect(() => resolveMasterKey({ ...extra, platform: "linux", providers: { "secret-service": secretService, file } })).toThrow(
				MasterKeyFailure,
			);
			expect(secretService.reads).toBe(1);
			expect(file.reads + file.writes).toBe(0);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("rejects a provider override that conflicts with the pinned manifest", () => {
		const dir = tmpDir();
		try {
			const extra = paths(dir);
			writeFileSync(extra.manifestPath, `${JSON.stringify({ version: 1, provider: "secret-service" })}\n`, { mode: 0o600 });
			expect(() =>
				resolveMasterKey({
					...extra,
					platform: "linux",
					requestedProvider: "file",
					providers: { "secret-service": fakeProvider("secret-service", randomBytes(32)), file: fakeProvider("file", randomBytes(32)) },
				}),
			).toThrow(MasterKeyFailure);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("rejects malformed or unknown provider manifests", () => {
		const dir = tmpDir();
		try {
			const manifestPath = join(dir, "master-key.json");
			writeFileSync(manifestPath, `${JSON.stringify({ version: 1, provider: "anything", secret: "forbidden" })}\n`, { mode: 0o600 });
			expect(() => readMasterKeyManifest(manifestPath)).toThrow(MasterKeyFailure);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("legacy provider migration", () => {
	it("pins the only key that decrypts every existing credential", () => {
		const dir = tmpDir();
		try {
			const extra = paths(dir);
			const valid = randomBytes(32);
			createCredentialVault({ dir: extra.credentialsDir, masterKey: valid }).save("github", { accessToken: "fixture-token-a" });
			createCredentialVault({ dir: extra.credentialsDir, masterKey: valid }).save("gitlab", { accessToken: "fixture-token-b" });
			const secretService = fakeProvider("secret-service", valid);
			const file = fakeProvider("file", randomBytes(32));
			const resolved = resolveMasterKey({ ...extra, platform: "linux", providers: { "secret-service": secretService, file } });
			expect(resolved).toEqual(valid);
			expect(readMasterKeyManifest(extra.manifestPath)?.provider).toBe("secret-service");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("migrates a uniquely valid legacy file key into the secure default without rewriting credentials", () => {
		const dir = tmpDir();
		try {
			const extra = paths(dir);
			const valid = randomBytes(32);
			createCredentialVault({ dir: extra.credentialsDir, masterKey: valid }).save("github", { accessToken: "fixture-token" });
			const before = readFileSync(join(extra.credentialsDir, "github.json"), "utf8");
			const secretService = fakeProvider("secret-service");
			const file = fakeProvider("file", valid);
			const resolved = resolveMasterKey({ ...extra, platform: "linux", providers: { "secret-service": secretService, file } });
			expect(resolved).toEqual(valid);
			expect(secretService.writes).toBe(1);
			expect(readFileSync(join(extra.credentialsDir, "github.json"), "utf8")).toBe(before);
			expect(readMasterKeyManifest(extra.manifestPath)?.provider).toBe("secret-service");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("rejects multiple independently valid candidates as ambiguous", () => {
		const first = randomBytes(32);
		const second = randomBytes(32);
		expect(() => selectUniqueLegacyKey([first, second], () => true)).toThrow(MasterKeyFailure);
		try {
			selectUniqueLegacyKey([first, second], () => true);
		} catch (error) {
			expect(error).toBeInstanceOf(MasterKeyFailure);
			expect((error as MasterKeyFailure).code).toBe("ambiguous");
		}
	});

	it("fails closed when no candidate decrypts all records", () => {
		const dir = tmpDir();
		try {
			const extra = paths(dir);
			const first = randomBytes(32);
			const second = randomBytes(32);
			createCredentialVault({ dir: extra.credentialsDir, masterKey: first }).save("github", { accessToken: "fixture-token-a" });
			createCredentialVault({ dir: extra.credentialsDir, masterKey: second }).save("gitlab", { accessToken: "fixture-token-b" });
			expect(() =>
				resolveMasterKey({
					...extra,
					platform: "linux",
					providers: { "secret-service": fakeProvider("secret-service", first), file: fakeProvider("file", second) },
				}),
			).toThrow(MasterKeyFailure);
			expect(() => statSync(extra.manifestPath)).toThrow();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("fails closed when an existing credential is corrupt", () => {
		const dir = tmpDir();
		try {
			const extra = paths(dir);
			mkdirSync(extra.credentialsDir, { recursive: true, mode: 0o700 });
			writeFileSync(join(extra.credentialsDir, "github.json"), "{corrupt}\n", { mode: 0o600 });
			expect(() =>
				resolveMasterKey({
					...extra,
					platform: "linux",
					providers: { "secret-service": fakeProvider("secret-service", randomBytes(32)), file: fakeProvider("file", randomBytes(32)) },
				}),
			).toThrow(MasterKeyFailure);
			expect(() => statSync(extra.manifestPath)).toThrow();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

// systemd credentials are a Linux-only OS mechanism; the writable/symlink
// checks below rely on POSIX mode bits that Windows and macOS don't share.
describe.skipIf(process.platform !== "linux")("systemd credential master-key provider", () => {
	it("reads one raw 32-byte credential from an absolute systemd directory", () => {
		const dir = tmpDir();
		try {
			const key = randomBytes(32);
			writeFileSync(join(dir, "enigma-master-key"), key, { mode: 0o400 });
			const provider = createSystemdCredentialMasterKeyProvider(dir);
			expect(provider.read()).toEqual(key);
			expect(() => provider.write(randomBytes(32))).toThrow(MasterKeyFailure);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("rejects absent, relative, oversized, writable, and symlinked credential paths", () => {
		expect(() => createSystemdCredentialMasterKeyProvider(undefined).read()).toThrow(MasterKeyFailure);
		expect(() => createSystemdCredentialMasterKeyProvider("relative/path").read()).toThrow(MasterKeyFailure);

		const dir = tmpDir();
		try {
			const path = join(dir, "enigma-master-key");
			writeFileSync(path, randomBytes(33), { mode: 0o400 });
			expect(() => createSystemdCredentialMasterKeyProvider(dir).read()).toThrow(MasterKeyFailure);
			chmodSync(path, 0o600);
			writeFileSync(path, randomBytes(32), { mode: 0o622 });
			chmodSync(path, 0o622);
			expect(() => createSystemdCredentialMasterKeyProvider(dir).read()).toThrow(MasterKeyFailure);
			rmSync(path);
			const target = join(dir, "target");
			writeFileSync(target, randomBytes(32), { mode: 0o400 });
			symlinkSync(target, path);
			expect(() => createSystemdCredentialMasterKeyProvider(dir).read()).toThrow(MasterKeyFailure);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("reads a credential delivered by a real transient user unit when supported", () => {
		const probe = spawnSync("systemd-run", ["--user", "--pipe", "--wait", "--collect", "true"], { maxBuffer: 4096, timeout: 10_000 });
		if (probe.error || probe.status !== 0) return;

		const dir = tmpDir();
		try {
			const source = join(dir, "source-key");
			const key = randomBytes(32);
			writeFileSync(source, key, { mode: 0o600 });
			const moduleUrl = new URL("../src/master-key.ts", import.meta.url).href;
			const script = `import { createSystemdCredentialMasterKeyProvider } from ${JSON.stringify(moduleUrl)}; const key = createSystemdCredentialMasterKeyProvider(process.env.CREDENTIALS_DIRECTORY).read(); if (key.length !== 32) process.exit(2); console.log("systemd-credential-ok")`;
			const result = spawnSync(
				"systemd-run",
				["--user", "--pipe", "--wait", "--collect", `--property=LoadCredential=enigma-master-key:${source}`, "bun", "-e", script],
				{ maxBuffer: 16_384, timeout: 15_000 },
			);
			expect(result.status).toBe(0);
			expect(result.stdout.toString("utf8")).toContain("systemd-credential-ok");
			expect(result.stdout.toString("utf8")).not.toContain(key.toString("base64"));
			expect(result.stderr.toString("utf8")).not.toContain(key.toString("base64"));
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("Secret Service master-key provider", () => {
	it("passes secret material through stdin rather than argv", () => {
		const calls: Array<{ args: string[]; input?: Buffer }> = [];
		const key = randomBytes(32);
		let stored = false;
		const provider = createSecretServiceMasterKeyProvider(
			{ service: "test.service", account: "master" },
			(command, args, options) => {
				calls.push({ args: [command, ...args], input: options.input });
				if (args[0] === "store") {
					stored = true;
					return { status: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
				}
				return stored
					? { status: 0, stdout: Buffer.from(`${key.toString("base64")}\n`), stderr: Buffer.alloc(0) }
					: { status: 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
			},
		);
		provider.write(key);
		const storeCall = calls.find((call) => call.args.includes("store"));
		expect(storeCall?.args.join(" ")).not.toContain(key.toString("base64"));
		expect(storeCall?.input?.toString("utf8")).toBe(`${key.toString("base64")}\n`);
	});

	it("classifies a locked collection without exposing provider stderr", () => {
		const provider = createSecretServiceMasterKeyProvider(
			{ service: "test.service", account: "master" },
			() => ({ status: 1, stdout: Buffer.alloc(0), stderr: Buffer.from("org.freedesktop.Secret.Error.IsLocked private-detail") }),
		);
		try {
			provider.read();
			expect.unreachable();
		} catch (error) {
			expect(error).toBeInstanceOf(MasterKeyFailure);
			expect((error as MasterKeyFailure).code).toBe("locked");
			expect((error as Error).message).not.toContain("private-detail");
		}
	});

	it("persists one key across two real Secret Service client processes when available", () => {
		const identity = { service: `danypops.enigma.test.${randomUUID()}`, account: "master" };
		const probe = spawnSync("/usr/bin/secret-tool", ["lookup", "service", identity.service, "username", identity.account], { maxBuffer: 4096 });
		if (probe.error || probe.status !== 1 || probe.stderr.length !== 0) return;
		const first = createSecretServiceMasterKeyProvider(identity);
		const second = createSecretServiceMasterKeyProvider(identity);
		const key = randomBytes(32);
		try {
			first.write(key);
			expect(second.read()).toEqual(key);
		} finally {
			spawnSync("/usr/bin/secret-tool", ["clear", "service", identity.service, "username", identity.account], { maxBuffer: 4096 });
		}
	});
});
