import { Entry, findCredentials } from "@napi-rs/keyring";
import { randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	linkSync,
	lstatSync,
	mkdirSync,
	readFileSync,
	readdirSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { createCredentialVault } from "./credential-vault.ts";
import { KEYRING_ACCOUNT, KEYRING_SERVICE } from "./constants.ts";

const MASTER_KEY_BYTES = 32;
const MAX_KEY_FILE_BYTES = 128;
const MAX_MANIFEST_BYTES = 1024;
const MAX_CREDENTIAL_FILES = 1000;
const MAX_CREDENTIAL_FILE_BYTES = 1024 * 1024;
const SECRET_TOOL_PATH = "/usr/bin/secret-tool";
const SECRET_TOOL_MAX_OUTPUT_BYTES = 4096;
const SECRET_TOOL_TIMEOUT_MS = 10_000;
const MACOS_SECURITY_PATH = "/usr/bin/security";

export type MasterKeyProviderKind =
	| "secret-service"
	| "systemd-credential"
	| "macos-keychain"
	| "windows-credential-manager"
	| "file";
export type MasterKeyFailureCode =
	| "not_found"
	| "locked"
	| "unavailable"
	| "denied"
	| "malformed"
	| "unsupported"
	| "conflict"
	| "ambiguous"
	| "corrupt";

export class MasterKeyFailure extends Error {
	constructor(
		public readonly code: MasterKeyFailureCode,
		public readonly provider: MasterKeyProviderKind | "resolver",
	) {
		super(`master key ${provider} failure: ${code}`);
		this.name = "MasterKeyFailure";
	}
}

export interface KeyringIdentity {
	service: string;
	account: string;
}

export interface MasterKeyProvider {
	kind: MasterKeyProviderKind;
	read(): Buffer;
	/** Writes only when absent or already equal. A different existing key is a conflict. */
	write(key: Buffer): void;
}

export interface NativeKeyringBindings {
	findCredentials(service: string, target?: string): Array<{ account: string; password: string }>;
	createEntry(service: string, account: string): { setPassword(password: string): void };
}



export interface MasterKeyManifest {
	version: 1;
	provider: MasterKeyProviderKind;
}

export interface SecretToolResult {
	status: number | null;
	stdout: Buffer;
	stderr: Buffer;
	error?: Error;
}

export type SecretToolRunner = (
	command: string,
	args: string[],
	options: { input?: Buffer },
) => SecretToolResult;

export interface ResolveMasterKeyOptions {
	manifestPath: string;
	filePath: string;
	credentialsDir: string;
	requestedProvider?: string;
	platform?: NodeJS.Platform;
	keyringIdentity?: KeyringIdentity;
	credentialDirectory?: string;
	providers?: Partial<Record<MasterKeyProviderKind, MasterKeyProvider>>;
}

const DEFAULT_KEYRING_IDENTITY: KeyringIdentity = { service: KEYRING_SERVICE, account: KEYRING_ACCOUNT };
const PROVIDER_KINDS = new Set<MasterKeyProviderKind>([
	"secret-service",
	"systemd-credential",
	"macos-keychain",
	"windows-credential-manager",
	"file",
]);
const NATIVE_KEYRING_BINDINGS: NativeKeyringBindings = {
	findCredentials,
	createEntry: (service, account) => new Entry(service, account),
};

function assertMasterKey(key: Buffer, provider: MasterKeyProviderKind | "resolver"): Buffer {
	if (key.length !== MASTER_KEY_BYTES) throw new MasterKeyFailure("malformed", provider);
	return key;
}

function decodeStoredKey(raw: string, provider: MasterKeyProviderKind): Buffer {
	const encoded = raw.endsWith("\n") ? raw.slice(0, -1) : raw;
	if (!/^[A-Za-z0-9+/]{43}=$/.test(encoded)) throw new MasterKeyFailure("malformed", provider);
	const key = Buffer.from(encoded, "base64");
	if (key.toString("base64") !== encoded) throw new MasterKeyFailure("malformed", provider);
	return assertMasterKey(key, provider);
}

function ensurePrivateDirectory(path: string): void {
	mkdirSync(path, { recursive: true, mode: 0o700 });
	chmodSync(path, 0o700);
}

/** Creates a fully-written file without replacing an existing path. */
function atomicCreate(path: string, contents: string): boolean {
	ensurePrivateDirectory(dirname(path));
	const temp = `${path}.${process.pid}.${randomUUID()}.tmp`;
	writeFileSync(temp, contents, { mode: 0o600, flag: "wx" });
	try {
		linkSync(temp, path);
		return true;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
		throw error;
	} finally {
		rmSync(temp, { force: true });
	}
}

function readBoundedPrivateFile(path: string, maxBytes: number, provider: MasterKeyProviderKind | "resolver"): string {
	if (!existsSync(path)) throw new MasterKeyFailure("not_found", provider);
	const metadata = lstatSync(path);
	if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maxBytes) throw new MasterKeyFailure("malformed", provider);
	chmodSync(path, 0o600);
	return readFileSync(path, "utf8");
}

export function createFileMasterKeyProvider(path: string): MasterKeyProvider {
	return {
		kind: "file",
		read(): Buffer {
			return decodeStoredKey(readBoundedPrivateFile(path, MAX_KEY_FILE_BYTES, "file"), "file");
		},
		write(key: Buffer): void {
			assertMasterKey(key, "file");
			if (atomicCreate(path, `${key.toString("base64")}\n`)) return;
			if (!this.read().equals(key)) throw new MasterKeyFailure("conflict", "file");
		},
	};
}

function runSecretTool(command: string, args: string[], options: { input?: Buffer }): SecretToolResult {
	const result = spawnSync(command, args, {
		input: options.input,
		encoding: null,
		maxBuffer: SECRET_TOOL_MAX_OUTPUT_BYTES,
		timeout: SECRET_TOOL_TIMEOUT_MS,
		windowsHide: true,
	});
	return {
		status: result.status,
		stdout: Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout ?? ""),
		stderr: Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr ?? ""),
		error: result.error,
	};
}

function secretToolFailure(result: SecretToolResult, operation: "read" | "write"): MasterKeyFailure {
	if ((result.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") return new MasterKeyFailure("unsupported", "secret-service");
	const stderr = result.stderr.toString("utf8");
	if (stderr.includes("org.freedesktop.Secret.Error.IsLocked") || /\blocked\b/i.test(stderr)) {
		return new MasterKeyFailure("locked", "secret-service");
	}
	if (stderr.includes("org.freedesktop.DBus.Error.AccessDenied") || /\bdenied\b/i.test(stderr)) {
		return new MasterKeyFailure("denied", "secret-service");
	}
	if (operation === "read" && result.status === 1 && result.stderr.length === 0 && result.stdout.length === 0) {
		return new MasterKeyFailure("not_found", "secret-service");
	}
	return new MasterKeyFailure("unavailable", "secret-service");
}

export function createSystemdCredentialMasterKeyProvider(directory: string | undefined): MasterKeyProvider {
	return {
		kind: "systemd-credential",
		read(): Buffer {
			if (!directory) throw new MasterKeyFailure("not_found", "systemd-credential");
			if (!isAbsolute(directory)) throw new MasterKeyFailure("malformed", "systemd-credential");
			if (!existsSync(directory)) throw new MasterKeyFailure("not_found", "systemd-credential");
			const directoryMetadata = lstatSync(directory);
			if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink() || (directoryMetadata.mode & 0o022) !== 0) {
				throw new MasterKeyFailure("denied", "systemd-credential");
			}

			const path = join(directory, "enigma-master-key");
			if (!existsSync(path)) throw new MasterKeyFailure("not_found", "systemd-credential");
			const metadata = lstatSync(path);
			if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_KEY_FILE_BYTES || (metadata.mode & 0o022) !== 0) {
				throw new MasterKeyFailure("malformed", "systemd-credential");
			}
			const raw = readFileSync(path);
			return raw.length === MASTER_KEY_BYTES ? raw : decodeStoredKey(raw.toString("utf8"), "systemd-credential");
		},
		write(): void {
			throw new MasterKeyFailure("unsupported", "systemd-credential");
		},
	};
}

function classifyNativeKeyringError(kind: "windows-credential-manager", error: unknown): MasterKeyFailure {
	const message = error instanceof Error ? error.message.toLowerCase() : "";
	if (message.includes("not a valid utf16") || message.includes("invalid utf")) return new MasterKeyFailure("malformed", kind);
	if (message.includes("item not found") || message.includes("not found")) return new MasterKeyFailure("not_found", kind);
	if (message.includes("interaction") && (message.includes("not allowed") || message.includes("required"))) {
		return new MasterKeyFailure("locked", kind);
	}
	if (message.includes("denied") || message.includes("not permitted") || message.includes("authorization failed")) {
		return new MasterKeyFailure("denied", kind);
	}
	return new MasterKeyFailure("unavailable", kind);
}

/**
 * Confirmed live in GitHub-hosted headless macOS CI: reading a LOCKED
 * keychain hangs indefinitely -- not just via @napi-rs/keyring's native
 * binding, but identically via the `security` CLI itself (a forcibly
 * killed orphan process, confirmed in job logs). There is no session to
 * show the interactive unlock prompt to, and unlike errSecInteractionNotAllowed's
 * documented fast-fail, the underlying call simply blocks. A bounded
 * subprocess (spawnSync's own `timeout`) is the only thing that reliably
 * recovers from this -- an in-process native call has no such backstop
 * and cannot be preempted once it blocks a syscall. Reads therefore go
 * through `security` (bounded); writes stay on the native binding, since
 * they only happen once at first enrollment against a store the caller
 * just set up, and were confirmed fast (~260ms) against a real runner.
 */
function macosSecurityFailure(result: SecretToolResult): MasterKeyFailure {
	if ((result.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") return new MasterKeyFailure("unsupported", "macos-keychain");
	// spawnSync's own timeout killed a hung child (status null, no signal-independent stderr to classify further):
	// this is the locked-and-noninteractive case above. "unavailable" is the honest label -- a timeout is not
	// positive proof of "locked" specifically, only proof that the query couldn't complete in budget.
	if (result.status === null) return new MasterKeyFailure("unavailable", "macos-keychain");
	const stderr = result.stderr.toString("utf8");
	if (result.status === 44 || /could not be found in the keychain/i.test(stderr)) return new MasterKeyFailure("not_found", "macos-keychain");
	if (/interaction.*not allowed/i.test(stderr)) return new MasterKeyFailure("locked", "macos-keychain");
	if (/denied|not permitted|authorization/i.test(stderr)) return new MasterKeyFailure("denied", "macos-keychain");
	return new MasterKeyFailure("unavailable", "macos-keychain");
}

export function createMacosKeychainMasterKeyProvider(
	identity: KeyringIdentity = DEFAULT_KEYRING_IDENTITY,
	bindings: NativeKeyringBindings = NATIVE_KEYRING_BINDINGS,
	runner: SecretToolRunner = runSecretTool,
): MasterKeyProvider {
	const read = (): Buffer => {
		const result = runner(MACOS_SECURITY_PATH, ["find-generic-password", "-a", identity.account, "-s", identity.service, "-w"], {});
		if (result.error || result.status !== 0) throw macosSecurityFailure(result);
		return decodeStoredKey(result.stdout.toString("utf8"), "macos-keychain");
	};

	return {
		kind: "macos-keychain",
		read,
		write(key: Buffer): void {
			assertMasterKey(key, "macos-keychain");
			try {
				const existing = read();
				if (!existing.equals(key)) throw new MasterKeyFailure("conflict", "macos-keychain");
				return;
			} catch (error) {
				if (!(error instanceof MasterKeyFailure) || error.code !== "not_found") throw error;
			}
			try {
				bindings.createEntry(identity.service, identity.account).setPassword(key.toString("base64"));
			} catch (error) {
				// Native write failures still classify against message text (no `security` CLI involved here).
				const message = error instanceof Error ? error.message.toLowerCase() : "";
				if (message.includes("denied") || message.includes("not permitted") || message.includes("authorization failed")) {
					throw new MasterKeyFailure("denied", "macos-keychain");
				}
				throw new MasterKeyFailure("unavailable", "macos-keychain");
			}
			if (!read().equals(key)) throw new MasterKeyFailure("corrupt", "macos-keychain");
		},
	};
}

function createNativeKeyringMasterKeyProvider(
	kind: "windows-credential-manager",
	identity: KeyringIdentity,
	bindings: NativeKeyringBindings,
): MasterKeyProvider {
	const read = (): Buffer => {
		let credentials: Array<{ account: string; password: string }>;
		try {
			credentials = bindings.findCredentials(identity.service);
		} catch (error) {
			throw classifyNativeKeyringError(kind, error);
		}
		const matches = credentials.filter((credential) => credential.account === identity.account);
		if (matches.length > 1) throw new MasterKeyFailure("ambiguous", kind);
		if (matches.length === 0) throw new MasterKeyFailure("not_found", kind);
		return decodeStoredKey(matches[0]!.password, kind);
	};

	return {
		kind,
		read,
		write(key: Buffer): void {
			assertMasterKey(key, kind);
			try {
				const existing = read();
				if (!existing.equals(key)) throw new MasterKeyFailure("conflict", kind);
				return;
			} catch (error) {
				if (!(error instanceof MasterKeyFailure) || error.code !== "not_found") throw error;
			}
			try {
				bindings.createEntry(identity.service, identity.account).setPassword(key.toString("base64"));
			} catch (error) {
				throw classifyNativeKeyringError(kind, error);
			}
			if (!read().equals(key)) throw new MasterKeyFailure("corrupt", kind);
		},
	};
}

/**
 * Windows Credential Manager generic credentials are always scoped to the
 * current logon session (CredReadW reads "the credential set associated
 * with the logon session of the current token"); this never sets DPAPI's
 * CRYPTPROTECT_LOCAL_MACHINE, which would let any local user decrypt the
 * key. The underlying store does not expose the Windows `persistence`
 * attribute through this binding, so new credentials get its default of
 * Enterprise persistence rather than Local -- see README for the roaming
 * caveat that follows from that.
 */
export function createWindowsCredentialManagerMasterKeyProvider(
	identity: KeyringIdentity = DEFAULT_KEYRING_IDENTITY,
	bindings: NativeKeyringBindings = NATIVE_KEYRING_BINDINGS,
): MasterKeyProvider {
	return createNativeKeyringMasterKeyProvider("windows-credential-manager", identity, bindings);
}

export function createSecretServiceMasterKeyProvider(
	identity: KeyringIdentity = DEFAULT_KEYRING_IDENTITY,
	runner: SecretToolRunner = runSecretTool,
): MasterKeyProvider {
	const lookupArgs = ["lookup", "service", identity.service, "username", identity.account, "enigma-purpose", "master-key-v1"];
	return {
		kind: "secret-service",
		read(): Buffer {
			const result = runner(SECRET_TOOL_PATH, lookupArgs, {});
			if (result.error || result.status !== 0) throw secretToolFailure(result, "read");
			return decodeStoredKey(result.stdout.toString("utf8"), "secret-service");
		},
		write(key: Buffer): void {
			assertMasterKey(key, "secret-service");
			try {
				const existing = this.read();
				if (!existing.equals(key)) throw new MasterKeyFailure("conflict", "secret-service");
				return;
			} catch (error) {
				if (!(error instanceof MasterKeyFailure) || error.code !== "not_found") throw error;
			}

			const result = runner(
				SECRET_TOOL_PATH,
				["store", "--label=Enigma master key", "service", identity.service, "username", identity.account, "enigma-purpose", "master-key-v1"],
				{ input: Buffer.from(`${key.toString("base64")}\n`) },
			);
			if (result.error || result.status !== 0) throw secretToolFailure(result, "write");
			if (!this.read().equals(key)) throw new MasterKeyFailure("corrupt", "secret-service");
		},
	};
}

export function readMasterKeyManifest(path: string): MasterKeyManifest | undefined {
	if (!existsSync(path)) return undefined;
	const raw = readBoundedPrivateFile(path, MAX_MANIFEST_BYTES, "resolver");
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		throw new MasterKeyFailure("malformed", "resolver");
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new MasterKeyFailure("malformed", "resolver");
	const record = parsed as Record<string, unknown>;
	const keys = Object.keys(record).sort();
	if (keys.length !== 2 || keys[0] !== "provider" || keys[1] !== "version") throw new MasterKeyFailure("malformed", "resolver");
	if (record.version !== 1 || typeof record.provider !== "string" || !PROVIDER_KINDS.has(record.provider as MasterKeyProviderKind)) {
		throw new MasterKeyFailure("malformed", "resolver");
	}
	return { version: 1, provider: record.provider as MasterKeyProviderKind };
}

function writeMasterKeyManifest(path: string, manifest: MasterKeyManifest): void {
	const contents = `${JSON.stringify(manifest)}\n`;
	if (atomicCreate(path, contents)) return;
	const existing = readMasterKeyManifest(path);
	if (!existing || existing.version !== manifest.version || existing.provider !== manifest.provider) {
		throw new MasterKeyFailure("conflict", "resolver");
	}
}

function requestedProviderKind(value: string | undefined): MasterKeyProviderKind | undefined {
	if (value === undefined) return undefined;
	if (!PROVIDER_KINDS.has(value as MasterKeyProviderKind)) throw new MasterKeyFailure("unsupported", "resolver");
	return value as MasterKeyProviderKind;
}

function defaultProviderKind(platform: NodeJS.Platform): MasterKeyProviderKind {
	if (platform === "linux") return "secret-service";
	if (platform === "darwin") return "macos-keychain";
	if (platform === "win32") return "windows-credential-manager";
	throw new MasterKeyFailure("unsupported", "resolver");
}

function providerFor(
	providers: Partial<Record<MasterKeyProviderKind, MasterKeyProvider>>,
	kind: MasterKeyProviderKind,
): MasterKeyProvider {
	const provider = providers[kind];
	if (!provider || provider.kind !== kind) throw new MasterKeyFailure("unsupported", kind);
	return provider;
}

function readLegacyNativeKeyring(identity: KeyringIdentity): Buffer | undefined {
	try {
		const encoded = new Entry(identity.service, identity.account).getPassword();
		return encoded ? decodeStoredKey(encoded, "secret-service") : undefined;
	} catch {
		return undefined;
	}
}

function credentialBackends(dir: string): string[] {
	if (!existsSync(dir)) return [];
	const names = readdirSync(dir)
		.filter((name) => name.endsWith(".json"))
		.sort();
	if (names.length > MAX_CREDENTIAL_FILES) throw new MasterKeyFailure("corrupt", "resolver");
	for (const name of names) {
		const metadata = lstatSync(join(dir, name));
		if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_CREDENTIAL_FILE_BYTES) {
			throw new MasterKeyFailure("corrupt", "resolver");
		}
	}
	return names.map((name) => name.slice(0, -".json".length));
}

function isStoredCredential(value: unknown): boolean {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const token = value as Record<string, unknown>;
	if (typeof token.accessToken !== "string" || token.accessToken.length === 0) return false;
	for (const field of ["refreshToken", "expiresAt", "scope"] as const) {
		if (token[field] !== undefined && typeof token[field] !== "string") return false;
	}
	if (token.extra !== undefined) {
		if (!token.extra || typeof token.extra !== "object" || Array.isArray(token.extra)) return false;
		if (Object.values(token.extra as Record<string, unknown>).some((entry) => typeof entry !== "string")) return false;
	}
	return true;
}

function keyDecryptsEveryCredential(dir: string, backends: string[], key: Buffer): boolean {
	try {
		const vault = createCredentialVault({ dir, masterKey: key });
		return backends.every((backend) => isStoredCredential(vault.get(backend)));
	} catch {
		return false;
	}
}

function collectUniqueCandidates(readers: Array<() => Buffer | undefined>): Buffer[] {
	const candidates: Buffer[] = [];
	for (const read of readers) {
		try {
			const candidate = read();
			if (!candidate) continue;
			assertMasterKey(candidate, "resolver");
			if (!candidates.some((existing) => existing.equals(candidate))) candidates.push(Buffer.from(candidate));
		} catch {
			// Candidate probing is read-only. Resolution below still requires one key
			// to authenticate every existing credential before any metadata is written.
		}
	}
	return candidates;
}

export function selectUniqueLegacyKey(candidates: Buffer[], verifies: (key: Buffer) => boolean): Buffer {
	const valid = candidates.filter(verifies);
	if (valid.length === 0) throw new MasterKeyFailure("corrupt", "resolver");
	if (valid.length > 1) throw new MasterKeyFailure("ambiguous", "resolver");
	return valid[0]!;
}

function provisionProvider(provider: MasterKeyProvider, key: Buffer): Buffer {
	try {
		const existing = assertMasterKey(provider.read(), provider.kind);
		if (!existing.equals(key)) throw new MasterKeyFailure("conflict", provider.kind);
		return existing;
	} catch (error) {
		if (!(error instanceof MasterKeyFailure) || error.code !== "not_found") throw error;
	}
	provider.write(key);
	const persisted = assertMasterKey(provider.read(), provider.kind);
	if (!persisted.equals(key)) throw new MasterKeyFailure("corrupt", provider.kind);
	return persisted;
}

interface UnpinnedResolution {
	options: ResolveMasterKeyOptions;
	identity: KeyringIdentity;
	providers: Partial<Record<MasterKeyProviderKind, MasterKeyProvider>>;
	targetKind: MasterKeyProviderKind;
	target: MasterKeyProvider;
}

function pinResolvedKey(context: UnpinnedResolution, key: Buffer): Buffer {
	const persisted = provisionProvider(context.target, key);
	writeMasterKeyManifest(context.options.manifestPath, { version: 1, provider: context.targetKind });
	return persisted;
}

function resolveLegacyStore(context: UnpinnedResolution, backends: string[]): Buffer {
	const readers: Array<() => Buffer | undefined> = Object.values(context.providers).map((provider) => () => provider?.read());
	if (!context.options.providers) readers.push(() => readLegacyNativeKeyring(context.identity));
	const legacyKey = selectUniqueLegacyKey(collectUniqueCandidates(readers), (key) =>
		keyDecryptsEveryCredential(context.options.credentialsDir, backends, key),
	);
	return pinResolvedKey(context, legacyKey);
}

function resolveFreshStore(context: UnpinnedResolution): Buffer {
	try {
		const existing = assertMasterKey(context.target.read(), context.targetKind);
		writeMasterKeyManifest(context.options.manifestPath, { version: 1, provider: context.targetKind });
		return existing;
	} catch (error) {
		if (!(error instanceof MasterKeyFailure) || error.code !== "not_found") throw error;
		return pinResolvedKey(context, randomBytes(MASTER_KEY_BYTES));
	}
}

export function resolveMasterKey(options: ResolveMasterKeyOptions): Buffer {
	const identity = options.keyringIdentity ?? DEFAULT_KEYRING_IDENTITY;
	const requested = requestedProviderKind(options.requestedProvider);
	const platform = options.platform ?? process.platform;
	let providers = options.providers;
	if (!providers) {
		providers = { file: createFileMasterKeyProvider(options.filePath) };
		if (platform === "linux") {
			providers["secret-service"] = createSecretServiceMasterKeyProvider(identity);
			providers["systemd-credential"] = createSystemdCredentialMasterKeyProvider(options.credentialDirectory);
		} else if (platform === "darwin") {
			providers["macos-keychain"] = createMacosKeychainMasterKeyProvider(identity);
		} else if (platform === "win32") {
			providers["windows-credential-manager"] = createWindowsCredentialManagerMasterKeyProvider(identity);
		}
	}

	const manifest = readMasterKeyManifest(options.manifestPath);
	if (manifest) {
		if (requested && requested !== manifest.provider) throw new MasterKeyFailure("conflict", "resolver");
		return assertMasterKey(providerFor(providers, manifest.provider).read(), manifest.provider);
	}

	const targetKind = requested ?? defaultProviderKind(platform);
	const context = { options, identity, providers, targetKind, target: providerFor(providers, targetKind) };
	const backends = credentialBackends(options.credentialsDir);
	return backends.length > 0 ? resolveLegacyStore(context, backends) : resolveFreshStore(context);
}

export interface MasterKeyPaths {
	credentialsDir: string;
	masterKeyFile: string;
	masterKeyProviderFile: string;
}

export function resolveConfiguredMasterKey(
	paths: MasterKeyPaths,
	env: Record<string, string | undefined> = process.env,
): Buffer {
	return resolveMasterKey({
		credentialsDir: paths.credentialsDir,
		filePath: paths.masterKeyFile,
		manifestPath: paths.masterKeyProviderFile,
		requestedProvider: env.ENIGMA_MASTER_KEY_PROVIDER,
		keyringIdentity: resolveKeyringIdentityFromEnv(env),
		credentialDirectory: env.CREDENTIALS_DIRECTORY,
	});
}

export function resolveKeyringIdentityFromEnv(env: Record<string, string | undefined> = process.env): KeyringIdentity | undefined {
	if (!env.ENIGMA_KEYRING_SERVICE && !env.ENIGMA_KEYRING_ACCOUNT) return undefined;
	return { service: env.ENIGMA_KEYRING_SERVICE ?? KEYRING_SERVICE, account: env.ENIGMA_KEYRING_ACCOUNT ?? KEYRING_ACCOUNT };
}
