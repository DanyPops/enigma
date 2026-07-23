/**
 * Master key for encrypting credentials at rest. Two paths, tried in
 * order — the key hierarchy itself is not a secret worth hiding, so this
 * is documented plainly rather than made to look more mysterious than it
 * is:
 *
 *  (a) OS keyring (primary). Real native keychain — Secret Service/D-Bus
 *      on Linux, Keychain on macOS, Credential Manager on Windows — via
 *      @napi-rs/keyring, the actively maintained NAPI binding (node-keytar,
 *      the older common choice, was last published 2022-02-17 and is
 *      effectively abandoned). No user prompt; generated lazily on first
 *      use.
 *  (b) File-based key (automatic fallback). For headless machines or any
 *      environment where no keyring backend is reachable. 0600 file under
 *      the caller-supplied path, generated on first boot.
 *
 * A passphrase-prompted third option is explicitly out of scope unless
 * later requested — it doesn't fit a systemd-supervised, non-interactive
 * process.
 */
import { Entry } from "@napi-rs/keyring";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { KEYRING_ACCOUNT, KEYRING_SERVICE } from "./constants.ts";

const MASTER_KEY_BYTES = 32;

export interface KeyringIdentity {
	service: string;
	account: string;
}

const DEFAULT_KEYRING_IDENTITY: KeyringIdentity = { service: KEYRING_SERVICE, account: KEYRING_ACCOUNT };

/**
 * Exported directly so tests can exercise the keyring path in isolation
 * without going through the full fallback chain. `identity` defaults to
 * the real production entry name; tests override it to a unique
 * per-invocation name so concurrent test files (or a real pre-existing
 * entry on the developer's machine) can never collide with each other —
 * a real cross-test collision was caught this way during development,
 * not a hypothetical concern.
 */
export function getOrCreateMasterKeyFromKeyring(identity: KeyringIdentity = DEFAULT_KEYRING_IDENTITY): Buffer | undefined {
	// Escape hatch for tests only — under a fully replaced (not merged) subprocess
	// environment (no DBUS_SESSION_BUS_ADDRESS, an overridden XDG_RUNTIME_DIR), the
	// real Secret Service session can't be discovered consistently, so the keyring
	// backend silently falls back to a non-persistent, per-invocation collection
	// — confirmed directly: two processes requesting the identical identity
	// resolved to two different keys. Production never sets this; only test
	// harnesses that need a deterministic, isolated master key do.
	if (process.env.ENIGMA_DISABLE_KEYRING === "1") return undefined;
	try {
		const entry = new Entry(identity.service, identity.account);
		const existing = entry.getPassword();
		if (existing) return Buffer.from(existing, "base64");

		const generated = randomBytes(MASTER_KEY_BYTES);
		entry.setPassword(generated.toString("base64"));
		return generated;
	} catch {
		// Any failure — no keyring daemon reachable, unsupported platform, permission
		// denied — falls through to the file-based path rather than propagating.
		return undefined;
	}
}

/** Exported directly so tests can exercise the file fallback deterministically, independent of whether a real keyring is available on the test machine. */
export function getOrCreateMasterKeyFromFile(path: string): Buffer {
	if (existsSync(path)) {
		chmodSync(path, 0o600);
		const raw = readFileSync(path, "utf8").trim();
		const key = Buffer.from(raw, "base64");
		if (key.length !== MASTER_KEY_BYTES) {
			throw new Error(`enigma master key file at ${path} does not decode to ${MASTER_KEY_BYTES} bytes — refusing to use a malformed key`);
		}
		return key;
	}
	const generated = randomBytes(MASTER_KEY_BYTES);
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const temp = `${path}.${process.pid}.tmp`;
	writeFileSync(temp, `${generated.toString("base64")}\n`, { mode: 0o600 });
	renameSync(temp, path);
	return generated;
}

/** Resolves the master key via the keyring first, the file fallback second. Never prompts. */
export function getOrCreateMasterKey(fileFallbackPath: string, keyringIdentity?: KeyringIdentity): Buffer {
	return getOrCreateMasterKeyFromKeyring(keyringIdentity) ?? getOrCreateMasterKeyFromFile(fileFallbackPath);
}

/**
 * Reads an optional keyring-identity override from the environment.
 * Production never sets these — the real service/account names apply.
 * Tests that spawn the real CLI as a subprocess set them to a unique
 * per-run value so concurrent test runs (or a real pre-existing entry on
 * the developer's machine) can never collide with each other.
 */
export function resolveKeyringIdentityFromEnv(env: Record<string, string | undefined> = process.env): KeyringIdentity | undefined {
	if (!env.ENIGMA_KEYRING_SERVICE && !env.ENIGMA_KEYRING_ACCOUNT) return undefined;
	return { service: env.ENIGMA_KEYRING_SERVICE ?? KEYRING_SERVICE, account: env.ENIGMA_KEYRING_ACCOUNT ?? KEYRING_ACCOUNT };
}
