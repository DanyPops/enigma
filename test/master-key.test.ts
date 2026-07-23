import { describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Entry } from "@napi-rs/keyring";
import { getOrCreateMasterKey, getOrCreateMasterKeyFromFile, getOrCreateMasterKeyFromKeyring } from "../src/master-key.ts";
import { KEYRING_ACCOUNT, KEYRING_SERVICE } from "../src/constants.ts";

function tmpDir(): string {
	return mkdtempSync(join(tmpdir(), "enigma-master-key-"));
}

describe("getOrCreateMasterKeyFromFile", () => {
	it("generates a fresh 32-byte key on first use and persists it 0600", () => {
		const dir = tmpDir();
		try {
			const path = join(dir, ".master");
			const key = getOrCreateMasterKeyFromFile(path);
			expect(key.length).toBe(32);
			const stat = statSync(path);
			expect((stat.mode & 0o777).toString(8)).toBe("600");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("returns the same key across repeated calls, not regenerating each time", () => {
		const dir = tmpDir();
		try {
			const path = join(dir, ".master");
			const first = getOrCreateMasterKeyFromFile(path);
			const second = getOrCreateMasterKeyFromFile(path);
			expect(second.equals(first)).toBe(true);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("refuses a malformed key file rather than silently deriving a wrong-length key", () => {
		const dir = tmpDir();
		try {
			const path = join(dir, ".master");
			writeFileSync(path, "not-valid-base64-for-32-bytes\n", { mode: 0o600 });
			expect(() => getOrCreateMasterKeyFromFile(path)).toThrow(/32 bytes/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("getOrCreateMasterKeyFromKeyring", () => {
	it("returns a 32-byte key when a real OS keyring backend is available, or undefined if not — never throws either way", () => {
		// This machine's session keyring is real and reachable (confirmed via a
		// manual smoke test before writing this module), so this exercises the
		// actual native binding, not a mock — but the assertion tolerates
		// undefined too, since CI/headless environments may have no keyring.
		// Cleans up the real entry it creates so running this suite doesn't
		// leave permanent state behind in the developer's actual OS keyring.
		try {
			const key = getOrCreateMasterKeyFromKeyring();
			if (key !== undefined) {
				expect(key.length).toBe(32);
			}
		} finally {
			try {
				new Entry(KEYRING_SERVICE, KEYRING_ACCOUNT).deletePassword();
			} catch {
				// No entry to delete (keyring unavailable in this environment) — fine.
			}
		}
	});
});

describe("getOrCreateMasterKey", () => {
	it("resolves to a usable 32-byte key end to end, via whichever path is actually available", () => {
		// On a machine with a real keyring (this one), getOrCreateMasterKey resolves
		// via the keyring path and the file path is never touched — clean up the
		// keyring entry too so this test leaves no permanent state either way.
		const dir = tmpDir();
		try {
			const key = getOrCreateMasterKey(join(dir, ".master"));
			expect(key.length).toBe(32);
		} finally {
			rmSync(dir, { recursive: true, force: true });
			try {
				new Entry(KEYRING_SERVICE, KEYRING_ACCOUNT).deletePassword();
			} catch {
				// No entry to delete — fine.
			}
		}
	});
});
