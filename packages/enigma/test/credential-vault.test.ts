import { describe, expect, it } from "bun:test";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createEncryptedFileStore } from "@danypops/vehicle-server/vault";
import { createCredentialVault } from "../src/credential-vault.ts";

function tmpVault() {
	const dir = mkdtempSync(join(tmpdir(), "enigma-credential-vault-"));
	return { dir, vault: createCredentialVault({ dir, masterKey: randomBytes(32) }) };
}

describe("createCredentialVault", () => {
	it("round-trips a credential through save/get", () => {
		const { dir, vault } = tmpVault();
		try {
			vault.save("widgetapi", { accessToken: "widget-token" });
			expect(vault.get("widgetapi")).toEqual({ accessToken: "widget-token" });
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("get/save/delete are case-insensitive -- a backend name is a lookup key, not display text", () => {
		const { dir, vault } = tmpVault();
		try {
			vault.save("WidgetApi", { accessToken: "widget-token" });
			expect(vault.get("widgetapi")).toEqual({ accessToken: "widget-token" });
			expect(vault.get("WIDGETAPI")).toEqual({ accessToken: "widget-token" });

			vault.delete("WIDGETAPI");
			expect(vault.get("widgetapi")).toBeUndefined();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("listBackends reflects the normalized (lowercase) name a credential was actually stored under", () => {
		const { dir, vault } = tmpVault();
		try {
			vault.save("WidgetApi", { accessToken: "t1" });
			vault.save("gadgetapi", { accessToken: "t2" });
			expect(vault.listBackends()).toEqual(["gadgetapi", "widgetapi"]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("returns undefined for a backend with nothing stored", () => {
		const { dir, vault } = tmpVault();
		try {
			expect(vault.get("nonexistent")).toBeUndefined();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("delete is idempotent -- deleting a nonexistent backend is not an error", () => {
		const { dir, vault } = tmpVault();
		try {
			expect(() => vault.delete("nonexistent")).not.toThrow();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("createCredentialVault: legacy pre-normalization data (a real file on disk under its raw casing, not written through this vault)", () => {
	it("finds a case-insensitive filename match, decrypting with this vault's own master key -- no migration needed", () => {
		const masterKey = randomBytes(32);
		const dir = mkdtempSync(join(tmpdir(), "enigma-credential-vault-"));
		try {
			// The shape production data actually had before backend names were
			// normalized: written directly under the raw "WidgetApi" name.
			createEncryptedFileStore({ dir, masterKey }, "WidgetApi").save({ accessToken: "legacy-token" });

			const vault = createCredentialVault({ dir, masterKey });
			expect(vault.get("widgetapi")).toEqual({ accessToken: "legacy-token" });
			expect(vault.get("WIDGETAPI")).toEqual({ accessToken: "legacy-token" });
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("listBackends normalizes and dedupes when a legacy-cased file and its normalized replacement coexist", () => {
		const masterKey = randomBytes(32);
		const dir = mkdtempSync(join(tmpdir(), "enigma-credential-vault-"));
		try {
			createEncryptedFileStore({ dir, masterKey }, "WidgetApi").save({ accessToken: "old" });
			createEncryptedFileStore({ dir, masterKey }, "widgetapi").save({ accessToken: "new" });

			const vault = createCredentialVault({ dir, masterKey });
			expect(vault.listBackends()).toEqual(["widgetapi"]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("delete removes both a normalized file and any coexisting legacy-cased file for the same backend", () => {
		const masterKey = randomBytes(32);
		const dir = mkdtempSync(join(tmpdir(), "enigma-credential-vault-"));
		try {
			createEncryptedFileStore({ dir, masterKey }, "WidgetApi").save({ accessToken: "old" });

			const vault = createCredentialVault({ dir, masterKey });
			vault.delete("widgetapi");
			expect(vault.get("widgetapi")).toBeUndefined();
			expect(vault.listBackends()).toEqual([]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
