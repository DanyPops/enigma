/**
 * Backend-agnostic credential storage: enigma knows backend *names*
 * ("github", "gitlab", "jira", "jenkins") and the generic credential
 * shape, never a specific backend's orchestration. One encrypted file per
 * backend under `credentialsDir`, via daemon-kit's AES-256-GCM store.
 */
import { createEncryptedFileStore, type RefreshableAccessToken } from "@danypops/daemon-kit/vault";
import { existsSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { normalizeBackendName } from "./backend-env-mapping.ts";

export interface CredentialVault {
	get(backend: string): RefreshableAccessToken | undefined;
	save(backend: string, token: RefreshableAccessToken): void;
	delete(backend: string): void;
	listBackends(): string[];
}

/** A file whose name case-insensitively matches `${normalized}.json`, for a credential stored before backend names were normalized -- avoids requiring a one-time file rename migration. */
function legacyCasedFile(dir: string, normalized: string): string | undefined {
	if (!existsSync(dir)) return undefined;
	return readdirSync(dir).find((f) => f.toLowerCase() === `${normalized}.json`);
}

export function createCredentialVault(options: { dir: string; masterKey: Buffer }): CredentialVault {
	return {
		get(backend: string): RefreshableAccessToken | undefined {
			const normalized = normalizeBackendName(backend);
			const direct = createEncryptedFileStore<RefreshableAccessToken>(options, normalized).load();
			if (direct) return direct;
			const legacy = legacyCasedFile(options.dir, normalized);
			return legacy ? createEncryptedFileStore<RefreshableAccessToken>(options, legacy.slice(0, -".json".length)).load() : undefined;
		},
		save(backend: string, token: RefreshableAccessToken): void {
			createEncryptedFileStore<RefreshableAccessToken>(options, normalizeBackendName(backend)).save(token);
		},
		delete(backend: string): void {
			const normalized = normalizeBackendName(backend);
			rmSync(join(options.dir, `${normalized}.json`), { force: true });
			const legacy = legacyCasedFile(options.dir, normalized);
			if (legacy) rmSync(join(options.dir, legacy), { force: true });
		},
		listBackends(): string[] {
			if (!existsSync(options.dir)) return [];
			const names = readdirSync(options.dir)
				.filter((f) => f.endsWith(".json"))
				.map((f) => normalizeBackendName(f.slice(0, -".json".length)));
			return [...new Set(names)].sort(); // dedupes a legacy-cased file coexisting with its normalized replacement
		},
	};
}
