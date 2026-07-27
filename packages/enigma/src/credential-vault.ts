/**
 * Backend-agnostic credential storage: enigma knows backend *names*
 * ("github", "gitlab", "jira", "jenkins") and the generic credential
 * shape, never a specific backend's orchestration. One encrypted file per
 * backend under `credentialsDir`, via daemon-kit's AES-256-GCM store.
 */
import { createEncryptedFileStore, type RefreshableAccessToken } from "@danypops/daemon-kit/vault";
import { existsSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

export interface CredentialVault {
	get(backend: string): RefreshableAccessToken | undefined;
	save(backend: string, token: RefreshableAccessToken): void;
	delete(backend: string): void;
	listBackends(): string[];
}

export function createCredentialVault(options: { dir: string; masterKey: Buffer }): CredentialVault {
	return {
		get(backend: string): RefreshableAccessToken | undefined {
			return createEncryptedFileStore<RefreshableAccessToken>(options, backend).load();
		},
		save(backend: string, token: RefreshableAccessToken): void {
			createEncryptedFileStore<RefreshableAccessToken>(options, backend).save(token);
		},
		delete(backend: string): void {
			rmSync(join(options.dir, `${backend}.json`), { force: true });
		},
		listBackends(): string[] {
			if (!existsSync(options.dir)) return [];
			return readdirSync(options.dir)
				.filter((f) => f.endsWith(".json"))
				.map((f) => f.slice(0, -".json".length))
				.sort();
		},
	};
}
