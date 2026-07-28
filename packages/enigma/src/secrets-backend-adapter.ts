/**
 * Enigma as one pluggable daemon-kit SecretsBackend, not the assumed target
 * of /secrets. Lives here (not in daemon-kit) because it wraps
 * EnigmaAdminClient's own wire protocol -- vendor-specific, same reason
 * enigma-client itself stays out of daemon-kit.
 *
 * Every field on the returned SecretRecord is redaction-safe by
 * construction, matching this project's own extension/src/redact.ts:
 * accessToken/refreshToken/extra never leave client.getCredentials()'s
 * result here.
 */
import type { SecretRecord, SecretsBackend } from "@danypops/daemon-kit/secrets-backend";
import type { EnigmaAdminClient, VaultCredential } from "./client.ts";

const SOURCE = "enigma";

function toRecord(name: string, credential: VaultCredential | undefined): SecretRecord {
	if (!credential) return { name, source: SOURCE, configured: false };
	return { name, source: SOURCE, configured: true, ...(credential.expiresAt ? { expiresAt: credential.expiresAt } : {}), ...(credential.scope ? { scope: credential.scope } : {}) };
}

export function createEnigmaSecretsBackend(client: EnigmaAdminClient): SecretsBackend {
	return {
		source: SOURCE,
		async list() {
			const names = await client.listCredentialKeys();
			const records: SecretRecord[] = [];
			for (const name of names) records.push(toRecord(name, await client.getCredentials(name)));
			return records;
		},
		async get(name) {
			const credential = await client.getCredentials(name);
			return credential ? toRecord(name, credential) : undefined;
		},
		async rotate(name) {
			await client.rotateCredential(name);
		},
		async revoke(name) {
			await client.revokeCredential(name);
		},
	};
}
