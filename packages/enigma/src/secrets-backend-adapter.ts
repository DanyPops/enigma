/**
 * Enigma as one pluggable daemon-kit SecretsBackend, not the assumed target
 * of /secrets. Lives here (not in daemon-kit) because it wraps
 * EnigmaAdminClient's own wire protocol -- vendor-specific, same reason
 * enigma-client itself stays out of daemon-kit.
 *
 * list()/get() stay redaction-safe by construction: every SecretRecord
 * field comes from toRecord()'s explicit allow-list, never
 * accessToken/refreshToken/extra directly. reveal() is the one deliberate
 * exception -- it returns client.getCredentials()'s result unredacted, the
 * same real GET /creds/:backend read `enigma show` uses, so it's covered
 * by that route's own audit logging either way. secrets-tui.ts's
 * performReveal is what actually gates this to a real interactive TUI
 * session; this adapter has no opinion on who's allowed to call it.
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
		async reveal(name) {
			const credential = await client.getCredentials(name);
			return credential ? (credential as unknown as Record<string, unknown>) : undefined;
		},
	};
}
