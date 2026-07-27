/**
 * Enforces "Enigma Pi extension: never expose decrypted credential material to
 * the LLM" by construction: every field here is explicitly allow-listed from a
 * VaultCredential, never derived by stripping known-secret keys off the raw
 * record. accessToken, refreshToken, and extra never pass through this file.
 */
import type { VaultCredential } from "../../src/client.ts";

export interface RedactedCredentialStatus {
	backend: string;
	configured: boolean;
	expiresAt?: string;
	scope?: string;
}

export function redactCredentialStatus(backend: string, credential: VaultCredential | undefined): RedactedCredentialStatus {
	if (!credential) return { backend, configured: false };
	return {
		backend,
		configured: true,
		...(credential.expiresAt ? { expiresAt: credential.expiresAt } : {}),
		...(credential.scope ? { scope: credential.scope } : {}),
	};
}

export function describeCredentialStatus(status: RedactedCredentialStatus): string {
	if (!status.configured) return "not configured";
	const parts: string[] = [];
	parts.push(describeExpiry(status.expiresAt));
	if (status.scope) parts.push(`scope: ${status.scope}`);
	return parts.join(" \u2022 ");
}

function describeExpiry(expiresAt: string | undefined): string {
	if (!expiresAt) return "no expiry";
	const target = new Date(expiresAt).getTime();
	if (Number.isNaN(target)) return "no expiry";
	const remainingMs = target - Date.now();
	if (remainingMs <= 0) return "expired";
	const hours = Math.round(remainingMs / (60 * 60 * 1000));
	if (hours < 1) return "expires in <1h";
	if (hours < 48) return `expires in ${hours}h`;
	return `expires in ${Math.round(hours / 24)}d`;
}
