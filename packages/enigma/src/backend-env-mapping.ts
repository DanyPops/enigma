/**
 * Case-insensitive by convention: a backend name is a lookup key (URL path
 * segment, credential-vault filename, client-registry scope entry), never
 * display text, so "Brave" and "brave" must be the exact same backend
 * everywhere. Confirmed live as a real bug otherwise: a credential stored
 * as "Brave" was unreachable through a scope check comparing an
 * un-normalized path segment against it.
 */
export function normalizeBackendName(backend: string): string {
	return backend.toLowerCase();
}

/** `my-company-sso` -> `MY_COMPANY_SSO` — shared sanitization for a default env-var name derived from a backend/alias name. */
export function defaultEnvVarPrefix(backend: string): string {
	return backend
		.toUpperCase()
		.replace(/[^A-Z0-9]+/g, "_")
		.replace(/^_+|_+$/g, "");
}

/** `my-company-sso` -> `MY_COMPANY_SSO_TOKEN` — used only when the operator didn't pass `--env-var` at login time. */
export function defaultEnvVarName(backend: string): string {
	return `${defaultEnvVarPrefix(backend)}_TOKEN`;
}
