/** `my-company-sso` -> `MY_COMPANY_SSO` — shared sanitization for a default env-var name derived from a backend/alias name. */
export function defaultEnvVarPrefix(backend: string): string {
	return backend.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

/** `my-company-sso` -> `MY_COMPANY_SSO_TOKEN` — used only when the operator didn't pass `--env-var` at login time. */
export function defaultEnvVarName(backend: string): string {
	return `${defaultEnvVarPrefix(backend)}_TOKEN`;
}
