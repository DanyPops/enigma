/**
 * Maps a stored credential to the env-var names a consumer daemon actually
 * reads. This mapping is enigma's alone — daemon-kit's vault module knows
 * only the generic credential shape, never these per-backend variable names.
 */
import type { RefreshableAccessToken } from "@danypops/daemon-kit/vault";

/**
 * Every env var name any backend can produce. Used to scrub a unit's
 * resolved env before injecting its own — daemon-kit's generic spawnUnit
 * inherits the whole parent process env by design (a normal daemon needs
 * PATH/HOME/etc.), which means any credential-shaped var that happens to
 * be ambiently set on enigma's own process (e.g. present in its systemd
 * unit's Environment=, or left over from an unrelated shell) would
 * otherwise leak into every child regardless of that unit's own
 * `backends` list. Explicitly overriding every known name to "" for a
 * unit that didn't request it closes that gap.
 */
export const ALL_CREDENTIAL_ENV_VAR_NAMES = [
	"GITHUB_TOKEN",
	"GITLAB_TOKEN",
	"GITLAB_URL",
	"JIRA_API_TOKEN",
	"JIRA_URL",
	"JENKINS_API_TOKEN",
	"JENKINS_USER",
	"JENKINS_URL",
] as const;

/**
 * The four built-in backends get fixed, well-known env var names. Any
 * other backend name (an operator-chosen generic OIDC backend, e.g. one
 * pointed at a company's own SSO) has no name enigma could possibly know
 * ahead of time — it uses `token.extra.envVarName`, stashed by the CLI's
 * `login oidc --env-var` flag at login time, falling back to a sanitized
 * default derived from the backend name itself if the operator didn't
 * supply one.
 */
export function mapCredentialToEnv(backend: string, token: RefreshableAccessToken): Record<string, string> {
	switch (backend) {
		case "github":
			return { GITHUB_TOKEN: token.accessToken };
		case "gitlab":
			return { GITLAB_TOKEN: token.accessToken, ...(token.extra?.baseUrl ? { GITLAB_URL: token.extra.baseUrl } : {}) };
		case "jira":
			// Tickets' own config.ts reads JIRA_API_TOKEN + JIRA_URL, not a bare JIRA_TOKEN — confirmed by reading its source directly.
			return { JIRA_API_TOKEN: token.accessToken, ...(token.extra?.siteUrl ? { JIRA_URL: token.extra.siteUrl } : {}) };
		case "jenkins":
			return {
				JENKINS_API_TOKEN: token.accessToken,
				...(token.extra?.username ? { JENKINS_USER: token.extra.username } : {}),
				...(token.extra?.url ? { JENKINS_URL: token.extra.url } : {}),
			};
		default: {
			const envVarName = token.extra?.envVarName ?? defaultEnvVarName(backend);
			return { [envVarName]: token.accessToken };
		}
	}
}

/** `my-company-sso` -> `MY_COMPANY_SSO_TOKEN` — used only when the operator didn't pass `--env-var` at login time. */
export function defaultEnvVarName(backend: string): string {
	return `${backend.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "")}_TOKEN`;
}
