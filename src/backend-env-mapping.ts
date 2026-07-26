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
	"GOOGLE_ACCESS_TOKEN",
	"JENKINS_API_TOKEN",
	"JENKINS_USER",
	"JENKINS_URL",
] as const;

function githubLikeEnv(prefix: string, token: RefreshableAccessToken): Record<string, string> {
	return { [`${prefix}_TOKEN`]: token.accessToken };
}

function gitlabEnv(prefix: string, token: RefreshableAccessToken): Record<string, string> {
	return { [`${prefix}_TOKEN`]: token.accessToken, ...(token.extra?.baseUrl ? { [`${prefix}_URL`]: token.extra.baseUrl } : {}) };
}

function jiraEnv(prefix: string, token: RefreshableAccessToken): Record<string, string> {
	// Tickets' own config.ts reads {PREFIX}_API_TOKEN + {PREFIX}_URL, not a bare {PREFIX}_TOKEN — confirmed by reading its source directly.
	return { [`${prefix}_API_TOKEN`]: token.accessToken, ...(token.extra?.siteUrl ? { [`${prefix}_URL`]: token.extra.siteUrl } : {}) };
}

function jenkinsEnv(prefix: string, token: RefreshableAccessToken): Record<string, string> {
	return {
		[`${prefix}_API_TOKEN`]: token.accessToken,
		...(token.extra?.username ? { [`${prefix}_USER`]: token.extra.username } : {}),
		...(token.extra?.url ? { [`${prefix}_URL`]: token.extra.url } : {}),
	};
}

function googleLikeEnv(prefix: string, token: RefreshableAccessToken): Record<string, string> {
	// Deliberately not named after GOOGLE_APPLICATION_CREDENTIALS — this is a raw bearer token for direct REST calls (Drive/Docs APIs), not an ADC file path for SDK auto-discovery.
	return { [`${prefix}_ACCESS_TOKEN`]: token.accessToken };
}

/**
 * The four built-in backends get fixed, well-known env var names when
 * stored under their literal platform name (`enigma login github` with no
 * `--as`) — unchanged, byte-for-byte, from before aliasing existed.
 *
 * A backend stored under any other name — either an operator-chosen
 * generic OIDC backend, or a built-in platform logged in *with* `--as`
 * for a second account (`enigma login github --as work`) — is resolved by
 * the stored credential's own *shape*, the same way `resolveRefreshFn`
 * already does, rather than by name. This is what lets a second GitHub/
 * GitLab/Jira/Jenkins/Google account keep its platform's full companion-
 * variable set (URL, USER, ...) under a prefix derived from the alias,
 * instead of collapsing to a single bare token var. Ordering relies on
 * the same structural non-collision guarantee `resolveRefreshFn` does:
 * generic OIDC (`loginOidc`) never carries a `clientSecret`, so
 * `issuerUrl+clientId+clientSecret` is uniquely Google-shaped.
 *
 * A truly generic backend (no recognizable built-in shape at all —
 * including a github-shaped credential, whose `extra` is empty) falls
 * through to `token.extra.envVarName` (stashed by `login oidc --env-var`)
 * or a sanitized default derived from the backend/alias name itself.
 */
export function mapCredentialToEnv(backend: string, token: RefreshableAccessToken): Record<string, string> {
	switch (backend) {
		case "github":
			return githubLikeEnv("GITHUB", token);
		case "gitlab":
			return gitlabEnv("GITLAB", token);
		case "jira":
			return jiraEnv("JIRA", token);
		case "jenkins":
			return jenkinsEnv("JENKINS", token);
		case "google":
			return googleLikeEnv("GOOGLE", token);
	}

	const prefix = defaultEnvVarPrefix(backend);
	if (token.extra?.cloudId) return jiraEnv(prefix, token);
	if (token.extra?.issuerUrl && token.extra?.clientId && token.extra?.clientSecret) return googleLikeEnv(prefix, token);
	if (token.extra?.baseUrl && token.extra?.clientId) return gitlabEnv(prefix, token);
	if (token.extra?.username && token.extra?.url && !token.extra?.clientId) return jenkinsEnv(prefix, token);

	// Generic OIDC already has its own explicit override (`--env-var` at login time, stashed as
	// extra.envVarName) since it's a single bare token with no fixed companion vars — the same
	// fallback also covers a github-shaped credential (no extra at all) under this alias.
	const envVarName = token.extra?.envVarName ?? defaultEnvVarName(backend);
	return { [envVarName]: token.accessToken };
}

/** `my-company-sso` -> `MY_COMPANY_SSO` — the shared sanitization behind both defaultEnvVarName and the built-in shape-detection prefix above. */
export function defaultEnvVarPrefix(backend: string): string {
	return backend.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

/** `my-company-sso` -> `MY_COMPANY_SSO_TOKEN` — used only when the operator didn't pass `--env-var` at login time. */
export function defaultEnvVarName(backend: string): string {
	return `${defaultEnvVarPrefix(backend)}_TOKEN`;
}
