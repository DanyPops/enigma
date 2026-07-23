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
	"JIRA_TOKEN",
	"JENKINS_API_TOKEN",
	"JENKINS_USER",
	"JENKINS_URL",
] as const;

export function mapCredentialToEnv(backend: string, token: RefreshableAccessToken): Record<string, string> {
	switch (backend) {
		case "github":
			return { GITHUB_TOKEN: token.accessToken };
		case "gitlab":
			return { GITLAB_TOKEN: token.accessToken, ...(token.extra?.baseUrl ? { GITLAB_URL: token.extra.baseUrl } : {}) };
		case "jira":
			return { JIRA_TOKEN: token.accessToken };
		case "jenkins":
			return {
				JENKINS_API_TOKEN: token.accessToken,
				...(token.extra?.username ? { JENKINS_USER: token.extra.username } : {}),
				...(token.extra?.url ? { JENKINS_URL: token.extra.url } : {}),
			};
		default:
			return {};
	}
}
