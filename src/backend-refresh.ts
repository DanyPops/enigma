/**
 * Per-backend token-refresh functions, keyed by backend name. This mapping
 * lives here, not in daemon-kit's vault module — daemon-kit knows only the
 * generic credential shape, never which backend issued it or how to renew
 * one. Each backend's own URL-shape/grant-type details are the small,
 * genuinely backend-specific residue this module exists to hold.
 */
import type { FetchLike, RefreshableAccessToken } from "@danypops/daemon-kit/vault";

export type RefreshFn = (current: RefreshableAccessToken) => Promise<RefreshableAccessToken>;

/**
 * GitLab issues real, rotating refresh tokens (unlike GitHub's OAuth App
 * device flow, which never expires and has none). `baseUrl` and `clientId`
 * travel in the token's own `extra` field (stashed there at login time) so
 * refresh never needs a separate, easy-to-drift configuration store.
 */
export function createGitLabRefresh(fetchImpl?: FetchLike): RefreshFn {
	return async (current: RefreshableAccessToken): Promise<RefreshableAccessToken> => {
		const baseUrl = current.extra?.baseUrl;
		const clientId = current.extra?.clientId;
		if (!baseUrl || !clientId) {
			throw new Error("GitLab credential is missing baseUrl/clientId in its extra fields — cannot refresh; re-run login");
		}
		if (!current.refreshToken) {
			throw new Error("GitLab credential has no refresh token — cannot refresh; re-run login");
		}
		const doFetch = fetchImpl ?? fetch;
		const response = await doFetch(`${baseUrl.replace(/\/$/, "")}/oauth/token`, {
			method: "POST",
			headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ client_id: clientId, refresh_token: current.refreshToken, grant_type: "refresh_token" }),
		});
		if (!response.ok) throw new Error(`GitLab token refresh failed: HTTP ${response.status}`);
		const body = (await response.json()) as { access_token: string; refresh_token?: string; expires_in?: number; scope?: string };
		return {
			accessToken: body.access_token,
			// GitLab rotates refresh tokens on use; keep the current one only if the response omits a new one.
			refreshToken: body.refresh_token ?? current.refreshToken,
			expiresAt: body.expires_in ? new Date(Date.now() + body.expires_in * 1000).toISOString() : undefined,
			scope: body.scope,
			extra: current.extra,
		};
	};
}

/**
 * Registry consulted by the `/rotate/:backend` route and `enigma rotate`.
 * `undefined` means "this backend has nothing to refresh" (GitHub OAuth App
 * tokens never expire; Jenkins is a static username+API-token pair with no
 * OAuth lifecycle at all) rather than a silently-missing feature.
 *
 * Jira/Atlassian 3LO does issue refresh tokens, but that flow isn't ported
 * here yet — an explicit, flagged gap, not a silent omission. `enigma
 * rotate jira` returns a clear "not yet supported" error rather than
 * pretending to succeed.
 */
export function buildBackendRefreshRegistry(fetchImpl?: FetchLike): Record<string, RefreshFn | undefined> {
	return {
		gitlab: createGitLabRefresh(fetchImpl),
		github: undefined,
		jenkins: undefined,
		jira: undefined,
	};
}
