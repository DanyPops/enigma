/**
 * Token refresh, resolved from what a credential's own `extra` field
 * carries rather than a fixed backend-name registry. A GitLab-shaped
 * credential (`extra.baseUrl` + `extra.clientId`, no `extra.issuerUrl`)
 * and a generic-OIDC-shaped one (`extra.issuerUrl` + `extra.clientId`,
 * stashed by loginOidc) both refresh through the exact same
 * `openid-client` refresh_token grant — the only difference is how their
 * Configuration is built. This is what makes refresh work for an
 * arbitrarily operator-named OIDC backend with zero new code per name:
 * capability follows the credential's own shape, not a name someone
 * remembered to register. Jira Cloud is the one exception needing its own
 * shape check (`extra.cloudId`), since it is client_secret-authenticated
 * rather than public-client, and its refresh tokens rotate on every use
 * rather than persisting.
 */
import type { RefreshableAccessToken } from "@danypops/daemon-kit/vault";
import * as oidc from "openid-client";
import type { OidcFetch } from "./login-command.ts";

export type RefreshFn = (current: RefreshableAccessToken) => Promise<RefreshableAccessToken>;

function tokenFromRefreshResponse(response: oidc.TokenEndpointResponse, current: RefreshableAccessToken): RefreshableAccessToken {
	return {
		accessToken: response.access_token,
		// Providers that rotate refresh tokens on use return a new one; keep the current one otherwise.
		refreshToken: response.refresh_token ?? current.refreshToken,
		expiresAt: response.expires_in !== undefined ? new Date(Date.now() + response.expires_in * 1000).toISOString() : undefined,
		scope: response.scope ?? current.scope,
		extra: current.extra,
	};
}

function withCustomFetch(config: oidc.Configuration, fetchImpl?: OidcFetch): oidc.Configuration {
	if (fetchImpl) config[oidc.customFetch] = fetchImpl;
	return config;
}

/**
 * Atlassian issues rotating refresh tokens: each successful refresh
 * invalidates the token just used and returns a new one (confirmed
 * against Atlassian's own docs and multiple corroborating reports of
 * `invalid_grant` failures from treating them as persistent). A response
 * missing a new refresh token is therefore an error condition, not a
 * "keep the current one" case the way GitLab's non-rotating refresh is.
 */
function tokenFromRotatingRefreshResponse(response: oidc.TokenEndpointResponse, current: RefreshableAccessToken): RefreshableAccessToken {
	if (!response.refresh_token) throw new Error("Jira refresh response carried no rotated refresh token — Atlassian's refresh tokens are single-use; this should not happen on a successful refresh");
	return {
		accessToken: response.access_token,
		refreshToken: response.refresh_token,
		expiresAt: response.expires_in !== undefined ? new Date(Date.now() + response.expires_in * 1000).toISOString() : undefined,
		scope: response.scope ?? current.scope,
		extra: current.extra,
	};
}

/** Jira Cloud's refresh grant is client_secret-authenticated, matching login — both clientId and clientSecret must have been stashed in extra at login time. */
function createJiraRefresh(clientId: string, clientSecret: string, fetchImpl?: OidcFetch): RefreshFn {
	return async (current: RefreshableAccessToken): Promise<RefreshableAccessToken> => {
		if (!current.refreshToken) throw new Error("Jira credential has no refresh token — cannot refresh; re-run login with the offline_access scope");
		const config = withCustomFetch(
			new oidc.Configuration({ issuer: "https://auth.atlassian.com", token_endpoint: "https://auth.atlassian.com/oauth/token" }, clientId, undefined, oidc.ClientSecretPost(clientSecret)),
			fetchImpl,
		);
		const response = await oidc.refreshTokenGrant(config, current.refreshToken);
		return tokenFromRotatingRefreshResponse(response, current);
	};
}

/** GitLab's token endpoint follows a well-known, documented convention — refresh needs only that, not a full re-discovery (device_authorization_endpoint is irrelevant here). */
function createGitLabRefresh(baseUrl: string, clientId: string, fetchImpl?: OidcFetch): RefreshFn {
	return async (current: RefreshableAccessToken): Promise<RefreshableAccessToken> => {
		if (!current.refreshToken) throw new Error("GitLab credential has no refresh token — cannot refresh; re-run login");
		const base = baseUrl.replace(/\/$/, "");
		const config = withCustomFetch(new oidc.Configuration({ issuer: base, token_endpoint: `${base}/oauth/token` }, clientId), fetchImpl);
		const response = await oidc.refreshTokenGrant(config, current.refreshToken);
		return tokenFromRefreshResponse(response, current);
	};
}

/** Generic OIDC re-discovers the issuer (a second round trip, accepted for how infrequent refreshes are) rather than requiring the token endpoint to be separately stashed at login time. */
function createOidcRefresh(issuerUrl: string, clientId: string, fetchImpl?: OidcFetch): RefreshFn {
	return async (current: RefreshableAccessToken): Promise<RefreshableAccessToken> => {
		if (!current.refreshToken) throw new Error("OIDC credential has no refresh token — cannot refresh; re-run login");
		const config = await oidc.discovery(
			new URL(issuerUrl),
			clientId,
			undefined,
			undefined,
			fetchImpl ? { [oidc.customFetch]: fetchImpl } : undefined,
		);
		const response = await oidc.refreshTokenGrant(config, current.refreshToken);
		return tokenFromRefreshResponse(response, current);
	};
}

/**
 * Same shape as generic OIDC refresh but with confidential client auth —
 * Google's token endpoint requires a client_secret even for a
 * device-flow-obtained credential (confirmed via its own discovery
 * document). Google's refresh tokens are persistent, not rotating, so a
 * response omitting a new one means keep the current one, matching
 * GitLab's pattern rather than Jira's error-on-missing pattern.
 */
function createConfidentialOidcRefresh(issuerUrl: string, clientId: string, clientSecret: string, fetchImpl?: OidcFetch): RefreshFn {
	return async (current: RefreshableAccessToken): Promise<RefreshableAccessToken> => {
		if (!current.refreshToken) throw new Error("OIDC credential has no refresh token — cannot refresh; re-run login");
		const config = await oidc.discovery(
			new URL(issuerUrl),
			clientId,
			undefined,
			oidc.ClientSecretPost(clientSecret),
			fetchImpl ? { [oidc.customFetch]: fetchImpl } : undefined,
		);
		const response = await oidc.refreshTokenGrant(config, current.refreshToken);
		return tokenFromRefreshResponse(response, current);
	};
}

/**
 * `undefined` means "this credential carries nothing refreshable" — GitHub
 * OAuth App tokens never expire and issue no refresh token; Jenkins is a
 * static username+API-token pair with no OAuth lifecycle at all.
 */
export function resolveRefreshFn(credential: RefreshableAccessToken, fetchImpl?: OidcFetch): RefreshFn | undefined {
	if (credential.extra?.cloudId && credential.extra?.clientId && credential.extra?.clientSecret) {
		return createJiraRefresh(credential.extra.clientId, credential.extra.clientSecret, fetchImpl);
	}
	// Checked before the plain issuerUrl+clientId branch below: a credential carrying a clientSecret
	// (Google) must never be misrouted through the public-client path, which would omit it and fail.
	if (credential.extra?.issuerUrl && credential.extra?.clientId && credential.extra?.clientSecret) {
		return createConfidentialOidcRefresh(credential.extra.issuerUrl, credential.extra.clientId, credential.extra.clientSecret, fetchImpl);
	}
	if (credential.extra?.issuerUrl && credential.extra?.clientId) {
		return createOidcRefresh(credential.extra.issuerUrl, credential.extra.clientId, fetchImpl);
	}
	if (credential.extra?.baseUrl && credential.extra?.clientId) {
		return createGitLabRefresh(credential.extra.baseUrl, credential.extra.clientId, fetchImpl);
	}
	return undefined;
}
