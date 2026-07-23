/**
 * Per-backend login flows, built on `openid-client` (panva; OpenID
 * Certified — Basic, FAPI 1.0, FAPI 2.0 — RFC 8628 Device Authorization
 * Grant, discovery, refresh token grant) rather than hand-rolled polling.
 * Enigma owns the small amount of genuinely backend-specific residue
 * (which endpoints, whether discovery is even available) directly, rather
 * than importing pipes'/tickets' adapter code — the boundary rule is that
 * enigma knows backend names and URL/grant shapes, never a consumer
 * daemon's internal orchestration.
 *
 * Discovery availability, confirmed live against real servers rather than
 * assumed:
 *  - GitHub: no `.well-known/openid-configuration` at all (confirmed 404)
 *    — Configuration is built from GitHub's two fixed, documented
 *    endpoints instead of discovery.
 *  - GitLab: discovery works for the general server metadata, but its own
 *    discovery document always reports `device_authorization_endpoint:
 *    null` even on instances that advertise `device_code` as a supported
 *    grant type (confirmed on two independent instances) — a genuine
 *    GitLab product inconsistency, not an assumption. The endpoint is
 *    patched in from GitLab's own documented conventional path
 *    (`{baseUrl}/oauth/authorize_device`) after discovery, rather than
 *    trusting discovery for this one field.
 *  - Any other OIDC-compliant provider (Okta, Auth0, or a company's own
 *    identity provider, etc.): pure discovery, zero backend-specific
 *    knowledge — this is the generic path, and it never needs to name a specific company's
 *    instance anywhere in this file.
 */
import type { RefreshableAccessToken } from "@danypops/daemon-kit/vault";
import * as oidc from "openid-client";

export interface DeviceCodePrompt {
	verificationUri: string;
	userCode: string;
}

/** Narrower than `typeof fetch` so a plain test double doesn't need to satisfy Bun's full fetch shape (e.g. preconnect) — matches the FetchLike convention used throughout this codebase. */
export type OidcFetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

function tokenFromResponse(
	response: oidc.TokenEndpointResponse,
	extra?: Record<string, string>,
): RefreshableAccessToken {
	return {
		accessToken: response.access_token,
		refreshToken: response.refresh_token,
		expiresAt: response.expires_in !== undefined ? new Date(Date.now() + response.expires_in * 1000).toISOString() : undefined,
		scope: response.scope,
		extra,
	};
}

async function runDeviceFlow(
	config: oidc.Configuration,
	scope: string | undefined,
	onPrompt: (prompt: DeviceCodePrompt) => void,
	extra?: Record<string, string>,
): Promise<RefreshableAccessToken> {
	const deviceResponse = await oidc.initiateDeviceAuthorization(config, scope ? { scope } : {});
	onPrompt({ verificationUri: deviceResponse.verification_uri, userCode: deviceResponse.user_code });
	const tokens = await oidc.pollDeviceAuthorizationGrant(config, deviceResponse);
	return tokenFromResponse(tokens, extra);
}

function withCustomFetch(config: oidc.Configuration, fetchImpl?: OidcFetch): oidc.Configuration {
	if (fetchImpl) config[oidc.customFetch] = fetchImpl;
	return config;
}

export interface GitHubLoginOptions {
	clientId: string;
	scope?: string;
	fetchImpl?: OidcFetch;
	onPrompt: (prompt: DeviceCodePrompt) => void;
}

/** GitHub OAuth App device flow. Classic OAuth App tokens never expire and issue no refresh token — confirmed against GitHub's own docs (the device-flow response example has no refresh_token field at all; refresh is a GitHub-App-only feature). */
export async function loginGitHub(options: GitHubLoginOptions): Promise<RefreshableAccessToken> {
	const config = withCustomFetch(
		new oidc.Configuration(
			{
				issuer: "https://github.com",
				token_endpoint: "https://github.com/login/oauth/access_token",
				device_authorization_endpoint: "https://github.com/login/device/code",
			},
			options.clientId,
		),
		options.fetchImpl,
	);
	return runDeviceFlow(config, options.scope, options.onPrompt);
}

export interface GitLabLoginOptions {
	baseUrl: string;
	clientId: string;
	scope?: string;
	fetchImpl?: OidcFetch;
	onPrompt: (prompt: DeviceCodePrompt) => void;
}

/**
 * GitLab OAuth Device Authorization Grant only, for this pass — PKCE via a
 * local loopback callback (needed for self-managed instances predating the
 * device grant) is an explicit, flagged follow-up, not built here.
 * baseUrl/clientId are stashed in the token's `extra` field so a later
 * rotate can refresh without needing separate configuration storage.
 */
export async function loginGitLab(options: GitLabLoginOptions): Promise<RefreshableAccessToken> {
	const base = options.baseUrl.replace(/\/$/, "");
	let config: oidc.Configuration;
	try {
		config = await oidc.discovery(
			new URL(base),
			options.clientId,
			undefined,
			undefined,
			options.fetchImpl ? { [oidc.customFetch]: options.fetchImpl } : undefined,
		);
	} catch (error) {
		throw new Error(
			`GitLab OIDC discovery failed for ${base}: ${error instanceof Error ? error.message : String(error)} — this instance may not support OIDC discovery; PKCE fallback is not yet implemented in enigma`,
		);
	}
	// GitLab's discovery document reports device_authorization_endpoint as null even when
	// device_code is a supported grant type — patch in the documented conventional path.
	if (!config.serverMetadata().device_authorization_endpoint) {
		// serverMetadata() mixes plain data fields with helper methods (e.g. supportsPKCE) on the
		// same object; round-trip through JSON to get a clean, Configuration-constructor-safe clone.
		const discoveredMetadata = JSON.parse(JSON.stringify(config.serverMetadata())) as oidc.ServerMetadata;
		const patchedMetadata: oidc.ServerMetadata = { ...discoveredMetadata, device_authorization_endpoint: `${base}/oauth/authorize_device` };
		config = withCustomFetch(new oidc.Configuration(patchedMetadata, options.clientId), options.fetchImpl);
	}
	try {
		return await runDeviceFlow(config, options.scope, options.onPrompt, { baseUrl: options.baseUrl, clientId: options.clientId });
	} catch (error) {
		if (error instanceof oidc.ResponseBodyError && error.cause && typeof error.cause === "object" && "error" in error.cause && (error.cause as { error: unknown }).error === "Not Found") {
			throw new Error(`GitLab device authorization request failed: this instance may not support the device grant — PKCE fallback is not yet implemented in enigma`);
		}
		throw error;
	}
}

export interface OidcLoginOptions {
	issuerUrl: string;
	clientId: string;
	scope?: string;
	fetchImpl?: OidcFetch;
	onPrompt: (prompt: DeviceCodePrompt) => void;
}

/**
 * Generic OIDC device flow for any compliant provider — Okta, Auth0,
 * a company's own identity provider, or anything else. Zero backend-specific knowledge: the issuer
 * URL and client ID are supplied entirely by the operator at runtime,
 * never known to or named in this source file. issuerUrl/clientId are
 * stashed in the token's `extra` field so a later rotate can refresh.
 */
export async function loginOidc(options: OidcLoginOptions): Promise<RefreshableAccessToken> {
	const config = await oidc.discovery(
		new URL(options.issuerUrl),
		options.clientId,
		undefined,
		undefined,
		options.fetchImpl ? { [oidc.customFetch]: options.fetchImpl } : undefined,
	);
	if (!config.serverMetadata().device_authorization_endpoint) {
		throw new Error(`${options.issuerUrl} does not advertise a device_authorization_endpoint — this provider may not support the device grant`);
	}
	return runDeviceFlow(config, options.scope, options.onPrompt, { issuerUrl: options.issuerUrl, clientId: options.clientId });
}

export interface JenkinsLoginOptions {
	url: string;
	username: string;
	apiToken: string;
}

/** No OAuth flow exists for Jenkins — a static username+API-token pair is the real, documented primary path, not a fallback. */
export function loginJenkins(options: JenkinsLoginOptions): RefreshableAccessToken {
	return {
		accessToken: options.apiToken,
		extra: { url: options.url, username: options.username },
	};
}
