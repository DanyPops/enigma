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
 *  - Jira Cloud (Atlassian OAuth 2.0 "3LO"): no OIDC discovery at all, and
 *    unlike GitHub/GitLab there is no device flow — authorization code
 *    only, confirmed against Atlassian's own docs. PKCE support is
 *    flag-gated per app by Atlassian support rather than universally
 *    available, so this uses the documented, guaranteed-available
 *    confidential-client path (client_secret) instead of assuming PKCE.
 *    Confirmed live that Atlassian's token endpoint accepts standard RFC
 *    6749 form-urlencoded requests identically to the JSON shape shown in
 *    their own docs (same error either way for a fake client), so
 *    openid-client's standard authorizationCodeGrant needs no
 *    modification. Multi-tenant: a cloudId must be looked up via a
 *    separate accessible-resources call after the token exchange, since
 *    every subsequent Jira API call is scoped through api.atlassian.com/
 *    ex/jira/{cloudId}/..., not the site's own domain.
 *  - Google: full OIDC discovery and a correctly-advertised device flow
 *    (confirmed live), but its token endpoint requires a client_secret
 *    even for device-flow clients (confirmed via its own discovery
 *    document listing no "none" auth method) — a genuinely different
 *    shape from GitHub/GitLab's public-client device flow despite both
 *    using the same grant type.
 */
import type { RefreshableAccessToken } from "@danypops/vehicle-server/vault";
import * as oidc from "openid-client";

export interface DeviceCodePrompt {
	verificationUri: string;
	userCode: string;
}

/** Narrower than `typeof fetch` so a plain test double doesn't need to satisfy Bun's full fetch shape (e.g. preconnect) — matches the FetchLike convention used throughout this codebase. */
export type OidcFetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

function tokenFromResponse(response: oidc.TokenEndpointResponse, extra?: Record<string, string>): RefreshableAccessToken {
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
	deviceAuthParams?: Record<string, string>,
): Promise<RefreshableAccessToken> {
	const deviceResponse = await oidc.initiateDeviceAuthorization(config, { ...(scope ? { scope } : {}), ...deviceAuthParams });
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
		if (
			error instanceof oidc.ResponseBodyError &&
			error.cause &&
			typeof error.cause === "object" &&
			"error" in error.cause &&
			(error.cause as { error: unknown }).error === "Not Found"
		) {
			throw new Error(
				`GitLab device authorization request failed: this instance may not support the device grant — PKCE fallback is not yet implemented in enigma`,
			);
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
		throw new Error(
			`${options.issuerUrl} does not advertise a device_authorization_endpoint — this provider may not support the device grant`,
		);
	}
	return runDeviceFlow(config, options.scope, options.onPrompt, { issuerUrl: options.issuerUrl, clientId: options.clientId });
}

// ── Google (Drive/Docs scopes, via device flow) ────────────────────────

const GOOGLE_ISSUER = "https://accounts.google.com";
const GOOGLE_DEFAULT_SCOPE = "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/documents";

export interface GoogleLoginOptions {
	clientId: string;
	clientSecret: string;
	scope?: string;
	fetchImpl?: OidcFetch;
	onPrompt: (prompt: DeviceCodePrompt) => void;
}

/**
 * Google fully supports OIDC discovery and a correctly-advertised device
 * flow (confirmed live — unlike GitLab's discovery, which reports
 * device_authorization_endpoint as null even when supported). Unlike
 * GitHub/GitLab's genuinely public-client device flow, Google's token
 * endpoint only accepts confidential client auth methods (confirmed via
 * its own discovery document's token_endpoint_auth_methods_supported,
 * which lists no "none" option) — so a client_secret is required even
 * for an installed-app/device-flow client. access_type=offline is passed
 * defensively, matching Google's documented mechanism for the
 * authorization-code flow to obtain a refresh token; unconfirmed whether
 * device flow strictly requires it, but harmless to include.
 */
export async function loginGoogle(options: GoogleLoginOptions): Promise<RefreshableAccessToken> {
	const config = await oidc.discovery(
		new URL(GOOGLE_ISSUER),
		options.clientId,
		undefined,
		oidc.ClientSecretPost(options.clientSecret),
		options.fetchImpl ? { [oidc.customFetch]: options.fetchImpl } : undefined,
	);
	return runDeviceFlow(
		config,
		options.scope ?? GOOGLE_DEFAULT_SCOPE,
		options.onPrompt,
		{ issuerUrl: GOOGLE_ISSUER, clientId: options.clientId, clientSecret: options.clientSecret },
		{ access_type: "offline" },
	);
}

// ── Jira Cloud (OAuth 2.0 3LO) ──────────────────────────────────────────────

const JIRA_AUTHORIZATION_ENDPOINT = "https://auth.atlassian.com/authorize";
const JIRA_TOKEN_ENDPOINT = "https://auth.atlassian.com/oauth/token";
const JIRA_ACCESSIBLE_RESOURCES_URL = "https://api.atlassian.com/oauth/token/accessible-resources";

export interface AccessibleResource {
	id: string;
	name: string;
	url: string;
	scopes: string[];
}

interface JiraCallbackResult {
	code: string;
	state: string;
}

export interface JiraCallbackListener {
	redirectUri: string;
	/** Resolves, never rejects — an OAuth error or a malformed callback is a result, not an exception. */
	waitForCallback(): Promise<JiraCallbackResult | { error: string }>;
	close(): void;
}

/**
 * Binds a fixed, documented port on 127.0.0.1, not an OS-assigned one.
 * Atlassian's docs state the redirect_uri "must match" the registered
 * Callback URL with no RFC 8252 loopback-port-exemption language the way
 * GitLab's Doorkeeper backend has (confirmed by reading Doorkeeper's own
 * source in earlier work on this project) — so the operator registers
 * this exact port once, and every login reuses it.
 */
export function startJiraCallbackListener(port: number): JiraCallbackListener {
	let resolveCallback: (result: JiraCallbackResult | { error: string }) => void;
	const waiter = new Promise<JiraCallbackResult | { error: string }>((resolve) => {
		resolveCallback = resolve;
	});

	const server = Bun.serve({
		hostname: "127.0.0.1",
		port,
		fetch(request) {
			const url = new URL(request.url);
			if (url.pathname !== "/callback") return new Response("not found", { status: 404 });
			const code = url.searchParams.get("code");
			const state = url.searchParams.get("state");
			const error = url.searchParams.get("error");
			if (error) {
				resolveCallback({ error });
				return new Response(`<html><body>Authorization failed: ${error}. You can close this tab.</body></html>`, {
					headers: { "content-type": "text/html" },
				});
			}
			if (!code || !state) {
				resolveCallback({ error: "missing code or state" });
				return new Response("<html><body>Missing code or state.</body></html>", { status: 400, headers: { "content-type": "text/html" } });
			}
			resolveCallback({ code, state });
			return new Response("<html><body>Authorization complete. You can close this tab.</body></html>", {
				headers: { "content-type": "text/html" },
			});
		},
	});

	return {
		redirectUri: `http://127.0.0.1:${port}/callback`,
		waitForCallback: () => waiter,
		close: () => server.stop(true),
	};
}

export interface JiraCloudLoginOptions {
	clientId: string;
	clientSecret: string;
	scope?: string;
	/** Fixed port matching the operator's registered Callback URL. */
	callbackPort: number;
	fetchImpl?: OidcFetch;
	/** Displays the URL to visit — unlike device flow there is no short user code, just a link. */
	onAuthUrl: (url: string) => void;
	/** Disambiguates when accessible-resources returns more than one site (URL or name substring match). */
	site?: string;
	/** Injectable for tests; production default starts a real loopback listener on callbackPort. */
	listener?: JiraCallbackListener;
}

function jiraConfiguration(options: Pick<JiraCloudLoginOptions, "clientId" | "clientSecret" | "fetchImpl">): oidc.Configuration {
	return withCustomFetch(
		new oidc.Configuration(
			{ issuer: "https://auth.atlassian.com", authorization_endpoint: JIRA_AUTHORIZATION_ENDPOINT, token_endpoint: JIRA_TOKEN_ENDPOINT },
			options.clientId,
			undefined,
			oidc.ClientSecretPost(options.clientSecret),
		),
		options.fetchImpl,
	);
}

async function fetchAccessibleResources(accessToken: string, fetchImpl?: OidcFetch): Promise<AccessibleResource[]> {
	const fetchFn = fetchImpl ?? fetch;
	const response = await fetchFn(JIRA_ACCESSIBLE_RESOURCES_URL, {
		headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
	});
	if (!response.ok) throw new Error(`Jira accessible-resources lookup failed: ${response.status} ${await response.text()}`);
	return (await response.json()) as AccessibleResource[];
}

function selectAccessibleResource(resources: AccessibleResource[], site?: string): AccessibleResource {
	if (resources.length === 0)
		throw new Error("Jira login succeeded but accessible-resources returned no sites — check the app's granted scopes");
	if (resources.length === 1) return resources[0]!;
	const match = site ? resources.find((r) => r.url.includes(site) || r.name.includes(site)) : undefined;
	if (match) return match;
	const names = resources.map((r) => r.url).join(", ");
	throw new Error(`Jira login is authorized for multiple sites (${names}) — pass a site option to disambiguate`);
}

/**
 * Authorization Code + confidential client (client_secret), matching
 * Atlassian's documented default rather than assuming PKCE. Stores
 * cloudId/siteUrl/clientId/clientSecret in the token's extra field: the
 * cloudId is required for every subsequent Jira API call's URL shape, and
 * clientId/clientSecret are required again for refresh since Jira's
 * refresh grant is client_secret-authenticated too.
 */
export async function loginJiraCloud(options: JiraCloudLoginOptions): Promise<RefreshableAccessToken> {
	const listener = options.listener ?? startJiraCallbackListener(options.callbackPort);
	try {
		const state = crypto.randomUUID();
		const params = new URLSearchParams({
			audience: "api.atlassian.com",
			client_id: options.clientId,
			redirect_uri: listener.redirectUri,
			state,
			response_type: "code",
			prompt: "consent",
			...(options.scope ? { scope: options.scope } : {}),
		});
		options.onAuthUrl(`${JIRA_AUTHORIZATION_ENDPOINT}?${params}`);

		const callback = await listener.waitForCallback();
		if ("error" in callback) throw new Error(`Jira authorization failed: ${callback.error}`);
		if (callback.state !== state) throw new Error("Jira authorization callback state mismatch — possible CSRF, aborting");

		const config = jiraConfiguration(options);
		const callbackUrl = new URL(listener.redirectUri);
		callbackUrl.searchParams.set("code", callback.code);
		callbackUrl.searchParams.set("state", callback.state);
		const tokens = await oidc.authorizationCodeGrant(config, callbackUrl, { expectedState: state });

		const resources = await fetchAccessibleResources(tokens.access_token, options.fetchImpl);
		const resource = selectAccessibleResource(resources, options.site);

		return tokenFromResponse(tokens, {
			clientId: options.clientId,
			clientSecret: options.clientSecret,
			cloudId: resource.id,
			siteUrl: resource.url,
		});
	} finally {
		listener.close();
	}
}

export interface ApiKeyLoginOptions {
	value: string;
	envVarName: string;
}

/**
 * Generic static API-key backend for a platform with no OAuth flow at all
 * (Brave, Tavily, Exa, Serper, SerpApi, or any other dashboard-issued
 * bearer key) — the same no-OAuth shape Jenkins already has, but with an
 * operator-supplied backend name and env var instead of a hardcoded one.
 * No company or product ever named in source, matching loginOidc's own
 * genericity. resolveRefreshFn already treats a credential carrying none
 * of the recognized OAuth `extra` shapes as unrefreshable, so this needs
 * no refresh-side change; `extra.envVarName` is stashed for whichever
 * consumer fetches this credential to use as its own default env var name.
 */
export function loginApiKey(options: ApiKeyLoginOptions): RefreshableAccessToken {
	return {
		accessToken: options.value,
		extra: { envVarName: options.envVarName },
	};
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
