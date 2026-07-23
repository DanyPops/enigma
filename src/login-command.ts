/**
 * Per-backend login flows. Enigma owns these directly rather than
 * importing pipes'/tickets' adapter code — the boundary rule is that
 * enigma knows backend names and URL/grant shapes, never a consumer
 * daemon's internal orchestration. GitHub's device flow and GitLab's
 * device flow are proven shapes (confirmed against each provider's own
 * docs); GitLab's Authorization Code+PKCE fallback for older self-managed
 * instances without the device grant is an explicit, flagged gap for a
 * follow-up, not built here.
 */
import type { FetchLike, RefreshableAccessToken } from "@danypops/daemon-kit/vault";

export interface DeviceCodePrompt {
	verificationUri: string;
	userCode: string;
}

export interface DeviceFlowResult {
	token: RefreshableAccessToken;
}

async function pollDeviceToken(
	tokenUrl: string,
	body: URLSearchParams,
	fetchImpl: FetchLike,
	sleepImpl: (ms: number) => Promise<void>,
	intervalS: number,
	expiresInS: number,
	onPoll: (response: Response) => Promise<{ status: "complete"; token: RefreshableAccessToken } | { status: "pending" } | { status: "slow_down"; intervalS?: number } | { status: "failed"; message: string }>,
): Promise<RefreshableAccessToken> {
	let interval = intervalS;
	const deadline = Date.now() + expiresInS * 1000;
	while (Date.now() < deadline) {
		await sleepImpl(interval * 1000);
		const response = await fetchImpl(tokenUrl, {
			method: "POST",
			headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
			body,
		});
		const result = await onPoll(response);
		if (result.status === "complete") return result.token;
		if (result.status === "failed") throw new Error(result.message);
		if (result.status === "slow_down") interval = result.intervalS ?? interval + 5;
	}
	throw new Error("device authorization expired before the user completed it");
}

export interface GitHubLoginOptions {
	clientId: string;
	scope?: string;
	fetchImpl?: FetchLike;
	sleepImpl?: (ms: number) => Promise<void>;
	onPrompt: (prompt: DeviceCodePrompt) => void;
}

/** GitHub OAuth App device flow. Classic OAuth App tokens never expire and issue no refresh token — confirmed against GitHub's own docs (the device-flow response example has no refresh_token field at all; refresh is a GitHub-App-only feature). */
export async function loginGitHub(options: GitHubLoginOptions): Promise<RefreshableAccessToken> {
	const doFetch = options.fetchImpl ?? fetch;
	const sleep = options.sleepImpl ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));

	const codeResponse = await doFetch("https://github.com/login/device/code", {
		method: "POST",
		headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ client_id: options.clientId, ...(options.scope ? { scope: options.scope } : {}) }),
	});
	if (!codeResponse.ok) throw new Error(`GitHub device code request failed: HTTP ${codeResponse.status}`);
	const code = (await codeResponse.json()) as { device_code: string; user_code: string; verification_uri: string; expires_in: number; interval: number };
	options.onPrompt({ verificationUri: code.verification_uri, userCode: code.user_code });

	return pollDeviceToken(
		"https://github.com/login/oauth/access_token",
		new URLSearchParams({ client_id: options.clientId, device_code: code.device_code, grant_type: "urn:ietf:params:oauth:grant-type:device_code" }),
		doFetch,
		sleep,
		code.interval,
		code.expires_in,
		async (response) => {
			const body = (await response.json()) as { error?: string; interval?: number; access_token?: string; scope?: string };
			if (body.error === "authorization_pending") return { status: "pending" };
			if (body.error === "slow_down") return { status: "slow_down", intervalS: body.interval };
			if (body.error === "expired_token") return { status: "failed", message: "device code expired" };
			if (body.error === "access_denied") return { status: "failed", message: "user denied the authorization request" };
			if (body.error) return { status: "failed", message: `GitHub device flow error: ${body.error}` };
			if (!body.access_token) return { status: "failed", message: "GitHub device flow response missing access_token" };
			return { status: "complete", token: { accessToken: body.access_token, scope: body.scope } };
		},
	);
}

export interface GitLabLoginOptions {
	baseUrl: string;
	clientId: string;
	scope?: string;
	fetchImpl?: FetchLike;
	sleepImpl?: (ms: number) => Promise<void>;
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
	const doFetch = options.fetchImpl ?? fetch;
	const sleep = options.sleepImpl ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
	const base = options.baseUrl.replace(/\/$/, "");

	const codeResponse = await doFetch(`${base}/oauth/authorize_device`, {
		method: "POST",
		headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ client_id: options.clientId, ...(options.scope ? { scope: options.scope } : {}) }),
	});
	if (!codeResponse.ok) {
		throw new Error(
			`GitLab device authorization request failed: HTTP ${codeResponse.status} — this instance may not support the device grant; PKCE fallback is not yet implemented in enigma`,
		);
	}
	const code = (await codeResponse.json()) as { device_code: string; user_code: string; verification_uri: string; expires_in: number; interval: number };
	options.onPrompt({ verificationUri: code.verification_uri, userCode: code.user_code });

	return pollDeviceToken(
		`${base}/oauth/token`,
		new URLSearchParams({ client_id: options.clientId, device_code: code.device_code, grant_type: "urn:ietf:params:oauth:grant-type:device_code" }),
		doFetch,
		sleep,
		code.interval,
		code.expires_in,
		async (response) => {
			const body = (await response.json()) as { error?: string; interval?: number; access_token?: string; refresh_token?: string; expires_in?: number; scope?: string };
			if (body.error === "authorization_pending") return { status: "pending" };
			if (body.error === "slow_down") return { status: "slow_down", intervalS: body.interval };
			if (body.error === "expired_token") return { status: "failed", message: "device code expired" };
			if (body.error === "access_denied") return { status: "failed", message: "user denied the authorization request" };
			if (body.error) return { status: "failed", message: `GitLab device flow error: ${body.error}` };
			if (!body.access_token) return { status: "failed", message: "GitLab device flow response missing access_token" };
			return {
				status: "complete",
				token: {
					accessToken: body.access_token,
					refreshToken: body.refresh_token,
					expiresAt: body.expires_in ? new Date(Date.now() + body.expires_in * 1000).toISOString() : undefined,
					scope: body.scope,
					extra: { baseUrl: options.baseUrl, clientId: options.clientId },
				},
			};
		},
	);
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
