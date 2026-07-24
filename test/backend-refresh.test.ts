import { describe, expect, it } from "bun:test";
import type { OidcFetch } from "../src/login-command.ts";
import { resolveRefreshFn } from "../src/backend-refresh.ts";

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("resolveRefreshFn", () => {
	it("returns undefined for a credential with neither GitLab-shaped nor generic-OIDC-shaped extra fields (GitHub, Jenkins)", () => {
		expect(resolveRefreshFn({ accessToken: "gh-token" })).toBeUndefined();
		expect(resolveRefreshFn({ accessToken: "jenkins-token", extra: { url: "https://jenkins.example.com", username: "bot" } })).toBeUndefined();
	});

	it("resolves a GitLab-shaped refresh function (baseUrl + clientId, no issuerUrl) that hits the well-known GitLab token endpoint directly", async () => {
		const credential = { accessToken: "stale", refreshToken: "r1", extra: { baseUrl: "https://gitlab.example.com", clientId: "c" } };
		const fetchImpl: OidcFetch = async (input) => {
			const url = String(input);
			if (url === "https://gitlab.example.com/oauth/token") {
				return jsonResponse({ access_token: "fresh-gitlab", refresh_token: "r2", expires_in: 7200, token_type: "bearer" });
			}
			throw new Error(`unexpected fetch: ${url}`);
		};
		const refresh = resolveRefreshFn(credential, fetchImpl);
		expect(refresh).toBeDefined();
		const refreshed = await refresh!(credential);
		expect(refreshed.accessToken).toBe("fresh-gitlab");
		expect(refreshed.refreshToken).toBe("r2");
		expect(refreshed.extra).toEqual(credential.extra);
	});

	it("resolves a generic-OIDC-shaped refresh function (issuerUrl + clientId) that re-discovers before refreshing", async () => {
		const credential = { accessToken: "stale", refreshToken: "r1", extra: { issuerUrl: "https://idp.example.com", clientId: "c" } };
		let discoveryCalled = false;
		const fetchImpl: OidcFetch = async (input) => {
			const url = String(input);
			if (url === "https://idp.example.com/.well-known/openid-configuration") {
				discoveryCalled = true;
				return jsonResponse({ issuer: "https://idp.example.com", token_endpoint: "https://idp.example.com/token" });
			}
			if (url === "https://idp.example.com/token") {
				return jsonResponse({ access_token: "fresh-generic", expires_in: 3600, token_type: "bearer" });
			}
			throw new Error(`unexpected fetch: ${url}`);
		};
		const refresh = resolveRefreshFn(credential, fetchImpl);
		expect(refresh).toBeDefined();
		const refreshed = await refresh!(credential);
		expect(discoveryCalled).toBe(true);
		expect(refreshed.accessToken).toBe("fresh-generic");
		// No rotated refresh token in the response: the current one is kept.
		expect(refreshed.refreshToken).toBe("r1");
	});

	it("keeps the current refresh token when the response omits a rotated one (GitLab-shaped)", async () => {
		const credential = { accessToken: "stale", refreshToken: "r1", extra: { baseUrl: "https://gitlab.example.com", clientId: "c" } };
		const fetchImpl: OidcFetch = async () => jsonResponse({ access_token: "fresh", expires_in: 7200, token_type: "bearer" });
		const refreshed = await resolveRefreshFn(credential, fetchImpl)!(credential);
		expect(refreshed.refreshToken).toBe("r1");
	});

	it("throws a clear error rather than attempting a request when the credential has no refresh token at all", async () => {
		const credential = { accessToken: "stale", extra: { baseUrl: "https://gitlab.example.com", clientId: "c" } };
		const fetchImpl: OidcFetch = async () => {
			throw new Error("should not be called");
		};
		await expect(resolveRefreshFn(credential, fetchImpl)!(credential)).rejects.toThrow(/no refresh token/);
	});

	it("resolves a Jira-shaped refresh function (cloudId + clientId + clientSecret) that authenticates with client_secret, distinct from GitLab/generic-OIDC's public-client shape", async () => {
		const credential = { accessToken: "stale", refreshToken: "jira-r1", extra: { cloudId: "cloud-1", siteUrl: "https://my-site.atlassian.net", clientId: "jc", clientSecret: "js" } };
		const fetchImpl: OidcFetch = async (input) => {
			const url = String(input);
			if (url === "https://auth.atlassian.com/oauth/token") {
				return jsonResponse({ access_token: "jira-fresh", refresh_token: "jira-r2", expires_in: 3600, token_type: "bearer" });
			}
			throw new Error(`unexpected fetch: ${url}`);
		};
		const refreshed = await resolveRefreshFn(credential, fetchImpl)!(credential);
		expect(refreshed.accessToken).toBe("jira-fresh");
		expect(refreshed.refreshToken).toBe("jira-r2");
		expect(refreshed.extra).toEqual(credential.extra);
	});

	it("treats a Jira refresh response missing a rotated refresh token as an error, not as \"keep the current one\" — Atlassian's refresh tokens are single-use, unlike GitLab's", async () => {
		const credential = { accessToken: "stale", refreshToken: "jira-r1", extra: { cloudId: "cloud-1", clientId: "jc", clientSecret: "js" } };
		const fetchImpl: OidcFetch = async () => jsonResponse({ access_token: "jira-fresh", expires_in: 3600, token_type: "bearer" });
		await expect(resolveRefreshFn(credential, fetchImpl)!(credential)).rejects.toThrow(/no rotated refresh token/);
	});

	it("throws a clear error for a Jira credential with no refresh token, without attempting a request", async () => {
		const credential = { accessToken: "stale", extra: { cloudId: "cloud-1", clientId: "jc", clientSecret: "js" } };
		const fetchImpl: OidcFetch = async () => {
			throw new Error("should not be called");
		};
		await expect(resolveRefreshFn(credential, fetchImpl)!(credential)).rejects.toThrow(/no refresh token/);
	});

	it("resolves a confidential-client OIDC refresh (Google-shaped: issuerUrl + clientId + clientSecret) rather than misrouting it through the plain public-client generic-OIDC path", async () => {
		const credential = { accessToken: "stale", refreshToken: "1//refresh-x", extra: { issuerUrl: "https://accounts.google.com", clientId: "g-client", clientSecret: "g-secret" } };
		let discoveryCalled = false;
		let tokenAuthBody: URLSearchParams | undefined;
		const fetchImpl: OidcFetch = async (input, init) => {
			const url = String(input);
			if (url === "https://accounts.google.com/.well-known/openid-configuration") {
				discoveryCalled = true;
				return jsonResponse({ issuer: "https://accounts.google.com", token_endpoint: "https://oauth2.googleapis.com/token", token_endpoint_auth_methods_supported: ["client_secret_post"] });
			}
			if (url === "https://oauth2.googleapis.com/token") {
				tokenAuthBody = new URLSearchParams(init?.body as string);
				return jsonResponse({ access_token: "ya29.fresh", expires_in: 3599, token_type: "Bearer" });
			}
			throw new Error(`unexpected fetch: ${url}`);
		};
		const refreshed = await resolveRefreshFn(credential, fetchImpl)!(credential);
		expect(discoveryCalled).toBe(true);
		expect(tokenAuthBody?.get("client_secret")).toBe("g-secret");
		expect(refreshed.accessToken).toBe("ya29.fresh");
		// Persistent refresh tokens (Google): a response omitting a new one means keep the current one, unlike Jira's rotating tokens.
		expect(refreshed.refreshToken).toBe("1//refresh-x");
	});
});
