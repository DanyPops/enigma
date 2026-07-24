import { describe, expect, it } from "bun:test";
import { loginGitHub, loginGitLab, loginJenkins, loginJiraCloud, loginOidc, type JiraCallbackListener, type OidcFetch } from "../src/login-command.ts";

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("loginGitHub", () => {
	it("prompts with the device code, polls through pending, and returns the token (no discovery — GitHub has none)", async () => {
		let polls = 0;
		const fetchImpl: OidcFetch = async (input) => {
			const url = String(input);
			if (url === "https://github.com/login/device/code") {
				return jsonResponse({ device_code: "d1", user_code: "ABCD-1234", verification_uri: "https://github.com/login/device", expires_in: 900, interval: 1 });
			}
			if (url === "https://github.com/login/oauth/access_token") {
				polls += 1;
				if (polls < 2) return jsonResponse({ error: "authorization_pending" }, 400);
				return jsonResponse({ access_token: "gho_x", token_type: "bearer", scope: "repo" });
			}
			throw new Error(`unexpected fetch: ${url}`);
		};
		let prompted: unknown;
		const token = await loginGitHub({ clientId: "c", fetchImpl, onPrompt: (p) => (prompted = p) });
		expect(prompted).toEqual({ verificationUri: "https://github.com/login/device", userCode: "ABCD-1234" });
		expect(token.accessToken).toBe("gho_x");
		expect(token.scope).toBe("repo");
	});

	it("never expires and issues no refresh token, matching real GitHub OAuth App device-flow behavior", async () => {
		const fetchImpl: OidcFetch = async (input) => {
			const url = String(input);
			if (url === "https://github.com/login/device/code") {
				return jsonResponse({ device_code: "d1", user_code: "ABCD-1234", verification_uri: "https://github.com/login/device", expires_in: 900, interval: 1 });
			}
			return jsonResponse({ access_token: "gho_x", token_type: "bearer" });
		};
		const token = await loginGitHub({ clientId: "c", fetchImpl, onPrompt: () => {} });
		expect(token.refreshToken).toBeUndefined();
		expect(token.expiresAt).toBeUndefined();
	});

	it("surfaces a denied authorization as a real error, not a silent hang", async () => {
		const fetchImpl: OidcFetch = async (input) => {
			const url = String(input);
			if (url === "https://github.com/login/device/code") {
				return jsonResponse({ device_code: "d1", user_code: "X", verification_uri: "https://github.com/login/device", expires_in: 900, interval: 1 });
			}
			return jsonResponse({ error: "access_denied" }, 400);
		};
		await expect(loginGitHub({ clientId: "c", fetchImpl, onPrompt: () => {} })).rejects.toThrow();
	});
});

describe("loginGitLab", () => {
	it("stashes baseUrl/clientId in extra so a later rotate can refresh without separate config, patching the device endpoint GitLab's own discovery omits", async () => {
		let deviceCodeRequested = false;
		const fetchImpl: OidcFetch = async (input) => {
			const url = String(input);
			if (url === "https://gitlab.example.com/.well-known/openid-configuration") {
				return jsonResponse({
					issuer: "https://gitlab.example.com",
					token_endpoint: "https://gitlab.example.com/oauth/token",
					// GitLab's real, confirmed behavior: null even when device_code is supported.
					device_authorization_endpoint: null,
					grant_types_supported: ["authorization_code", "device_code", "refresh_token"],
				});
			}
			if (url === "https://gitlab.example.com/oauth/authorize_device") {
				deviceCodeRequested = true;
				return jsonResponse({ device_code: "d1", user_code: "WXYZ-5678", verification_uri: "https://gitlab.example.com/device", expires_in: 900, interval: 1 });
			}
			if (url === "https://gitlab.example.com/oauth/token") {
				return jsonResponse({ access_token: "glpat-x", refresh_token: "refresh-x", expires_in: 7200, scope: "api", token_type: "bearer" });
			}
			throw new Error(`unexpected fetch: ${url}`);
		};
		const token = await loginGitLab({ baseUrl: "https://gitlab.example.com", clientId: "c", fetchImpl, onPrompt: () => {} });
		expect(deviceCodeRequested).toBe(true);
		expect(token.accessToken).toBe("glpat-x");
		expect(token.refreshToken).toBe("refresh-x");
		expect(token.extra).toEqual({ baseUrl: "https://gitlab.example.com", clientId: "c" });
		expect(token.expiresAt).toBeDefined();
	});

	it("gives a clear, actionable error when OIDC discovery itself fails (instance too old / not reachable)", async () => {
		const fetchImpl: OidcFetch = async () => new Response("", { status: 404 });
		await expect(loginGitLab({ baseUrl: "https://old-gitlab.example.com", clientId: "c", fetchImpl, onPrompt: () => {} })).rejects.toThrow(
			/discovery failed/,
		);
	});

	it("gives a clear, actionable error (not a raw 404) when discovery succeeds but the device grant truly isn't supported", async () => {
		const fetchImpl: OidcFetch = async (input) => {
			const url = String(input);
			if (url === "https://gitlab.example.com/.well-known/openid-configuration") {
				return jsonResponse({ issuer: "https://gitlab.example.com", token_endpoint: "https://gitlab.example.com/oauth/token", device_authorization_endpoint: null });
			}
			return jsonResponse({ error: "Not Found" }, 404);
		};
		await expect(loginGitLab({ baseUrl: "https://gitlab.example.com", clientId: "c", fetchImpl, onPrompt: () => {} })).rejects.toThrow(
			/PKCE fallback is not yet implemented/,
		);
	});
});

describe("loginOidc", () => {
	it("logs in against an arbitrary, generically-discovered OIDC provider with zero backend-specific knowledge", async () => {
		const fetchImpl: OidcFetch = async (input) => {
			const url = String(input);
			if (url === "https://idp.example.com/.well-known/openid-configuration") {
				return jsonResponse({
					issuer: "https://idp.example.com",
					token_endpoint: "https://idp.example.com/token",
					device_authorization_endpoint: "https://idp.example.com/device",
				});
			}
			if (url === "https://idp.example.com/device") {
				return jsonResponse({ device_code: "d1", user_code: "OIDC-0001", verification_uri: "https://idp.example.com/activate", expires_in: 900, interval: 1 });
			}
			if (url === "https://idp.example.com/token") {
				return jsonResponse({ access_token: "generic-token", refresh_token: "generic-refresh", expires_in: 3600, token_type: "bearer" });
			}
			throw new Error(`unexpected fetch: ${url}`);
		};
		let prompted: unknown;
		const token = await loginOidc({ issuerUrl: "https://idp.example.com", clientId: "generic-client", fetchImpl, onPrompt: (p) => (prompted = p) });
		expect(prompted).toEqual({ verificationUri: "https://idp.example.com/activate", userCode: "OIDC-0001" });
		expect(token.accessToken).toBe("generic-token");
		expect(token.extra).toEqual({ issuerUrl: "https://idp.example.com", clientId: "generic-client" });
	});

	it("throws a clear error rather than hanging when the provider doesn't advertise a device_authorization_endpoint at all", async () => {
		const fetchImpl: OidcFetch = async (input) => {
			const url = String(input);
			if (url === "https://idp.example.com/.well-known/openid-configuration") {
				return jsonResponse({ issuer: "https://idp.example.com", token_endpoint: "https://idp.example.com/token", device_authorization_endpoint: null });
			}
			throw new Error(`unexpected fetch: ${url}`);
		};
		await expect(loginOidc({ issuerUrl: "https://idp.example.com", clientId: "c", fetchImpl, onPrompt: () => {} })).rejects.toThrow(
			/does not advertise a device_authorization_endpoint/,
		);
	});
});

describe("loginJiraCloud", () => {
	function tokenExchangeAndSingleSiteFetch(): OidcFetch {
		return async (input) => {
			const url = String(input);
			if (url === "https://auth.atlassian.com/oauth/token") {
				return jsonResponse({ access_token: "jira-at", refresh_token: "jira-rt", expires_in: 3600, scope: "read:jira-work offline_access", token_type: "bearer" });
			}
			if (url === "https://api.atlassian.com/oauth/token/accessible-resources") {
				return jsonResponse([{ id: "cloud-1", name: "My Site", url: "https://my-site.atlassian.net", scopes: ["read:jira-work"] }]);
			}
			throw new Error(`unexpected fetch: ${url}`);
		};
	}

	it("exchanges the authorization code, looks up the cloudId, and stashes everything refresh will need in extra", async () => {
		let authUrl: string | undefined;
		const capturingListener: JiraCallbackListener = {
			redirectUri: "http://127.0.0.1:8976/callback",
			waitForCallback: async () => {
				const state = new URL(authUrl!).searchParams.get("state")!;
				return { code: "auth-code-1", state };
			},
			close: () => {},
		};
		const token = await loginJiraCloud({
			clientId: "jira-client",
			clientSecret: "jira-secret",
			callbackPort: 8976,
			listener: capturingListener,
			fetchImpl: tokenExchangeAndSingleSiteFetch(),
			onAuthUrl: (url) => (authUrl = url),
		});
		expect(authUrl).toContain("https://auth.atlassian.com/authorize?");
		expect(authUrl).toContain("prompt=consent");
		expect(authUrl).toContain("audience=api.atlassian.com");
		expect(token.accessToken).toBe("jira-at");
		expect(token.refreshToken).toBe("jira-rt");
		expect(token.extra).toEqual({ clientId: "jira-client", clientSecret: "jira-secret", cloudId: "cloud-1", siteUrl: "https://my-site.atlassian.net" });
	});

	it("rejects a callback whose state does not match — possible CSRF", async () => {
		const listener: JiraCallbackListener = { redirectUri: "http://127.0.0.1:8976/callback", waitForCallback: async () => ({ code: "c", state: "wrong-state" }), close: () => {} };
		await expect(
			loginJiraCloud({ clientId: "c", clientSecret: "s", callbackPort: 8976, listener, fetchImpl: async () => new Response("", { status: 500 }), onAuthUrl: () => {} }),
		).rejects.toThrow(/state mismatch/);
	});

	it("surfaces an authorization error from the callback (e.g. the user denied consent) as a real error", async () => {
		const listener: JiraCallbackListener = { redirectUri: "http://127.0.0.1:8976/callback", waitForCallback: async () => ({ error: "access_denied" }), close: () => {} };
		await expect(
			loginJiraCloud({ clientId: "c", clientSecret: "s", callbackPort: 8976, listener, fetchImpl: async () => new Response("", { status: 500 }), onAuthUrl: () => {} }),
		).rejects.toThrow(/access_denied/);
	});

	it("throws a clear, actionable error when accessible-resources returns multiple sites and none is disambiguated", async () => {
		let capturedState = "";
		const listener: JiraCallbackListener = {
			redirectUri: "http://127.0.0.1:8976/callback",
			waitForCallback: async () => ({ code: "c", state: capturedState }),
			close: () => {},
		};
		const fetchImpl: OidcFetch = async (input) => {
			const url = String(input);
			if (url === "https://auth.atlassian.com/oauth/token") return jsonResponse({ access_token: "at", expires_in: 3600, token_type: "bearer" });
			if (url === "https://api.atlassian.com/oauth/token/accessible-resources") {
				return jsonResponse([
					{ id: "cloud-1", name: "Site One", url: "https://site-one.atlassian.net", scopes: [] },
					{ id: "cloud-2", name: "Site Two", url: "https://site-two.atlassian.net", scopes: [] },
				]);
			}
			throw new Error(`unexpected fetch: ${url}`);
		};
		await expect(
			loginJiraCloud({
				clientId: "c",
				clientSecret: "s",
				callbackPort: 8976,
				listener,
				fetchImpl,
				onAuthUrl: (url) => {
					capturedState = new URL(url).searchParams.get("state")!;
				},
			}),
		).rejects.toThrow(/multiple sites/);
	});

	it("resolves the right site when disambiguated via the site option", async () => {
		let capturedState = "";
		const listener: JiraCallbackListener = {
			redirectUri: "http://127.0.0.1:8976/callback",
			waitForCallback: async () => ({ code: "c", state: capturedState }),
			close: () => {},
		};
		const fetchImpl: OidcFetch = async (input) => {
			const url = String(input);
			if (url === "https://auth.atlassian.com/oauth/token") return jsonResponse({ access_token: "at", expires_in: 3600, token_type: "bearer" });
			if (url === "https://api.atlassian.com/oauth/token/accessible-resources") {
				return jsonResponse([
					{ id: "cloud-1", name: "Site One", url: "https://site-one.atlassian.net", scopes: [] },
					{ id: "cloud-2", name: "Site Two", url: "https://site-two.atlassian.net", scopes: [] },
				]);
			}
			throw new Error(`unexpected fetch: ${url}`);
		};
		const token = await loginJiraCloud({
			clientId: "c",
			clientSecret: "s",
			callbackPort: 8976,
			site: "site-two",
			listener,
			fetchImpl,
			onAuthUrl: (url) => {
				capturedState = new URL(url).searchParams.get("state")!;
			},
		});
		expect(token.extra?.cloudId).toBe("cloud-2");
		expect(token.extra?.siteUrl).toBe("https://site-two.atlassian.net");
	});
});

describe("loginJenkins", () => {
	it("wraps the static username+API-token pair with no network call at all", () => {
		const token = loginJenkins({ url: "https://jenkins.example.com", username: "bot", apiToken: "tok-123" });
		expect(token).toEqual({ accessToken: "tok-123", extra: { url: "https://jenkins.example.com", username: "bot" } });
	});
});
