import { describe, expect, it } from "bun:test";
import { loginGitHub, loginGitLab, loginJenkins, loginOidc, type OidcFetch } from "../src/login-command.ts";

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

describe("loginJenkins", () => {
	it("wraps the static username+API-token pair with no network call at all", () => {
		const token = loginJenkins({ url: "https://jenkins.example.com", username: "bot", apiToken: "tok-123" });
		expect(token).toEqual({ accessToken: "tok-123", extra: { url: "https://jenkins.example.com", username: "bot" } });
	});
});
