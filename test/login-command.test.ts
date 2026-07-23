import { describe, expect, it } from "bun:test";
import type { FetchLike } from "@danypops/daemon-kit/vault";
import { loginGitHub, loginGitLab, loginJenkins } from "../src/login-command.ts";

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

const noSleep = async () => {};

describe("loginGitHub", () => {
	it("prompts with the device code, polls through pending, and returns the token", async () => {
		let polls = 0;
		const fetchImpl: FetchLike = async (url) => {
			if (url === "https://github.com/login/device/code") {
				return jsonResponse({ device_code: "d1", user_code: "ABCD-1234", verification_uri: "https://github.com/login/device", expires_in: 900, interval: 5 });
			}
			polls += 1;
			if (polls < 2) return jsonResponse({ error: "authorization_pending" });
			return jsonResponse({ access_token: "gho_x", scope: "repo" });
		};
		let prompted: unknown;
		const token = await loginGitHub({ clientId: "c", fetchImpl, sleepImpl: noSleep, onPrompt: (p) => (prompted = p) });
		expect(prompted).toEqual({ verificationUri: "https://github.com/login/device", userCode: "ABCD-1234" });
		expect(token).toEqual({ accessToken: "gho_x", scope: "repo" });
	});

	it("never expires and issues no refresh token, matching real GitHub OAuth App device-flow behavior", async () => {
		const fetchImpl: FetchLike = async (url) => {
			if (url === "https://github.com/login/device/code") {
				return jsonResponse({ device_code: "d1", user_code: "ABCD-1234", verification_uri: "https://github.com/login/device", expires_in: 900, interval: 5 });
			}
			return jsonResponse({ access_token: "gho_x" });
		};
		const token = await loginGitHub({ clientId: "c", fetchImpl, sleepImpl: noSleep, onPrompt: () => {} });
		expect(token.refreshToken).toBeUndefined();
		expect(token.expiresAt).toBeUndefined();
	});

	it("throws a clear error when the user denies the authorization", async () => {
		const fetchImpl: FetchLike = async (url) => {
			if (url === "https://github.com/login/device/code") {
				return jsonResponse({ device_code: "d1", user_code: "X", verification_uri: "https://github.com/login/device", expires_in: 900, interval: 5 });
			}
			return jsonResponse({ error: "access_denied" });
		};
		await expect(loginGitHub({ clientId: "c", fetchImpl, sleepImpl: noSleep, onPrompt: () => {} })).rejects.toThrow(/denied/);
	});
});

describe("loginGitLab", () => {
	it("stashes baseUrl/clientId in extra so a later rotate can refresh without separate config", async () => {
		const fetchImpl: FetchLike = async (url) => {
			if (url === "https://gitlab.example.com/oauth/authorize_device") {
				return jsonResponse({ device_code: "d1", user_code: "WXYZ-5678", verification_uri: "https://gitlab.example.com/device", expires_in: 900, interval: 5 });
			}
			return jsonResponse({ access_token: "glpat-x", refresh_token: "refresh-x", expires_in: 7200, scope: "api" });
		};
		const token = await loginGitLab({ baseUrl: "https://gitlab.example.com", clientId: "c", fetchImpl, sleepImpl: noSleep, onPrompt: () => {} });
		expect(token.accessToken).toBe("glpat-x");
		expect(token.refreshToken).toBe("refresh-x");
		expect(token.extra).toEqual({ baseUrl: "https://gitlab.example.com", clientId: "c" });
		expect(token.expiresAt).toBeDefined();
	});

	it("gives a clear, actionable error (not a raw HTTP failure) when the instance has no device grant support", async () => {
		const fetchImpl: FetchLike = async () => new Response("", { status: 404 });
		await expect(loginGitLab({ baseUrl: "https://old-gitlab.example.com", clientId: "c", fetchImpl, sleepImpl: noSleep, onPrompt: () => {} })).rejects.toThrow(
			/PKCE fallback is not yet implemented/,
		);
	});
});

describe("loginJenkins", () => {
	it("wraps the static username+API-token pair with no network call at all", () => {
		const token = loginJenkins({ url: "https://jenkins.example.com", username: "bot", apiToken: "tok-123" });
		expect(token).toEqual({ accessToken: "tok-123", extra: { url: "https://jenkins.example.com", username: "bot" } });
	});
});
