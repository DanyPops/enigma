import { describe, expect, it } from "bun:test";
import type { VaultCredential } from "../../src/client.ts";
import { describeCredentialStatus, redactCredentialStatus } from "../src/redact.ts";

const REAL_LOOKING_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";

describe("redactCredentialStatus", () => {
	it("never includes accessToken, refreshToken, or extra even when present on the source record", () => {
		const credential: VaultCredential = {
			accessToken: REAL_LOOKING_TOKEN,
			refreshToken: "refresh-secret-value",
			expiresAt: "2026-01-01T00:00:00.000Z",
			scope: "repo",
			extra: { clientSecret: "another-secret" },
		};
		const status = redactCredentialStatus("github", credential);
		const serialized = JSON.stringify(status);
		expect(serialized).not.toContain(REAL_LOOKING_TOKEN);
		expect(serialized).not.toContain("refresh-secret-value");
		expect(serialized).not.toContain("another-secret");
		expect(status).toEqual({ backend: "github", configured: true, expiresAt: "2026-01-01T00:00:00.000Z", scope: "repo" });
	});

	it("reports not-configured for an absent credential without fabricating fields", () => {
		expect(redactCredentialStatus("gitlab", undefined)).toEqual({ backend: "gitlab", configured: false });
	});

	it("omits expiresAt/scope entirely when the source record doesn't have them, rather than emitting undefined", () => {
		const status = redactCredentialStatus("jenkins", { accessToken: REAL_LOOKING_TOKEN });
		expect(Object.keys(status).sort()).toEqual(["backend", "configured"]);
	});
});

describe("describeCredentialStatus", () => {
	it("describes an unconfigured backend plainly", () => {
		expect(describeCredentialStatus({ backend: "gitlab", configured: false })).toBe("not configured");
	});

	it("describes a non-expiring credential", () => {
		expect(describeCredentialStatus({ backend: "github", configured: true })).toBe("no expiry");
	});

	it("describes an expired credential distinctly from one with time remaining", () => {
		const past = new Date(Date.now() - 60_000).toISOString();
		expect(describeCredentialStatus({ backend: "jira", configured: true, expiresAt: past })).toBe("expired");
	});

	it("includes scope when present", () => {
		const future = new Date(Date.now() + 3 * 60 * 60 * 1000).toISOString();
		expect(describeCredentialStatus({ backend: "github", configured: true, expiresAt: future, scope: "repo" })).toContain("scope: repo");
	});
});
