import { describe, expect, it } from "bun:test";
import { defaultEnvVarName, mapCredentialToEnv } from "../src/backend-env-mapping.ts";

describe("mapCredentialToEnv", () => {
	it("maps github to GITHUB_TOKEN only", () => {
		expect(mapCredentialToEnv("github", { accessToken: "gh-x" })).toEqual({ GITHUB_TOKEN: "gh-x" });
	});

	it("maps gitlab to GITLAB_TOKEN plus GITLAB_URL when the credential carries a baseUrl", () => {
		expect(mapCredentialToEnv("gitlab", { accessToken: "gl-x", extra: { baseUrl: "https://gitlab.example.com" } })).toEqual({
			GITLAB_TOKEN: "gl-x",
			GITLAB_URL: "https://gitlab.example.com",
		});
		expect(mapCredentialToEnv("gitlab", { accessToken: "gl-x" })).toEqual({ GITLAB_TOKEN: "gl-x" });
	});

	it("maps jenkins to its three-variable shape from extra fields", () => {
		expect(mapCredentialToEnv("jenkins", { accessToken: "tok", extra: { username: "bot", url: "https://jenkins.example.com" } })).toEqual({
			JENKINS_API_TOKEN: "tok",
			JENKINS_USER: "bot",
			JENKINS_URL: "https://jenkins.example.com",
		});
	});

	it("maps jira to JIRA_API_TOKEN plus JIRA_URL when the credential carries a siteUrl — matching Tickets' actual config.ts expectations, not a bare JIRA_TOKEN", () => {
		expect(mapCredentialToEnv("jira", { accessToken: "jira-x", extra: { siteUrl: "https://my-site.atlassian.net" } })).toEqual({
			JIRA_API_TOKEN: "jira-x",
			JIRA_URL: "https://my-site.atlassian.net",
		});
		expect(mapCredentialToEnv("jira", { accessToken: "jira-x" })).toEqual({ JIRA_API_TOKEN: "jira-x" });
	});

	it("maps google to GOOGLE_ACCESS_TOKEN — deliberately not GOOGLE_APPLICATION_CREDENTIALS, since this is a raw bearer token, not an ADC file path", () => {
		expect(mapCredentialToEnv("google", { accessToken: "ya29.x" })).toEqual({ GOOGLE_ACCESS_TOKEN: "ya29.x" });
	});

	it("maps an arbitrary/generic backend to its operator-chosen envVarName, stashed at login time", () => {
		expect(mapCredentialToEnv("my-company-sso", { accessToken: "x", extra: { envVarName: "CUSTOM_SSO_TOKEN" } })).toEqual({ CUSTOM_SSO_TOKEN: "x" });
	});

	it("falls back to a sanitized default env var name for a generic backend when the operator didn't supply one", () => {
		expect(mapCredentialToEnv("my-company-sso", { accessToken: "x" })).toEqual({ MY_COMPANY_SSO_TOKEN: "x" });
	});
});

describe("defaultEnvVarName", () => {
	it("uppercases and sanitizes an arbitrary backend name into a _TOKEN suffixed var name", () => {
		expect(defaultEnvVarName("my-company-sso")).toBe("MY_COMPANY_SSO_TOKEN");
		expect(defaultEnvVarName("weird.name!!")).toBe("WEIRD_NAME_TOKEN");
		expect(defaultEnvVarName("--leading-trailing--")).toBe("LEADING_TRAILING_TOKEN");
	});
});
