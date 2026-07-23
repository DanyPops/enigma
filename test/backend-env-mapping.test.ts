import { describe, expect, it } from "bun:test";
import { mapCredentialToEnv } from "../src/backend-env-mapping.ts";

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

	it("maps jira to JIRA_TOKEN only", () => {
		expect(mapCredentialToEnv("jira", { accessToken: "jira-x" })).toEqual({ JIRA_TOKEN: "jira-x" });
	});

	it("returns an empty mapping for an unknown backend rather than throwing", () => {
		expect(mapCredentialToEnv("unknown-backend", { accessToken: "x" })).toEqual({});
	});
});
