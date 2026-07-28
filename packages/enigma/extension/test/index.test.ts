import { describe, expect, it } from "bun:test";
import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import type { RefreshableAccessToken } from "@danypops/daemon-kit/vault";
import type { EnigmaAdminClient, VaultCredential } from "../../src/client.ts";
import type { CredentialVault } from "../../src/credential-vault.ts";
import { LOGIN_ACTION, type LoginFns, loadStatuses, runSecretsCommand, type PickFromList } from "../src/index.ts";

const REAL_LOOKING_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";
const FIXTURE_JENKINS_TOKEN = "jenkins-fixture-token-not-real";
const FIXTURE_OAUTH_TOKEN = "fixture-oauth-token-not-real";

function fakeVaultClient(records: Record<string, VaultCredential>): EnigmaAdminClient & { rotated: string[]; revoked: string[] } {
	const client = {
		rotated: [] as string[],
		revoked: [] as string[],
		listCredentialKeys: async () => Object.keys(records),
		getCredentials: async (backend: string) => records[backend],
		rotateCredential: async (backend: string) => {
			client.rotated.push(backend);
		},
		revokeCredential: async (backend: string) => {
			client.revoked.push(backend);
			delete records[backend];
		},
		health: async () => ({ ok: true, version: "test" }),
	};
	return client;
}

function fakeCtx(overrides: { confirm?: boolean; hasUI?: boolean; inputs?: Array<string | undefined> } = {}): {
	ctx: ExtensionCommandContext;
	notifications: Array<{ text: string; level: string }>;
	inputPrompts: string[];
} {
	const notifications: Array<{ text: string; level: string }> = [];
	const inputPrompts: string[] = [];
	const inputQueue = [...(overrides.inputs ?? [])];
	const ctx = {
		hasUI: overrides.hasUI ?? true,
		mode: "tui",
		ui: {
			notify: (text: string, level: string) => {
				notifications.push({ text, level });
			},
			confirm: async () => overrides.confirm ?? true,
			input: async (title: string) => {
				inputPrompts.push(title);
				return inputQueue.length > 0 ? inputQueue.shift() : undefined;
			},
		},
	} as unknown as ExtensionCommandContext;
	return { ctx, notifications, inputPrompts };
}

/** Scripted `pick`: returns each queued value in order, then null forever after. */
function scriptedPick(...values: Array<string | null>): PickFromList {
	const queue = [...values];
	return async () => (queue.length > 0 ? queue.shift()! : null);
}

function fakeVault(): CredentialVault & { saved: Array<{ backend: string; token: RefreshableAccessToken }> } {
	const saved: Array<{ backend: string; token: RefreshableAccessToken }> = [];
	return {
		saved,
		get: () => undefined,
		save: (backend: string, token: RefreshableAccessToken) => {
			saved.push({ backend, token });
		},
		delete: () => undefined,
		listBackends: () => [],
	};
}

/** Never actually launches anything; records what it was asked to open. */
function fakeBrowserOpener(succeeds = true): { open: (url: string) => Promise<unknown>; opened: string[] } {
	const opened: string[] = [];
	return {
		opened,
		open: async (url: string) => {
			opened.push(url);
			if (!succeeds) throw new Error("no browser available");
		},
	};
}

function fakeLoginFns(overrides: Partial<LoginFns> = {}): LoginFns & { calls: Record<string, unknown[]> } {
	const calls: Record<string, unknown[]> = { loginApiKey: [], loginGitHub: [], loginGitLab: [], loginGoogle: [], loginJenkins: [], loginJiraCloud: [], loginOidc: [] };
	return {
		calls,
		loginApiKey: (opts) => {
			calls.loginApiKey!.push(opts);
			return { accessToken: opts.value, extra: { envVarName: opts.envVarName } };
		},
		loginGitHub: async (opts) => {
			calls.loginGitHub!.push(opts);
			opts.onPrompt({ verificationUri: "https://github.com/login/device", userCode: "ABCD-1234" });
			return { accessToken: FIXTURE_OAUTH_TOKEN };
		},
		loginGitLab: async (opts) => {
			calls.loginGitLab!.push(opts);
			opts.onPrompt({ verificationUri: "https://gitlab.example.com/device", userCode: "WXYZ-5678" });
			return { accessToken: FIXTURE_OAUTH_TOKEN };
		},
		loginGoogle: async (opts) => {
			calls.loginGoogle!.push(opts);
			opts.onPrompt({ verificationUri: "https://google.com/device", userCode: "GOOG-0001" });
			return { accessToken: FIXTURE_OAUTH_TOKEN };
		},
		loginJenkins: (opts) => {
			calls.loginJenkins!.push(opts);
			return { accessToken: FIXTURE_JENKINS_TOKEN, extra: { url: opts.url, username: opts.username } };
		},
		loginJiraCloud: async (opts) => {
			calls.loginJiraCloud!.push(opts);
			opts.onAuthUrl("https://auth.atlassian.com/authorize?fixture=1");
			return { accessToken: FIXTURE_OAUTH_TOKEN };
		},
		loginOidc: async (opts) => {
			calls.loginOidc!.push(opts);
			opts.onPrompt({ verificationUri: "https://sso.example.com/device", userCode: "OIDC-9999" });
			return { accessToken: FIXTURE_OAUTH_TOKEN };
		},
		...overrides,
	} as LoginFns & { calls: Record<string, unknown[]> };
}

describe("loadStatuses", () => {
	it("redacts every configured backend, never surfacing the real token", async () => {
		const client = fakeVaultClient({
			github: { accessToken: REAL_LOOKING_TOKEN, scope: "repo" },
			jenkins: { accessToken: REAL_LOOKING_TOKEN, extra: { url: "https://jenkins.example.com" } },
		});
		const statuses = await loadStatuses(client);
		const serialized = JSON.stringify(statuses);
		expect(serialized).not.toContain(REAL_LOOKING_TOKEN);
		expect(statuses).toEqual([
			{ backend: "github", configured: true, scope: "repo" },
			{ backend: "jenkins", configured: true },
		]);
	});
});

describe("runSecretsCommand", () => {
	it("reports a clear error and stops when the daemon isn't running, without throwing", async () => {
		const { ctx, notifications } = fakeCtx();
		const connect = () => {
			throw new Error("Enigma daemon is not running; run `enigma serve` or `enigma supervisor`.");
		};
		await runSecretsCommand(ctx, connect, scriptedPick());
		expect(notifications).toHaveLength(1);
		expect(notifications[0]?.level).toBe("error");
		expect(notifications[0]?.text).toContain("not running");
	});

	it("reports a clear error when the vault is unreachable mid-session", async () => {
		const { ctx, notifications } = fakeCtx();
		const client: EnigmaAdminClient = {
			listCredentialKeys: async () => {
				throw new Error("vault request failed: GET /keys: HTTP 500");
			},
			getCredentials: async () => undefined,
			rotateCredential: async () => undefined,
			revokeCredential: async () => undefined,
			health: async () => ({ ok: true, version: "test" }),
		};
		await runSecretsCommand(ctx, () => client, scriptedPick());
		expect(notifications[0]?.level).toBe("error");
		expect(notifications[0]?.text).toContain("Could not reach the Enigma vault");
	});

	it("tells the user to log in when no backends are configured yet", async () => {
		const { ctx, notifications } = fakeCtx();
		const client = fakeVaultClient({});
		await runSecretsCommand(ctx, () => client, scriptedPick());
		expect(notifications[0]?.text).toContain("enigma login");
	});

	it("rotates the selected backend and reports success, never the token", async () => {
		const { ctx, notifications } = fakeCtx();
		const client = fakeVaultClient({ github: { accessToken: REAL_LOOKING_TOKEN } });
		// pick: 1) choose "github" from the backend list, 2) choose "rotate" from its action menu,
		// 3) "back" out of the action menu, 4) close the backend list.
		await runSecretsCommand(ctx, () => client, scriptedPick("github", "rotate", "back", null));
		expect(client.rotated).toEqual(["github"]);
		expect(notifications.some((n) => n.text === "github: rotated." && n.level === "info")).toBe(true);
		expect(JSON.stringify(notifications)).not.toContain(REAL_LOOKING_TOKEN);
	});

	it("surfaces a rotate failure without crashing or leaking secret-shaped detail", async () => {
		const { ctx, notifications } = fakeCtx();
		const client = fakeVaultClient({ jenkins: { accessToken: REAL_LOOKING_TOKEN } });
		client.rotateCredential = async () => {
			throw new Error("backend \"jenkins\" has no refresh function configured");
		};
		await runSecretsCommand(ctx, () => client, scriptedPick("jenkins", "rotate", "back", null));
		const failure = notifications.find((n) => n.level === "error");
		expect(failure?.text).toContain("rotate failed");
		expect(failure?.text).toContain("no refresh function configured");
	});

	it("revokes only after explicit confirmation", async () => {
		const { ctx, notifications } = fakeCtx({ confirm: false });
		const client = fakeVaultClient({ gitlab: { accessToken: REAL_LOOKING_TOKEN } });
		// Declining the confirm dialog must not revoke; "back" then exits the (still-configured) backend's menu.
		await runSecretsCommand(ctx, () => client, scriptedPick("gitlab", "revoke", "back", null));
		expect(client.revoked).toEqual([]);
		expect(notifications.some((n) => n.text.includes("revoked"))).toBe(false);
	});

	it("revokes when confirmed and reports success", async () => {
		const { ctx, notifications } = fakeCtx({ confirm: true });
		const client = fakeVaultClient({ gitlab: { accessToken: REAL_LOOKING_TOKEN } });
		await runSecretsCommand(ctx, () => client, scriptedPick("gitlab", "revoke", null));
		expect(client.revoked).toEqual(["gitlab"]);
		expect(notifications.some((n) => n.text === "gitlab: revoked." && n.level === "info")).toBe(true);
	});

	it("always offers a login entry alongside configured backends", async () => {
		const { ctx } = fakeCtx();
		const client = fakeVaultClient({ github: { accessToken: REAL_LOOKING_TOKEN } });
		let seenItems: string[] = [];
		const pick: PickFromList = async (_ctx, _title, items) => {
			seenItems = items.map((item) => item.label);
			return null;
		};
		await runSecretsCommand(ctx, () => client, pick);
		expect(seenItems).toContain("+ Log in a backend");
	});
});

describe("runSecretsCommand > login", () => {
	it("logs in a device-flow backend (github), relays the code, opens a browser to the verification URL, and saves the token without ever exposing it", async () => {
		const { ctx, notifications } = fakeCtx();
		const client = fakeVaultClient({});
		const vault = fakeVault();
		const loginFns = fakeLoginFns();
		const browser = fakeBrowserOpener();
		process.env.GITHUB_CLIENT_ID = "fixture-client-id";
		try {
			await runSecretsCommand(ctx, () => client, scriptedPick(LOGIN_ACTION, "github", null), () => vault, loginFns, browser.open);
		} finally {
			delete process.env.GITHUB_CLIENT_ID;
		}
		expect(vault.saved).toEqual([{ backend: "github", token: { accessToken: FIXTURE_OAUTH_TOKEN } }]);
		expect(notifications.some((n) => n.text.includes("ABCD-1234"))).toBe(true);
		expect(notifications.some((n) => n.text === "GitHub login complete.")).toBe(true);
		expect(browser.opened).toEqual(["https://github.com/login/device"]);
		expect(JSON.stringify(notifications)).not.toContain(FIXTURE_OAUTH_TOKEN);
	});

	it("never fails a login just because the browser couldn't be opened, and says so", async () => {
		const { ctx, notifications } = fakeCtx();
		const client = fakeVaultClient({});
		const vault = fakeVault();
		const loginFns = fakeLoginFns();
		const browser = fakeBrowserOpener(false);
		process.env.GITHUB_CLIENT_ID = "fixture-client-id";
		try {
			await runSecretsCommand(ctx, () => client, scriptedPick(LOGIN_ACTION, "github", null), () => vault, loginFns, browser.open);
			// The browser-open failure is reported asynchronously (fire-and-forget); give it a tick.
			await new Promise((resolve) => setTimeout(resolve, 0));
		} finally {
			delete process.env.GITHUB_CLIENT_ID;
		}
		expect(vault.saved).toEqual([{ backend: "github", token: { accessToken: FIXTURE_OAUTH_TOKEN } }]);
		expect(notifications.some((n) => n.text === "GitHub login complete.")).toBe(true);
		expect(notifications.some((n) => n.level === "warning" && n.text.includes("open the URL above manually"))).toBe(true);
	});

	it("refuses to log in a backend when its required env vars are missing, without calling the login function", async () => {
		const { ctx, notifications } = fakeCtx();
		const client = fakeVaultClient({});
		const vault = fakeVault();
		const loginFns = fakeLoginFns();
		delete process.env.GITLAB_URL;
		delete process.env.GITLAB_CLIENT_ID;
		await runSecretsCommand(ctx, () => client, scriptedPick(LOGIN_ACTION, "gitlab", null), () => vault, loginFns);
		expect(loginFns.calls.loginGitLab).toEqual([]);
		expect(vault.saved).toEqual([]);
		const failure = notifications.find((n) => n.level === "error");
		expect(failure?.text).toContain("GITLAB_URL and GITLAB_CLIENT_ID required");
	});

	it("logs in Jenkins' static token from env with no device-flow prompt, never exposing the token", async () => {
		const { ctx, notifications } = fakeCtx();
		const client = fakeVaultClient({});
		const vault = fakeVault();
		const loginFns = fakeLoginFns();
		process.env.JENKINS_URL = "https://jenkins.example.com";
		process.env.JENKINS_USER = "demo";
		process.env.JENKINS_API_TOKEN = FIXTURE_JENKINS_TOKEN;
		try {
			await runSecretsCommand(ctx, () => client, scriptedPick(LOGIN_ACTION, "jenkins", null), () => vault, loginFns);
		} finally {
			delete process.env.JENKINS_URL;
			delete process.env.JENKINS_USER;
			delete process.env.JENKINS_API_TOKEN;
		}
		expect(vault.saved).toEqual([{ backend: "jenkins", token: { accessToken: FIXTURE_JENKINS_TOKEN, extra: { url: "https://jenkins.example.com", username: "demo" } } }]);
		expect(notifications.some((n) => n.text === "Jenkins credentials saved.")).toBe(true);
		expect(JSON.stringify(notifications)).not.toContain(FIXTURE_JENKINS_TOKEN);
	});

	it("logs in a static API key from ENIGMA_APIKEY_VALUE, never typing the key itself into a prompt", async () => {
		const { ctx, notifications, inputPrompts } = fakeCtx({ inputs: ["brave", "BRAVE_SEARCH_API_KEY"] });
		const client = fakeVaultClient({});
		const vault = fakeVault();
		const loginFns = fakeLoginFns();
		process.env.ENIGMA_APIKEY_VALUE = "brave-key-fixture";
		try {
			await runSecretsCommand(ctx, () => client, scriptedPick(LOGIN_ACTION, "apikey", null), () => vault, loginFns);
		} finally {
			delete process.env.ENIGMA_APIKEY_VALUE;
		}
		expect(inputPrompts).toEqual(["Backend name", "Env var name"]);
		expect(vault.saved).toEqual([{ backend: "brave", token: { accessToken: "brave-key-fixture", extra: { envVarName: "BRAVE_SEARCH_API_KEY" } } }]);
		expect(notifications.some((n) => n.text === 'API key saved for backend "brave".')).toBe(true);
		expect(JSON.stringify(notifications)).not.toContain("brave-key-fixture");
	});

	it("opens the interactive registration form (never ctx.ui.input) when ENIGMA_APIKEY_VALUE isn't set, and saves its result", async () => {
		const { ctx, notifications, inputPrompts } = fakeCtx();
		const client = fakeVaultClient({});
		const vault = fakeVault();
		const loginFns = fakeLoginFns();
		const promptApiKey = async () => ({ name: "exa", envVar: "EXA_API_KEY", value: "exa-key-fixture" });
		await runSecretsCommand(ctx, () => client, scriptedPick(LOGIN_ACTION, "apikey", null), () => vault, loginFns, undefined, promptApiKey);
		expect(inputPrompts).toEqual([]); // the value never goes through the plain, unmasked ctx.ui.input()
		expect(vault.saved).toEqual([{ backend: "exa", token: { accessToken: "exa-key-fixture", extra: { envVarName: "EXA_API_KEY" } } }]);
		expect(notifications.some((n) => n.text === 'API key saved for backend "exa".')).toBe(true);
		expect(JSON.stringify(notifications)).not.toContain("exa-key-fixture");
	});

	it("does nothing and reports no error when the registration form is canceled", async () => {
		const { ctx, notifications } = fakeCtx();
		const client = fakeVaultClient({});
		const vault = fakeVault();
		const loginFns = fakeLoginFns();
		const promptApiKey = async () => null;
		await runSecretsCommand(ctx, () => client, scriptedPick(LOGIN_ACTION, "apikey", null), () => vault, loginFns, undefined, promptApiKey);
		expect(vault.saved).toEqual([]);
		expect(loginFns.calls.loginApiKey).toEqual([]);
		expect(notifications.some((n) => n.level === "error")).toBe(false);
	});

	it("collects OIDC's required fields interactively and saves under the given backend name", async () => {
		const { ctx, notifications, inputPrompts } = fakeCtx({ inputs: ["my-company-sso", "https://sso.example.com", "fixture-client-id", undefined, undefined] });
		const client = fakeVaultClient({});
		const vault = fakeVault();
		const loginFns = fakeLoginFns();
		await runSecretsCommand(ctx, () => client, scriptedPick(LOGIN_ACTION, "oidc", null), () => vault, loginFns, fakeBrowserOpener().open);
		expect(inputPrompts).toEqual(["Backend name", "Issuer URL", "Client ID", "Scope (optional)", "Env var name (optional)"]);
		expect(vault.saved).toEqual([{ backend: "my-company-sso", token: { accessToken: FIXTURE_OAUTH_TOKEN, extra: { envVarName: "MY_COMPANY_SSO_TOKEN" } } }]);
		expect(notifications.some((n) => n.text.includes("OIDC-9999"))).toBe(true);
		expect(JSON.stringify(notifications)).not.toContain(FIXTURE_OAUTH_TOKEN);
	});

	it("rejects an OIDC login left with a blank required field, without calling the login function", async () => {
		const { ctx, notifications } = fakeCtx({ inputs: [undefined] });
		const client = fakeVaultClient({});
		const vault = fakeVault();
		const loginFns = fakeLoginFns();
		await runSecretsCommand(ctx, () => client, scriptedPick(LOGIN_ACTION, "oidc", null), () => vault, loginFns);
		expect(loginFns.calls.loginOidc).toEqual([]);
		expect(vault.saved).toEqual([]);
		expect(notifications.some((n) => n.level === "error" && n.text.includes("backend name is required"))).toBe(true);
	});

	it("refuses interactive login outside a UI session instead of hanging on a dialog that can't render", async () => {
		const { ctx, notifications } = fakeCtx({ hasUI: false });
		const client = fakeVaultClient({});
		const vault = fakeVault();
		const loginFns = fakeLoginFns();
		await runSecretsCommand(ctx, () => client, scriptedPick(LOGIN_ACTION, "github", null), () => vault, loginFns);
		expect(loginFns.calls.loginGitHub).toEqual([]);
		expect(vault.saved).toEqual([]);
		expect(notifications.some((n) => n.level === "error" && n.text.includes("run `enigma login` from a terminal"))).toBe(true);
	});

	it("saves a second account for the same platform under an alias when one is given", async () => {
		const { ctx, notifications, inputPrompts } = fakeCtx({ inputs: ["github-work"] });
		const client = fakeVaultClient({});
		const vault = fakeVault();
		const loginFns = fakeLoginFns();
		process.env.GITHUB_CLIENT_ID = "fixture-client-id";
		try {
			await runSecretsCommand(ctx, () => client, scriptedPick(LOGIN_ACTION, "github", null), () => vault, loginFns, fakeBrowserOpener().open);
		} finally {
			delete process.env.GITHUB_CLIENT_ID;
		}
		expect(inputPrompts).toEqual(["Save as (optional, for a second account)"]);
		expect(vault.saved).toEqual([{ backend: "github-work", token: { accessToken: FIXTURE_OAUTH_TOKEN } }]);
		expect(notifications.some((n) => n.text === 'GitHub login complete (stored as "github-work").')).toBe(true);
	});

	it("defaults to the platform's literal name when no alias is given", async () => {
		const { ctx, notifications } = fakeCtx({ inputs: [undefined] });
		const client = fakeVaultClient({});
		const vault = fakeVault();
		const loginFns = fakeLoginFns();
		process.env.GITHUB_CLIENT_ID = "fixture-client-id";
		try {
			await runSecretsCommand(ctx, () => client, scriptedPick(LOGIN_ACTION, "github", null), () => vault, loginFns, fakeBrowserOpener().open);
		} finally {
			delete process.env.GITHUB_CLIENT_ID;
		}
		expect(vault.saved).toEqual([{ backend: "github", token: { accessToken: FIXTURE_OAUTH_TOKEN } }]);
		expect(notifications.some((n) => n.text === "GitHub login complete.")).toBe(true);
	});

	it("backing out of the backend-kind menu does nothing", async () => {
		const { ctx } = fakeCtx();
		const client = fakeVaultClient({});
		const vault = fakeVault();
		const loginFns = fakeLoginFns();
		await runSecretsCommand(ctx, () => client, scriptedPick(LOGIN_ACTION, "back", null), () => vault, loginFns);
		expect(vault.saved).toEqual([]);
		const anyCalled = Object.values(loginFns.calls).some((c) => c.length > 0);
		expect(anyCalled).toBe(false);
	});
});
