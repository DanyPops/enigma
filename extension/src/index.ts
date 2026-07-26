/**
 * pi-enigma: `/secrets` command for interactive vault management from inside
 * Pi. Human-driven only -- no LLM-callable tool here. Talks to the same
 * running `enigma serve`/`enigma supervisor` daemon the CLI does, via the
 * same VaultClient daemon-kit already ships; this lives in enigma's own
 * package (not a separate one depending on it over npm), so importing
 * ../../src/client.ts directly is a plain relative TypeScript import, not a
 * cross-package boundary jiti would need to transpile through node_modules --
 * confirmed safe by @danypops/jittor's own extension/src/service-client.ts,
 * which does exactly this against its own daemon.
 *
 * Never surfaces accessToken/refreshToken/extra: every value shown here comes
 * from redactCredentialStatus's explicit allow-list, per the standing rule
 * "Enigma Pi extension: never expose decrypted credential material to the LLM".
 */
import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { DynamicBorder, getSelectListTheme } from "@earendil-works/pi-coding-agent";
import { Container, type SelectItem, SelectList, Text } from "@earendil-works/pi-tui";
import type { VaultClient } from "@danypops/daemon-kit/vault";
import { defaultEnvVarName } from "../../src/backend-env-mapping.ts";
import { type BrowserOpener, openInBrowser } from "../../src/browser-launcher.ts";
import { connectEnigmaClient } from "../../src/client.ts";
import { createCredentialVault, type CredentialVault } from "../../src/credential-vault.ts";
import {
	type DeviceCodePrompt,
	loginGitHub,
	loginGitLab,
	loginGoogle,
	loginJenkins,
	loginJiraCloud,
	loginOidc,
} from "../../src/login-command.ts";
import { resolveConfiguredMasterKey } from "../../src/master-key.ts";
import { resolveEnigmaExtraPaths, resolveEnigmaPaths } from "../../src/paths.ts";
import { describeCredentialStatus, redactCredentialStatus, type RedactedCredentialStatus } from "./redact.ts";

/** Sentinel item value for the persistent "log in" menu entry, distinct from any real backend name. */
export const LOGIN_ACTION = "__enigma_secrets_login__";

/**
 * Builds the same on-disk encrypted vault `enigma login` writes to directly
 * (bypassing the daemon's HTTP surface entirely, exactly like `src/cli.ts`'s
 * own `loginMain` does) -- a running daemon re-reads the store fresh on its
 * next request, so no restart is needed after a login from here either.
 */
function buildLocalVault(): CredentialVault {
	const extra = resolveEnigmaExtraPaths(resolveEnigmaPaths());
	const masterKey = resolveConfiguredMasterKey(extra);
	return createCredentialVault({ dir: extra.credentialsDir, masterKey });
}

/** Real login functions, injectable so tests never make a network call. */
export interface LoginFns {
	loginGitHub: typeof loginGitHub;
	loginGitLab: typeof loginGitLab;
	loginGoogle: typeof loginGoogle;
	loginJenkins: typeof loginJenkins;
	loginJiraCloud: typeof loginJiraCloud;
	loginOidc: typeof loginOidc;
}

const defaultLoginFns: LoginFns = { loginGitHub, loginGitLab, loginGoogle, loginJenkins, loginJiraCloud, loginOidc };

export async function loadStatuses(client: VaultClient): Promise<RedactedCredentialStatus[]> {
	const backends = await client.listCredentialKeys();
	const statuses: RedactedCredentialStatus[] = [];
	for (const backend of backends) {
		const credential = await client.getCredentials(backend);
		statuses.push(redactCredentialStatus(backend, credential));
	}
	return statuses;
}

async function pickFromList(ctx: ExtensionCommandContext, title: string, items: SelectItem[], helpText: string): Promise<string | null> {
	if (ctx.mode !== "tui") {
		ctx.ui.notify(`${title}: ${items.map((item) => item.label).join(", ") || "(none)"}`, "info");
		return null;
	}
	return ctx.ui.custom<string | null>((tui, theme, _keybindings, done) => {
		const container = new Container();
		container.addChild(new DynamicBorder((s: string) => theme.fg("accent", s)));
		container.addChild(new Text(theme.fg("accent", theme.bold(title)), 1, 0));
		const selectList = new SelectList(items, Math.min(items.length, 10), getSelectListTheme());
		selectList.onSelect = (item) => done(item.value);
		selectList.onCancel = () => done(null);
		container.addChild(selectList);
		container.addChild(new Text(theme.fg("dim", helpText), 1, 0));
		container.addChild(new DynamicBorder((s: string) => theme.fg("accent", s)));
		return {
			render: (w) => container.render(w),
			invalidate: () => container.invalidate(),
			handleInput: (data) => {
				selectList.handleInput(data);
				tui.requestRender();
			},
		};
	});
}

export type PickFromList = (ctx: ExtensionCommandContext, title: string, items: SelectItem[], helpText: string) => Promise<string | null>;

async function manageBackend(ctx: ExtensionCommandContext, client: VaultClient, backend: string, pick: PickFromList = pickFromList): Promise<void> {
	for (;;) {
		const credential = await client.getCredentials(backend);
		const status = redactCredentialStatus(backend, credential);
		const items: SelectItem[] = [
			{ value: "rotate", label: "Rotate", description: "Refresh this credential in place" },
			{ value: "revoke", label: "Revoke", description: "Delete the stored credential" },
			{ value: "back", label: "Back" },
		];
		const action = await pick(ctx, `${backend} \u2014 ${describeCredentialStatus(status)}`, items, "\u2191\u2193 navigate \u2022 enter select \u2022 esc back");
		if (!action || action === "back") return;

		if (action === "rotate") {
			try {
				await client.rotateCredential(backend);
				ctx.ui.notify(`${backend}: rotated.`, "info");
			} catch (error) {
				ctx.ui.notify(`${backend}: rotate failed (${error instanceof Error ? error.message : String(error)})`, "error");
			}
			continue;
		}

		if (action === "revoke") {
			const confirmed = ctx.hasUI ? await ctx.ui.confirm(`Revoke ${backend}?`, "This deletes the stored credential. Re-authenticate with `enigma login` to restore it.") : false;
			if (!confirmed) continue;
			try {
				await client.revokeCredential(backend);
				ctx.ui.notify(`${backend}: revoked.`, "info");
			} catch (error) {
				ctx.ui.notify(`${backend}: revoke failed (${error instanceof Error ? error.message : String(error)})`, "error");
			}
			return; // nothing left to manage for this backend once revoked
		}
	}
}

function notifyMissingEnv(ctx: ExtensionCommandContext, vars: string, guidance: string): void {
	ctx.ui.notify(`${vars} required \u2014 ${guidance}.`, "error");
}

/** Lets a second account for the same platform (`enigma login github --as work`'s TUI equivalent) be stored distinctly, defaulting to the platform's literal name. */
async function promptAlias(ctx: ExtensionCommandContext, literalName: string): Promise<string> {
	const alias = await ctx.ui.input("Save as (optional, for a second account)", literalName);
	return alias || literalName;
}

async function loginBackendFlow(
	ctx: ExtensionCommandContext,
	buildVault: () => CredentialVault = buildLocalVault,
	pick: PickFromList = pickFromList,
	loginFns: LoginFns = defaultLoginFns,
	browserOpener?: BrowserOpener,
): Promise<void> {
	const kindItems: SelectItem[] = [
		{ value: "github", label: "github", description: "Device flow \u2014 requires GITHUB_CLIENT_ID" },
		{ value: "gitlab", label: "gitlab", description: "Device flow \u2014 requires GITLAB_URL and GITLAB_CLIENT_ID" },
		{ value: "jenkins", label: "jenkins", description: "Static API token \u2014 requires JENKINS_URL, JENKINS_USER, JENKINS_API_TOKEN" },
		{ value: "jira", label: "jira", description: "OAuth 2.0 (3LO) \u2014 requires JIRA_CLIENT_ID and JIRA_CLIENT_SECRET" },
		{ value: "google", label: "google", description: "Device flow \u2014 requires GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET" },
		{ value: "oidc", label: "oidc", description: "Generic OIDC device flow for any compliant provider" },
		{ value: "back", label: "Back" },
	];
	const kind = await pick(ctx, "Log in which backend?", kindItems, "\u2191\u2193 navigate \u2022 enter select \u2022 esc back");
	if (!kind || kind === "back") return;

	if (!ctx.hasUI) {
		ctx.ui.notify("Interactive login needs a UI session \u2014 run `enigma login` from a terminal instead.", "error");
		return;
	}

	const onPrompt = (prompt: DeviceCodePrompt) => {
		ctx.ui.notify(`Visit ${prompt.verificationUri} and enter code: ${prompt.userCode}`, "info");
		void openInBrowser(prompt.verificationUri, browserOpener).then((opened) => {
			if (!opened) ctx.ui.notify("Could not open a browser automatically \u2014 open the URL above manually.", "warning");
		});
	};
	const onAuthUrl = (url: string) => {
		ctx.ui.notify(`Visit this URL to authorize: ${url}`, "info");
		void openInBrowser(url, browserOpener).then((opened) => {
			if (!opened) ctx.ui.notify("Could not open a browser automatically \u2014 open the URL above manually.", "warning");
		});
	};

	try {
		if (kind === "github") {
			const clientId = process.env.GITHUB_CLIENT_ID;
			if (!clientId) return notifyMissingEnv(ctx, "GITHUB_CLIENT_ID", "register a personal OAuth App with Device Flow enabled at github.com/settings/developers");
			const alias = await promptAlias(ctx, "github");
			const token = await loginFns.loginGitHub({ clientId, scope: process.env.GITHUB_SCOPES, onPrompt });
			buildVault().save(alias, token);
			ctx.ui.notify(alias === "github" ? "GitHub login complete." : `GitHub login complete (stored as "${alias}").`, "info");
			return;
		}

		if (kind === "gitlab") {
			const baseUrl = process.env.GITLAB_URL;
			const clientId = process.env.GITLAB_CLIENT_ID;
			if (!baseUrl || !clientId) return notifyMissingEnv(ctx, "GITLAB_URL and GITLAB_CLIENT_ID", "register a personal Application under your GitLab instance's User Settings > Applications");
			const alias = await promptAlias(ctx, "gitlab");
			const token = await loginFns.loginGitLab({ baseUrl, clientId, scope: process.env.GITLAB_SCOPES, onPrompt });
			buildVault().save(alias, token);
			ctx.ui.notify(alias === "gitlab" ? "GitLab login complete." : `GitLab login complete (stored as "${alias}").`, "info");
			return;
		}

		if (kind === "google") {
			const clientId = process.env.GOOGLE_CLIENT_ID;
			const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
			if (!clientId || !clientSecret) {
				return notifyMissingEnv(
					ctx,
					"GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET",
					"register a Desktop app OAuth client at console.cloud.google.com/apis/credentials, and enable the Drive API and Docs API",
				);
			}
			const alias = await promptAlias(ctx, "google");
			const token = await loginFns.loginGoogle({ clientId, clientSecret, scope: process.env.GOOGLE_SCOPES, onPrompt });
			buildVault().save(alias, token);
			ctx.ui.notify(alias === "google" ? "Google login complete." : `Google login complete (stored as "${alias}").`, "info");
			return;
		}

		if (kind === "jira") {
			const clientId = process.env.JIRA_CLIENT_ID;
			const clientSecret = process.env.JIRA_CLIENT_SECRET;
			const callbackPort = Number(process.env.JIRA_CALLBACK_PORT ?? 8976);
			if (!clientId || !clientSecret) {
				return notifyMissingEnv(
					ctx,
					"JIRA_CLIENT_ID and JIRA_CLIENT_SECRET",
					`register an OAuth 2.0 (3LO) app at developer.atlassian.com/console/myapps with Callback URL http://127.0.0.1:${callbackPort}/callback`,
				);
			}
			const alias = await promptAlias(ctx, "jira");
			const site = (await ctx.ui.input("Jira site (optional)", "leave blank unless authorized for multiple sites")) || undefined;
			const token = await loginFns.loginJiraCloud({ clientId, clientSecret, scope: process.env.JIRA_SCOPES, callbackPort, site, onAuthUrl });
			buildVault().save(alias, token);
			ctx.ui.notify(alias === "jira" ? "Jira login complete." : `Jira login complete (stored as "${alias}").`, "info");
			return;
		}

		if (kind === "jenkins") {
			const { JENKINS_URL: url, JENKINS_USER: username, JENKINS_API_TOKEN: apiToken } = process.env;
			if (!url || !username || !apiToken) return notifyMissingEnv(ctx, "JENKINS_URL, JENKINS_USER, and JENKINS_API_TOKEN", "generate an API token from your Jenkins user's Configure page");
			const alias = await promptAlias(ctx, "jenkins");
			buildVault().save(alias, loginFns.loginJenkins({ url, username, apiToken }));
			ctx.ui.notify(alias === "jenkins" ? "Jenkins credentials saved." : `Jenkins credentials saved (stored as "${alias}").`, "info");
			return;
		}

		if (kind === "oidc") {
			const name = await ctx.ui.input("Backend name", "e.g. my-company-sso");
			if (!name) return ctx.ui.notify("OIDC login canceled: a backend name is required.", "error");
			const issuerUrl = await ctx.ui.input("Issuer URL", "https://sso.example.com/realms/employees");
			if (!issuerUrl) return ctx.ui.notify("OIDC login canceled: an issuer URL is required.", "error");
			const clientId = await ctx.ui.input("Client ID");
			if (!clientId) return ctx.ui.notify("OIDC login canceled: a client ID is required.", "error");
			const scope = (await ctx.ui.input("Scope (optional)")) || undefined;
			const envVar = (await ctx.ui.input("Env var name (optional)", defaultEnvVarName(name))) || undefined;
			const token = await loginFns.loginOidc({ issuerUrl, clientId, scope, onPrompt });
			token.extra = { ...token.extra, envVarName: envVar ?? defaultEnvVarName(name) };
			buildVault().save(name, token);
			ctx.ui.notify(`OIDC login complete for backend "${name}".`, "info");
			return;
		}
	} catch (error) {
		ctx.ui.notify(`Login failed: ${error instanceof Error ? error.message : String(error)}`, "error");
	}
}

export async function runSecretsCommand(
	ctx: ExtensionCommandContext,
	connect: () => VaultClient = connectEnigmaClient,
	pick: PickFromList = pickFromList,
	buildVault: () => CredentialVault = buildLocalVault,
	loginFns: LoginFns = defaultLoginFns,
	browserOpener?: BrowserOpener,
): Promise<void> {
	let client: VaultClient;
	try {
		client = connect();
	} catch (error) {
		ctx.ui.notify(error instanceof Error ? error.message : String(error), "error");
		return;
	}

	for (;;) {
		let statuses: RedactedCredentialStatus[];
		try {
			statuses = await loadStatuses(client);
		} catch (error) {
			ctx.ui.notify(`Could not reach the Enigma vault: ${error instanceof Error ? error.message : String(error)}`, "error");
			return;
		}

		if (statuses.length === 0) {
			ctx.ui.notify("No backends configured yet. Run `enigma login <backend>` first.", "info");
		}

		const items: SelectItem[] = [
			...statuses.map((status) => ({
				value: status.backend,
				label: status.backend,
				description: describeCredentialStatus(status),
			})),
			{ value: LOGIN_ACTION, label: "+ Log in a backend", description: "Authenticate a new backend, or re-authenticate an existing one" },
		];
		const selected = await pick(ctx, "Enigma secrets", items, "\u2191\u2193 navigate \u2022 enter select \u2022 esc close");
		if (!selected) return;

		if (selected === LOGIN_ACTION) {
			await loginBackendFlow(ctx, buildVault, pick, loginFns, browserOpener);
			continue;
		}

		await manageBackend(ctx, client, selected, pick);
	}
}

export default function (pi: ExtensionAPI): void {
	pi.registerCommand("secrets", {
		description: "Manage Enigma-held credentials: view redacted status, rotate, or revoke",
		handler: async (_args, ctx) => runSecretsCommand(ctx),
	});
}
