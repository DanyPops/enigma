/**
 * pi-enigma: `/secrets` command for interactive vault management from inside
 * Pi. Human-driven only -- no LLM-callable tool here. Talks to the same
 * running `enigma serve` daemon the CLI does, via the same EnigmaAdminClient;
 * this lives in enigma's own package (not a separate one depending on it
 * over npm), so importing ../../src/client.ts directly is a plain relative
 * TypeScript import, not a cross-package boundary jiti would need to
 * transpile through node_modules -- confirmed safe by @danypops/jittor's
 * own extension/src/service-client.ts, which does exactly this against its
 * own daemon.
 *
 * Never surfaces accessToken/refreshToken/extra: every value shown here comes
 * from SecretRecord's explicit allow-list (../../src/secrets-backend-adapter.ts),
 * per the standing rule "Enigma Pi extension: never expose decrypted credential
 * material to the LLM".
 */
import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { DynamicBorder, getSelectListTheme } from "@earendil-works/pi-coding-agent";
import { Container, type SelectItem, SelectList, Text } from "@earendil-works/pi-tui";
import { registerSharedSecretsCommand, runSecretsCommand as runGenericSecretsCommand, type SecretsContribution } from "@danypops/daemon-kit/secrets-tui";
import type { SecretsBackend, ServicesRegistry } from "@danypops/daemon-kit/secrets-backend";
import { type ApiKeyFormResult, ApiKeyRegistrationForm } from "./apikey-form.ts";
import { defaultEnvVarName } from "../../src/backend-env-mapping.ts";
import { type BrowserOpener, openInBrowser } from "../../src/browser-launcher.ts";
import { connectEnigmaClient, type EnigmaAdminClient } from "../../src/client.ts";
import { createCredentialVault, type CredentialVault } from "../../src/credential-vault.ts";
import {
	type DeviceCodePrompt,
	loginApiKey,
	loginGitHub,
	loginGitLab,
	loginGoogle,
	loginJenkins,
	loginJiraCloud,
	loginOidc,
} from "../../src/login-command.ts";
import { resolveConfiguredMasterKey } from "../../src/master-key.ts";
import { resolveEnigmaExtraPaths, resolveEnigmaPaths } from "../../src/paths.ts";
import { createEnigmaSecretsBackend } from "../../src/secrets-backend-adapter.ts";
import { createEnigmaServicesRegistry } from "../../src/services-registry-adapter.ts";

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
	loginApiKey: typeof loginApiKey;
	loginGitHub: typeof loginGitHub;
	loginGitLab: typeof loginGitLab;
	loginGoogle: typeof loginGoogle;
	loginJenkins: typeof loginJenkins;
	loginJiraCloud: typeof loginJiraCloud;
	loginOidc: typeof loginOidc;
}

const defaultLoginFns: LoginFns = { loginApiKey, loginGitHub, loginGitLab, loginGoogle, loginJenkins, loginJiraCloud, loginOidc };

/**
 * Three-field form (name, env var, masked value) for a static API key --
 * the value field never renders the real characters typed/pasted into it.
 * Returns null on cancel (Escape).
 */
async function promptApiKeyForm(ctx: ExtensionCommandContext): Promise<ApiKeyFormResult | null> {
	return ctx.ui.custom<ApiKeyFormResult | null>((tui, theme, _keybindings, done) => {
		const container = new Container();
		container.addChild(new DynamicBorder((s: string) => theme.fg("accent", s)));
		container.addChild(new Text(theme.fg("accent", theme.bold("Register a static API key")), 1, 0));
		const form = new ApiKeyRegistrationForm({
			label: (s) => theme.fg("muted", s),
			focusedLabel: (s) => theme.fg("accent", s),
			help: (s) => theme.fg("dim", s),
			error: (s) => theme.fg("error", s),
		});
		form.onSubmit = (result) => done(result);
		form.onCancel = () => done(null);
		container.addChild(form);
		container.addChild(new DynamicBorder((s: string) => theme.fg("accent", s)));
		return {
			render: (w) => container.render(w),
			invalidate: () => container.invalidate(),
			handleInput: (data) => {
				form.handleInput(data);
				tui.requestRender();
			},
		};
	});
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

function notifyMissingEnv(ctx: ExtensionCommandContext, vars: string, guidance: string): void {
	ctx.ui.notify(`${vars} required \u2014 ${guidance}.`, "error");
}

/** Lets a second account for the same platform (`enigma login github --as work`'s TUI equivalent) be stored distinctly, defaulting to the platform's literal name. */
async function promptAlias(ctx: ExtensionCommandContext, literalName: string): Promise<string> {
	const alias = await ctx.ui.input("Save as (optional, for a second account)", literalName);
	return alias || literalName;
}

export type PromptApiKeyForm = (ctx: ExtensionCommandContext) => Promise<ApiKeyFormResult | null>;

/** Exported so tests exercise this wizard directly, without navigating any outer menu (Lexicon practices/tui-testing.md: state/decomposition over scripted pick sequences). */
export async function loginBackendFlow(
	ctx: ExtensionCommandContext,
	buildVault: () => CredentialVault = buildLocalVault,
	pick: PickFromList = pickFromList,
	loginFns: LoginFns = defaultLoginFns,
	browserOpener?: BrowserOpener,
	promptApiKey: PromptApiKeyForm = promptApiKeyForm,
): Promise<void> {
	const kindItems: SelectItem[] = [
		{ value: "github", label: "github", description: "Device flow \u2014 requires GITHUB_CLIENT_ID" },
		{ value: "gitlab", label: "gitlab", description: "Device flow \u2014 requires GITLAB_URL and GITLAB_CLIENT_ID" },
		{ value: "jenkins", label: "jenkins", description: "Static API token \u2014 requires JENKINS_URL, JENKINS_USER, JENKINS_API_TOKEN" },
		{ value: "jira", label: "jira", description: "OAuth 2.0 (3LO) \u2014 requires JIRA_CLIENT_ID and JIRA_CLIENT_SECRET" },
		{ value: "google", label: "google", description: "Device flow \u2014 requires GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET" },
		{ value: "oidc", label: "oidc", description: "Generic OIDC device flow for any compliant provider" },
		{ value: "apikey", label: "apikey", description: "Static API key, no OAuth (Brave, Tavily, Exa, ...) — requires ENIGMA_APIKEY_VALUE" },
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

		if (kind === "apikey") {
			// ENIGMA_APIKEY_VALUE (automation/scripting): skip the form, keep the
			// lightweight two-prompt flow -- there is no secret left to mask, it
			// already arrived via the operator's own environment.
			const envValue = process.env.ENIGMA_APIKEY_VALUE;
			if (envValue) {
				const name = await ctx.ui.input("Backend name", "e.g. brave");
				if (!name) return ctx.ui.notify("API key login canceled: a backend name is required.", "error");
				const envVar = (await ctx.ui.input("Env var name", defaultEnvVarName(name))) || defaultEnvVarName(name);
				buildVault().save(name, loginFns.loginApiKey({ value: envValue, envVarName: envVar }));
				ctx.ui.notify(`API key saved for backend "${name}".`, "info");
				return;
			}
			// Interactive (the common case): a real registration form with a masked
			// value field -- the key is never typed into a plain ctx.ui.input(),
			// which has no masked mode at all.
			const result = await promptApiKey(ctx);
			if (!result) return; // canceled, no notification needed
			buildVault().save(result.name, loginFns.loginApiKey({ value: result.value, envVarName: result.envVar }));
			ctx.ui.notify(`API key saved for backend "${result.name}".`, "info");
			return;
		}
	} catch (error) {
		ctx.ui.notify(`Login failed: ${error instanceof Error ? error.message : String(error)}`, "error");
	}
}

/**
 * Enigma's own contribution to daemon-kit's shared /secrets namespace --
 * Enigma is one pluggable backend among possibly several sharing that
 * command (pipes, tickets), not the assumed target, even on a machine
 * running only Enigma. The device-flow/static-token login menu the
 * generic port deliberately doesn't model is threaded through as an
 * extraAction.
 *
 * `connect()` is called lazily, the first time the backend or
 * servicesRegistry is actually used (list/get/rotate/revoke), not eagerly
 * here -- a contribution is merged with every other consumer's before any
 * menu renders (see mergeSecretsContributions), so an eager connect()
 * throwing here would take down tickets' and pipes' otherwise-working
 * secrets along with Enigma's. A lazy failure instead surfaces through the
 * exact same per-backend SecretsBackendListError path every other backend
 * failure already goes through.
 */
export function buildEnigmaSecretsContribution(
	connect: () => EnigmaAdminClient = connectEnigmaClient,
	pick: PickFromList = pickFromList,
	buildVault: () => CredentialVault = buildLocalVault,
	loginFns: LoginFns = defaultLoginFns,
	browserOpener?: BrowserOpener,
	promptApiKey: PromptApiKeyForm = promptApiKeyForm,
): SecretsContribution {
	let cachedClient: EnigmaAdminClient | undefined;
	const ensureClient = (): EnigmaAdminClient => {
		if (!cachedClient) cachedClient = connect();
		return cachedClient;
	};
	const backend: SecretsBackend = {
		source: "enigma",
		list: () => createEnigmaSecretsBackend(ensureClient()).list(),
		get: (name) => createEnigmaSecretsBackend(ensureClient()).get(name),
		rotate: (name) => createEnigmaSecretsBackend(ensureClient()).rotate(name),
		revoke: (name) => createEnigmaSecretsBackend(ensureClient()).revoke(name),
	};
	const servicesRegistry: ServicesRegistry = { list: () => createEnigmaServicesRegistry(ensureClient()).list() };
	return {
		backends: [backend],
		servicesRegistry,
		extraActions: [
			{
				value: LOGIN_ACTION,
				label: "+ Log in a backend",
				description: "Authenticate a new backend, or re-authenticate an existing one",
				run: (c) => loginBackendFlow(c, buildVault, pick, loginFns, browserOpener, promptApiKey),
			},
		],
	};
}

/** Standalone entry point kept for direct testing and any caller that wants Enigma's secrets view on its own, outside the shared registry. */
export async function runSecretsCommand(
	ctx: ExtensionCommandContext,
	connect: () => EnigmaAdminClient = connectEnigmaClient,
	pick: PickFromList = pickFromList,
	buildVault: () => CredentialVault = buildLocalVault,
	loginFns: LoginFns = defaultLoginFns,
	browserOpener?: BrowserOpener,
	promptApiKey: PromptApiKeyForm = promptApiKeyForm,
): Promise<void> {
	await runGenericSecretsCommand(ctx, { ...buildEnigmaSecretsContribution(connect, pick, buildVault, loginFns, browserOpener, promptApiKey), pick });
}

export default function (pi: ExtensionAPI): void {
	// Contributes to the shared /secrets namespace (daemon-kit's
	// registerSharedSecretsCommand) instead of a standalone command --
	// pipes and tickets contribute the same way, so whichever of the three
	// loads first in a given Pi session ends up claiming the real command
	// registration, and all three still show up in it regardless of order.
	registerSharedSecretsCommand(pi, { source: "enigma", resolve: () => buildEnigmaSecretsContribution() });
}
