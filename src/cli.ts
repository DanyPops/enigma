#!/usr/bin/env bun
import { ensureAuthToken, readDaemonHandle } from "@danypops/daemon-kit/paths";
import { connectEnigmaClient } from "./client.ts";
import { createCredentialVault } from "./credential-vault.ts";
import { serveMain, supervisorMain } from "./daemon.ts";
import { loginGitHub, loginGitLab, loginGoogle, loginJenkins, loginJiraCloud, loginOidc } from "./login-command.ts";

const JIRA_DEFAULT_CALLBACK_PORT = 8976;
import { defaultEnvVarName } from "./backend-env-mapping.ts";
import { MasterKeyFailure, resolveConfiguredMasterKey } from "./master-key.ts";
import { resolveEnigmaExtraPaths, resolveEnigmaPaths } from "./paths.ts";

const [, , command] = process.argv;

function parseFlag(argv: string[], name: string): string | undefined {
	const index = argv.indexOf(name);
	return index !== -1 ? argv[index + 1] : undefined;
}

/**
 * Runs entirely client-side against each backend's own OAuth/credential
 * mechanics, writing directly into the same encrypted store the daemon
 * reads — works even before a daemon has ever been started, and a running
 * daemon picks up a fresh login on its very next request (the token
 * provider re-reads the store fresh each time), no restart needed.
 */
async function loginMain(backend: string | undefined): Promise<void> {
	const extra = resolveEnigmaExtraPaths(resolveEnigmaPaths());
	const masterKey = resolveConfiguredMasterKey(extra);
	const vault = createCredentialVault({ dir: extra.credentialsDir, masterKey });

	if (backend === "github") {
		const clientId = process.env.GITHUB_CLIENT_ID;
		if (!clientId) {
			console.error("GITHUB_CLIENT_ID is required — register a personal OAuth App with Device Flow enabled at github.com/settings/developers");
			process.exit(1);
		}
		const token = await loginGitHub({
			clientId,
			scope: process.env.GITHUB_SCOPES,
			onPrompt: (p) => {
				console.log(`Visit ${p.verificationUri} and enter code: ${p.userCode}`);
				console.log("Waiting for authorization...");
			},
		});
		vault.save("github", token);
		console.log("GitHub login complete.");
		return;
	}

	if (backend === "gitlab") {
		const baseUrl = process.env.GITLAB_URL;
		const clientId = process.env.GITLAB_CLIENT_ID;
		if (!baseUrl || !clientId) {
			console.error("GITLAB_URL and GITLAB_CLIENT_ID are required — register a personal Application under your GitLab instance's User Settings > Applications");
			process.exit(1);
		}
		const token = await loginGitLab({
			baseUrl,
			clientId,
			scope: process.env.GITLAB_SCOPES,
			onPrompt: (p) => {
				console.log(`Visit ${p.verificationUri} and enter code: ${p.userCode}`);
				console.log("Waiting for authorization...");
			},
		});
		vault.save("gitlab", token);
		console.log("GitLab login complete.");
		return;
	}

	if (backend === "oidc") {
		const name = parseFlag(process.argv, "--name");
		const issuerUrl = parseFlag(process.argv, "--issuer");
		const clientId = parseFlag(process.argv, "--client-id");
		const scope = parseFlag(process.argv, "--scope");
		const envVar = parseFlag(process.argv, "--env-var");
		if (!name || !issuerUrl || !clientId) {
			console.error("usage: enigma login oidc --name <arbitrary-name> --issuer <url> --client-id <id> [--scope <scope>] [--env-var <VAR_NAME>]");
			process.exit(1);
		}
		const token = await loginOidc({
			issuerUrl,
			clientId,
			scope,
			onPrompt: (p) => {
				console.log(`Visit ${p.verificationUri} and enter code: ${p.userCode}`);
				console.log("Waiting for authorization...");
			},
		});
		token.extra = { ...token.extra, envVarName: envVar ?? defaultEnvVarName(name) };
		vault.save(name, token);
		console.log(`OIDC login complete for backend "${name}".`);
		return;
	}

	if (backend === "google") {
		const clientId = process.env.GOOGLE_CLIENT_ID;
		const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
		const scope = parseFlag(process.argv, "--scope") ?? process.env.GOOGLE_SCOPES;
		if (!clientId || !clientSecret) {
			console.error(
				"GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required — register a Desktop app OAuth client at console.cloud.google.com/apis/credentials, " +
					"and enable the Drive API and Docs API for the project. Note: a client left in \"Testing\" publishing status has refresh tokens that expire after 7 days.",
			);
			process.exit(1);
		}
		const token = await loginGoogle({
			clientId,
			clientSecret,
			scope,
			onPrompt: (p) => {
				console.log(`Visit ${p.verificationUri} and enter code: ${p.userCode}`);
				console.log("Waiting for authorization...");
			},
		});
		vault.save("google", token);
		console.log("Google login complete.");
		return;
	}

	if (backend === "jira") {
		const clientId = process.env.JIRA_CLIENT_ID;
		const clientSecret = process.env.JIRA_CLIENT_SECRET;
		const site = parseFlag(process.argv, "--site");
		const scope = parseFlag(process.argv, "--scope") ?? process.env.JIRA_SCOPES;
		const callbackPort = Number(process.env.JIRA_CALLBACK_PORT ?? JIRA_DEFAULT_CALLBACK_PORT);
		if (!clientId || !clientSecret) {
			console.error(
				"JIRA_CLIENT_ID and JIRA_CLIENT_SECRET are required — register an OAuth 2.0 (3LO) app at developer.atlassian.com/console/myapps, " +
					`with Callback URL http://127.0.0.1:${callbackPort}/callback (or set JIRA_CALLBACK_PORT to match a different registered port). ` +
					"Include offline_access in --scope/JIRA_SCOPES for a refresh token.",
			);
			process.exit(1);
		}
		const token = await loginJiraCloud({
			clientId,
			clientSecret,
			scope,
			callbackPort,
			site,
			onAuthUrl: (url) => {
				console.log(`Visit this URL to authorize: ${url}`);
				console.log("Waiting for the callback...");
			},
		});
		vault.save("jira", token);
		console.log("Jira login complete.");
		return;
	}

	if (backend === "jenkins") {
		const { JENKINS_URL: url, JENKINS_USER: username, JENKINS_API_TOKEN: apiToken } = process.env;
		if (!url || !username || !apiToken) {
			console.error("JENKINS_URL, JENKINS_USER, and JENKINS_API_TOKEN are required — generate an API token from your Jenkins user's Configure page");
			process.exit(1);
		}
		vault.save("jenkins", loginJenkins({ url, username, apiToken }));
		console.log("Jenkins credentials saved.");
		return;
	}

	console.error("usage: enigma login <github|gitlab|jenkins|jira|google|oidc>");
	process.exit(1);
}

async function rotateMain(backend: string | undefined): Promise<void> {
	if (!backend) {
		console.error("usage: enigma rotate <backend>");
		process.exit(1);
	}
	await connectEnigmaClient().rotateCredential(backend);
	console.log(`${backend} credential rotated.`);
}

async function revokeMain(backend: string | undefined): Promise<void> {
	if (!backend) {
		console.error("usage: enigma revoke <backend>");
		process.exit(1);
	}
	await connectEnigmaClient().revokeCredential(backend);
	console.log(`${backend} credential revoked.`);
}

async function listMain(): Promise<void> {
	const keys = await connectEnigmaClient().listCredentialKeys();
	console.log(JSON.stringify(keys));
}

try {
	switch (command) {
		case "serve":
			serveMain();
			break;
		case "supervisor": {
			const configFlagIndex = process.argv.indexOf("--config");
			const configPath = configFlagIndex !== -1 ? process.argv[configFlagIndex + 1] : undefined;
			supervisorMain(configPath);
			break;
		}
		case "login":
			await loginMain(process.argv[3]);
			break;
		case "rotate":
			await rotateMain(process.argv[3]);
			break;
		case "revoke":
			await revokeMain(process.argv[3]);
			break;
		case "list":
			await listMain();
			break;
		case "health": {
			const paths = resolveEnigmaPaths();
			const handle = readDaemonHandle(paths.handle);
			if (!handle) {
				console.error("Enigma daemon is not running.");
				process.exit(1);
			}
			const token = ensureAuthToken(paths.token, "Enigma");
			const response = await fetch(`http://${handle.host}:${handle.port}/health`, { headers: { authorization: `Bearer ${token}` } });
			console.log(await response.text());
			break;
		}
		default:
			console.error(
				"usage: enigma <serve|supervisor|login|rotate|revoke|list|health>\n" +
					"  serve                          serve the vault only, no supervision\n" +
					"  supervisor [--config <path>]   serve the vault and spawn configured daemons\n" +
					"  login <github|gitlab|jenkins>  authenticate and store credentials for a backend\n" +
					"  login jira [--site <name-or-url>] [--scope <scope>]\n" +
					"                                 Jira Cloud OAuth 2.0 (3LO), via JIRA_CLIENT_ID/JIRA_CLIENT_SECRET\n" +
					"  login google [--scope <scope>] Drive/Docs OAuth, via GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET\n" +
					"  login oidc --name <name> --issuer <url> --client-id <id> [--scope][--env-var]\n" +
					"                                 generic OIDC device flow for any compliant provider\n" +
					"  rotate <backend>               force a refresh of a stored credential\n" +
					"  revoke <backend>               delete a stored credential\n" +
					"  list                           list backends with a stored credential\n" +
					"  health                         talk to a running instance, print status JSON",
			);
			process.exit(1);
	}
} catch (error) {
	if (error instanceof MasterKeyFailure) {
		console.error(error.message);
		process.exit(1);
	}
	throw error;
}
