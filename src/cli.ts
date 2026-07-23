#!/usr/bin/env bun
import { ensureAuthToken, readDaemonHandle } from "@danypops/daemon-kit/paths";
import { connectEnigmaClient } from "./client.ts";
import { createCredentialVault } from "./credential-vault.ts";
import { serveMain, supervisorMain } from "./daemon.ts";
import { loginGitHub, loginGitLab, loginJenkins } from "./login-command.ts";
import { getOrCreateMasterKey, resolveKeyringIdentityFromEnv } from "./master-key.ts";
import { resolveEnigmaExtraPaths, resolveEnigmaPaths } from "./paths.ts";

const [, , command] = process.argv;

/**
 * Runs entirely client-side against each backend's own OAuth/credential
 * mechanics, writing directly into the same encrypted store the daemon
 * reads — works even before a daemon has ever been started, and a running
 * daemon picks up a fresh login on its very next request (the token
 * provider re-reads the store fresh each time), no restart needed.
 */
async function loginMain(backend: string | undefined): Promise<void> {
	const extra = resolveEnigmaExtraPaths(resolveEnigmaPaths());
	const masterKey = getOrCreateMasterKey(extra.masterKeyFile, resolveKeyringIdentityFromEnv());
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

	console.error("usage: enigma login <github|gitlab|jenkins>");
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
				"  rotate <backend>               force a refresh of a stored credential\n" +
				"  revoke <backend>               delete a stored credential\n" +
				"  list                           list backends with a stored credential\n" +
				"  health                         talk to a running instance, print status JSON",
		);
		process.exit(1);
}
