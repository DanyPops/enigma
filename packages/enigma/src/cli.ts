#!/usr/bin/env bun
import { addEnigmaClient, removeEnigmaClient, rotateEnigmaClient } from "@danypops/enigma-client";
import { openInBrowser } from "./browser-launcher.ts";
import { connectEnigmaClient, type EnigmaAdminClient } from "./client.ts";
import { ClientAlreadyRegisteredError, ClientNotFoundError, createClientRegistry, UidAlreadyBoundError, type ClientRegistry } from "./client-registry.ts";
import { createCredentialVault } from "./credential-vault.ts";
import { serveMain } from "./daemon.ts";
import { loginApiKey, loginGitHub, loginGitLab, loginGoogle, loginJenkins, loginJiraCloud, loginOidc } from "./login-command.ts";
import { promptMaskedSecret } from "./masked-prompt.ts";

const JIRA_DEFAULT_CALLBACK_PORT = 8976;
import { defaultEnvVarName, normalizeBackendName } from "./backend-env-mapping.ts";
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

	const rawAlias = parseFlag(process.argv, "--as");
	const alias = rawAlias ? normalizeBackendName(rawAlias) : undefined;

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
				void openInBrowser(p.verificationUri).then((opened) => {
					if (!opened) console.log("Could not open a browser automatically -- open the URL above manually.");
				});
			},
		});
		vault.save(alias ?? "github", token);
		console.log(alias ? `GitHub login complete (stored as "${alias}").` : "GitHub login complete.");
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
				void openInBrowser(p.verificationUri).then((opened) => {
					if (!opened) console.log("Could not open a browser automatically -- open the URL above manually.");
				});
			},
		});
		vault.save(alias ?? "gitlab", token);
		console.log(alias ? `GitLab login complete (stored as "${alias}").` : "GitLab login complete.");
		return;
	}

	if (backend === "oidc") {
		const rawName = parseFlag(process.argv, "--name");
		const issuerUrl = parseFlag(process.argv, "--issuer");
		const clientId = parseFlag(process.argv, "--client-id");
		const scope = parseFlag(process.argv, "--scope");
		const envVar = parseFlag(process.argv, "--env-var");
		if (!rawName || !issuerUrl || !clientId) {
			console.error("usage: enigma login oidc --name <arbitrary-name> --issuer <url> --client-id <id> [--scope <scope>] [--env-var <VAR_NAME>]");
			process.exit(1);
		}
		const name = normalizeBackendName(rawName);
		const token = await loginOidc({
			issuerUrl,
			clientId,
			scope,
			onPrompt: (p) => {
				console.log(`Visit ${p.verificationUri} and enter code: ${p.userCode}`);
				console.log("Waiting for authorization...");
				void openInBrowser(p.verificationUri).then((opened) => {
					if (!opened) console.log("Could not open a browser automatically -- open the URL above manually.");
				});
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
				void openInBrowser(p.verificationUri).then((opened) => {
					if (!opened) console.log("Could not open a browser automatically -- open the URL above manually.");
				});
			},
		});
		vault.save(alias ?? "google", token);
		console.log(alias ? `Google login complete (stored as "${alias}").` : "Google login complete.");
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
				void openInBrowser(url).then((opened) => {
					if (!opened) console.log("Could not open a browser automatically -- open the URL above manually.");
				});
			},
		});
		vault.save(alias ?? "jira", token);
		console.log(alias ? `Jira login complete (stored as "${alias}").` : "Jira login complete.");
		return;
	}

	if (backend === "jenkins") {
		const { JENKINS_URL: url, JENKINS_USER: username, JENKINS_API_TOKEN: apiToken } = process.env;
		if (!url || !username || !apiToken) {
			console.error("JENKINS_URL, JENKINS_USER, and JENKINS_API_TOKEN are required — generate an API token from your Jenkins user's Configure page");
			process.exit(1);
		}
		vault.save(alias ?? "jenkins", loginJenkins({ url, username, apiToken }));
		console.log(alias ? `Jenkins credentials saved (stored as "${alias}").` : "Jenkins credentials saved.");
		return;
	}

	if (backend === "apikey") {
		const rawName = parseFlag(process.argv, "--name");
		const envVar = parseFlag(process.argv, "--env-var");
		if (!rawName || !envVar) {
			console.error("usage: enigma login apikey --name <arbitrary-name> --env-var <VAR_NAME>");
			process.exit(1);
		}
		const name = normalizeBackendName(rawName);
		// ENIGMA_APIKEY_VALUE remains for non-interactive/scripted use (a provisioning
		// script that already holds the secret in its own env). At a real terminal,
		// prompt with input masked instead -- never echoed, never on argv, never in
		// shell history the way `ENIGMA_APIKEY_VALUE=... enigma ...` on one line would be.
		const value = process.env.ENIGMA_APIKEY_VALUE ?? (await promptMaskedSecret(`Paste the "${name}" API key (input hidden): `));
		if (!value) {
			console.error("no API key value provided — paste one at the prompt, or set ENIGMA_APIKEY_VALUE for non-interactive use");
			process.exit(1);
		}
		vault.save(name, loginApiKey({ value, envVarName: envVar }));
		console.log(`API key saved for backend "${name}".`);
		return;
	}

	console.error("usage: enigma login <github|gitlab|jenkins|jira|google> [--as <alias>], or enigma login oidc/apikey ...");
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

/**
 * Deliberately the one place Enigma prints a real credential value --
 * matching a real secrets manager's own "yes, you can read it" model
 * (HashiCorp Vault's `vault kv get`): the admin token already permits this
 * exact read via GET /creds/:backend, this just gives it a first-class
 * command instead of a raw curl+jq workaround. Goes through the same
 * connectEnigmaClient() path rotate/revoke already use, so it's covered by
 * the same audit logging on the server side -- never a silent bypass.
 * CLI-only, human-terminal use: never wired into the pi extension's
 * /secrets command, which stays redacted for the AI-agent-facing surface.
 */
export async function showMain(backend: string | undefined, connect: () => EnigmaAdminClient = connectEnigmaClient): Promise<void> {
	if (!backend) {
		console.error("usage: enigma show <backend>");
		process.exit(1);
	}
	const credential = await connect().getCredentials(backend);
	if (!credential) {
		console.error(`no credential stored for backend "${backend}"`);
		process.exit(1);
	}
	console.error(`Printing the real, decrypted "${backend}" credential -- this will end up in shell history/scrollback.`);
	console.log(JSON.stringify(credential, null, 2));
}

async function listMain(): Promise<void> {
	const keys = await connectEnigmaClient().listCredentialKeys();
	console.log(JSON.stringify(keys));
}

/**
 * Prefers the running daemon (POST /clients and its /rotate, /remove
 * siblings -- see server.ts, all admin-gated) over local-file mutation: the
 * daemon performs the write itself, so the operator never needs filesystem
 * access to wherever Enigma's own state actually lives (a different
 * service account's directory, on a real deployment).
 *
 * addEnigmaClient/rotateEnigmaClient/removeEnigmaClient resolve undefined
 * specifically when Enigma isn't reachable at all -- that, and only that,
 * is the fallback trigger. A real rejection from a running daemon (already
 * registered, uid already bound, not authorized, not found) is surfaced
 * directly instead: falling back to a local-file write after a real remote
 * rejection would create a phantom local registration alongside whatever
 * is or isn't in the real registry, which is worse than just failing.
 *
 * Registration is metadata (a name, an allowed-backends list, a token
 * hash) with no dependency on the master key -- the local-file fallback
 * runs entirely against the client registry file, the same way loginMain
 * runs directly against the credential store, and works even before a
 * daemon has ever been started. A running daemon picks up a local-file
 * add/rotate/remove on its very next request, no restart needed -- but
 * only if it happens to read the very same file this process resolved,
 * which is exactly the cross-account case the RPC path above exists for.
 */
export interface ClientMainDeps {
	registry?: ClientRegistry;
	addEnigmaClient?: typeof addEnigmaClient;
	rotateEnigmaClient?: typeof rotateEnigmaClient;
	removeEnigmaClient?: typeof removeEnigmaClient;
	connectEnigmaClient?: () => EnigmaAdminClient;
}

/**
 * Two distinct ways a *reachable* daemon still isn't a usable remote path
 * for this operation:
 *  - 401/403: no admin credential against this particular Enigma -- this
 *    CLI process simply isn't trusted here.
 *  - 404 on /clients (add has no legitimate 404 of its own -- only 201,
 *    400, or 409): the daemon predates this route entirely (confirmed
 *    live against this session's own real system Enigma, several minor
 *    versions behind the CLI talking to it).
 * Both are structurally the same problem as the daemon not being reachable
 * at all, not a real rejection of a well-formed request. rotate/remove's
 * 404 is genuinely ambiguous (an up-to-date daemon's real "no such
 * client" vs. an old daemon's missing route) -- falling through either way
 * is still correct: an up-to-date local registry re-derives the identical
 * "no such client" rejection on its own if the name truly doesn't exist
 * there either.
 */
function shouldFallBackToLocalFile(status: number): boolean {
	return status === 401 || status === 403 || status === 404;
}

export async function clientMain(args: string[], deps: ClientMainDeps = {}): Promise<void> {
	const registry = deps.registry ?? createClientRegistry(resolveEnigmaExtraPaths(resolveEnigmaPaths()).clientRegistryFile);
	const tryAddViaRpc = deps.addEnigmaClient ?? addEnigmaClient;
	const tryRotateViaRpc = deps.rotateEnigmaClient ?? rotateEnigmaClient;
	const tryRemoveViaRpc = deps.removeEnigmaClient ?? removeEnigmaClient;
	const connectAdmin = deps.connectEnigmaClient ?? connectEnigmaClient;
	const [subcommand, name] = args;

	switch (subcommand) {
		case "add": {
			const backendsFlag = parseFlag(args, "--backends");
			const uidFlag = parseFlag(args, "--uid");
			if (!name || !backendsFlag) {
				console.error("usage: enigma client add <name> --backends <comma,separated,list> [--uid <kernel-verified-caller-uid>]");
				process.exit(1);
			}
			const uid = uidFlag !== undefined ? Number(uidFlag) : undefined;
			if (uidFlag !== undefined && (!Number.isInteger(uid) || uid! < 0)) {
				console.error(`--uid must be a non-negative integer, got "${uidFlag}"`);
				process.exit(1);
			}
			const backends = backendsFlag.split(",").map((b) => b.trim()).filter(Boolean);

			const viaRpc = await tryAddViaRpc({ name, backends, uid });
			if (viaRpc !== undefined && !(!viaRpc.ok && shouldFallBackToLocalFile(viaRpc.status))) {
				if (!viaRpc.ok) {
					console.error(viaRpc.error);
					process.exit(1);
				}
				console.log(`Registered "${name}" via the running daemon. Token (shown once, store it in ${name}'s own config, never in Enigma):`);
				console.log(viaRpc.token);
				break;
			}

			try {
				const token = registry.add(name, backends, uid !== undefined ? { uid } : undefined);
				console.log(`Registered "${name}". Token (shown once, store it in ${name}'s own config, never in Enigma):`);
				console.log(token);
			} catch (error) {
				if (error instanceof ClientAlreadyRegisteredError) {
					console.error(`${error.message} -- use "enigma client rotate ${name}" to reissue its token.`);
					process.exit(1);
				}
				if (error instanceof UidAlreadyBoundError) {
					console.error(error.message);
					process.exit(1);
				}
				throw error;
			}
			break;
		}
		case "rotate": {
			if (!name) {
				console.error("usage: enigma client rotate <name>");
				process.exit(1);
			}

			const viaRpc = await tryRotateViaRpc(name);
			if (viaRpc !== undefined && !(!viaRpc.ok && shouldFallBackToLocalFile(viaRpc.status))) {
				if (!viaRpc.ok) {
					console.error(viaRpc.error);
					process.exit(1);
				}
				console.log(`New token for "${name}" via the running daemon (shown once, the old one no longer works):`);
				console.log(viaRpc.token);
				break;
			}

			try {
				const token = registry.rotate(name);
				console.log(`New token for "${name}" (shown once, the old one no longer works):`);
				console.log(token);
			} catch (error) {
				if (error instanceof ClientNotFoundError) {
					console.error(error.message);
					process.exit(1);
				}
				throw error;
			}
			break;
		}
		case "remove": {
			if (!name) {
				console.error("usage: enigma client remove <name>");
				process.exit(1);
			}

			const viaRpc = await tryRemoveViaRpc(name);
			if (viaRpc !== undefined && !(!viaRpc.ok && shouldFallBackToLocalFile(viaRpc.status))) {
				if (!viaRpc.ok) {
					console.error(viaRpc.error);
					process.exit(1);
				}
				console.log(`Removed "${name}" via the running daemon. Its token no longer works.`);
				break;
			}

			try {
				registry.remove(name);
				console.log(`Removed "${name}". Its token no longer works.`);
			} catch (error) {
				if (error instanceof ClientNotFoundError) {
					console.error(error.message);
					process.exit(1);
				}
				throw error;
			}
			break;
		}
		case "list": {
			// Prefers the real running daemon's own registry (GET /clients, admin-only) over
			// this process's local file -- reading the wrong one silently (a real, confirmed
			// footgun: this process's own local file can look emptily "correct" while a real
			// deployment's actual registry, owned by a different service account, has entries
			// this process can never see) is worse than a list command that's occasionally
			// slower because it tried the network first.
			try {
				console.log(JSON.stringify(await connectAdmin().listClients(), null, 2));
			} catch {
				console.log(JSON.stringify(registry.list(), null, 2));
			}
			break;
		}
		default:
			console.error("usage: enigma client <add|rotate|remove|list>\n  add <name> --backends <list>  register a new consumer, print its token once\n  rotate <name>                 reissue a client's token, invalidating the old one\n  remove <name>                 delete a registration, invalidating its token\n  list                          show registered clients and their allowed backends (no tokens)");
			process.exit(1);
	}
}

// Guarded so importing this module for its exports (showMain, in a test) never also
// runs the CLI dispatch against whatever argv the importing process happens to have.
if (import.meta.main) {
	try {
		switch (command) {
			case "serve":
				serveMain();
				break;
			case "login":
				await loginMain(process.argv[3]);
				break;
			case "rotate":
				await rotateMain(process.argv[3]);
				break;
			case "revoke":
				await revokeMain(process.argv[3]);
				break;
			case "show":
				await showMain(process.argv[3]);
				break;
			case "list":
				await listMain();
				break;
			case "client":
				await clientMain(process.argv.slice(3));
				break;
			case "health": {
				try {
					console.log(JSON.stringify(await connectEnigmaClient().health()));
				} catch (error) {
					console.error(error instanceof Error ? error.message : String(error));
					process.exit(1);
				}
				break;
			}
			default:
				console.error(
					"usage: enigma <serve|login|rotate|revoke|show|list|client|health>\n" +
						"  serve                          serve the vault; every consumer fetches its own credential\n" +
						"  login <github|gitlab|jenkins>  authenticate and store credentials for a backend\n" +
						"  login jira [--site <name-or-url>] [--scope <scope>]\n" +
						"                                 Jira Cloud OAuth 2.0 (3LO), via JIRA_CLIENT_ID/JIRA_CLIENT_SECRET\n" +
						"  login google [--scope <scope>] Drive/Docs OAuth, via GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET\n" +
						"  login oidc --name <name> --issuer <url> --client-id <id> [--scope][--env-var]\n" +
						"                                 generic OIDC device flow for any compliant provider\n" +
						"  login apikey --name <name> --env-var <VAR_NAME>\n" +
						"                                 generic static API key, no OAuth (Brave, Tavily, Exa, ...) —\n" +
						"                                 prompts with input hidden, or set ENIGMA_APIKEY_VALUE non-interactively\n" +
						"  rotate <backend>               force a refresh of a stored credential\n" +
						"  revoke <backend>               delete a stored credential\n" +
						"  show <backend>                 print the real, decrypted credential (audit-logged) -- human terminal use only\n" +
						"  list                           list backends with a stored credential\n" +
						"  client <add|rotate|remove|list>\n" +
						"                                 register a consumer daemon and scope which backends it may fetch\n" +
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
}
