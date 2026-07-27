/** Bun composition root: binds and serves the vault via @danypops/daemon-kit's runDaemonProcess. */
import { runDaemonProcess } from "@danypops/daemon-kit/daemon";
import { createLogger } from "@danypops/daemon-kit/logging";
import { ensureAuthToken } from "@danypops/daemon-kit/paths";
import { createClientRegistry } from "./client-registry.ts";
import { createCredentialVault, type CredentialVault } from "./credential-vault.ts";
import { resolveConfiguredMasterKey } from "./master-key.ts";
import { resolveEnigmaExtraPaths, resolveEnigmaPaths } from "./paths.ts";
import { createApp } from "./server.ts";

const logger = createLogger("enigma");

function buildVault(): { vault: CredentialVault; extra: ReturnType<typeof resolveEnigmaExtraPaths> } {
	const paths = resolveEnigmaPaths();
	const extra = resolveEnigmaExtraPaths(paths);
	const masterKey = resolveConfiguredMasterKey(extra);
	return { vault: createCredentialVault({ dir: extra.credentialsDir, masterKey }), extra };
}

/** Vault-only mode — the only mode. Every consumer fetches its own credential over the authenticated API; Enigma never spawns or supervises anything. */
export function serveMain(): void {
	const paths = resolveEnigmaPaths();
	const token = ensureAuthToken(paths.token, "Enigma");
	const { vault, extra } = buildVault();
	const clients = createClientRegistry(extra.clientRegistryFile);

	runDaemonProcess({
		daemonLabel: "Enigma",
		handlePath: paths.handle,
		logger,
		buildApp: () => createApp({ vault, token, clients }),
		onListen: ({ host, port }) => logger.info("listening", { host, port }),
	});
}
