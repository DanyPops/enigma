/** Bun composition root: binds and serves the vault via @danypops/daemon-kit's runDaemonProcess. */
import { runDaemonProcess } from "@danypops/daemon-kit/daemon";
import { createLogger } from "@danypops/daemon-kit/logging";
import { ensureAuthToken } from "@danypops/daemon-kit/paths";
import { buildBackendRefreshRegistry } from "./backend-refresh.ts";
import { createCredentialVault, type CredentialVault } from "./credential-vault.ts";
import { getOrCreateMasterKey, resolveKeyringIdentityFromEnv } from "./master-key.ts";
import { resolveEnigmaExtraPaths, resolveEnigmaPaths } from "./paths.ts";
import { createApp } from "./server.ts";
import { loadSupervisorConfig } from "./supervisor-config.ts";
import { runSupervisor } from "./supervisor.ts";

const logger = createLogger("enigma");

function buildVault(): { vault: CredentialVault; extra: ReturnType<typeof resolveEnigmaExtraPaths> } {
	const paths = resolveEnigmaPaths();
	const extra = resolveEnigmaExtraPaths(paths);
	const masterKey = getOrCreateMasterKey(extra.masterKeyFile, resolveKeyringIdentityFromEnv());
	return { vault: createCredentialVault({ dir: extra.credentialsDir, masterKey }), extra };
}

/** Vault-only mode (no child-daemon supervision) — used by `enigma serve` and by tests. */
export function serveMain(): void {
	const paths = resolveEnigmaPaths();
	const token = ensureAuthToken(paths.token, "Enigma");
	const { vault } = buildVault();
	const refreshRegistry = buildBackendRefreshRegistry();

	runDaemonProcess({
		daemonLabel: "Enigma",
		handlePath: paths.handle,
		logger,
		buildApp: () => createApp({ vault, refreshRegistry, token }),
		onListen: ({ host, port }) => logger.info("listening", { host, port }),
	});
}

/** Vault + supervisor: serves the vault and spawns configured units, injecting their credentials as env. The production default (the systemd unit runs this). */
export function supervisorMain(configPathOverride?: string): void {
	const paths = resolveEnigmaPaths();
	const token = ensureAuthToken(paths.token, "Enigma");
	const { vault, extra } = buildVault();
	const refreshRegistry = buildBackendRefreshRegistry();
	const config = loadSupervisorConfig(configPathOverride ?? extra.supervisorConfig);
	const supervisor = runSupervisor(config, vault, { logger });

	runDaemonProcess({
		daemonLabel: "Enigma",
		handlePath: paths.handle,
		logger,
		buildApp: () => createApp({ vault, refreshRegistry, token }),
		onShutdown: () => supervisor.stop(),
		onListen: ({ host, port }) => logger.info("listening", { host, port, units: config.units.length }),
	});
}
