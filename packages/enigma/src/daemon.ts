/** Bun composition root: binds and serves the vault via @danypops/vehicle-server's runDaemonProcess. */
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { runDaemonProcess } from "@danypops/vehicle-server/daemon";
import { createLogger } from "@danypops/vehicle-server/logging";
import { openVehicleMetricsStore } from "@danypops/vehicle-server/metrics";
import { ensureAuthToken } from "@danypops/vehicle-server/paths";
import { serveUnixRpc } from "@danypops/vehicle-server/unix-rpc-server";
import { createClientRegistry } from "./client-registry.ts";
import { ADMIN_SOCKET_FILENAME } from "./constants.ts";
import { type CredentialVault, createCredentialVault } from "./credential-vault.ts";
import { resolveConfiguredMasterKey } from "./master-key.ts";
import { resolveEnigmaExtraPaths, resolveEnigmaPaths } from "./paths.ts";
import { createPkcheckAuthorizer } from "./polkit-check.ts";
import { createApp, createUnixSocketHandler } from "./server.ts";

const logger = createLogger("enigma");

function buildVault(): { vault: CredentialVault; extra: ReturnType<typeof resolveEnigmaExtraPaths> } {
	const paths = resolveEnigmaPaths();
	const extra = resolveEnigmaExtraPaths(paths);
	const masterKey = resolveConfiguredMasterKey(extra);
	return { vault: createCredentialVault({ dir: extra.credentialsDir, masterKey }), extra };
}

/**
 * ENIGMA_ADMIN_UID names the one OS uid trusted for full admin access over
 * the Unix-socket transport -- typically the human operator's own uid,
 * configured once in the systemd unit. Absent by default: without it, the
 * Unix socket still authenticates registered clients via their own bound
 * uid, but nothing gets unscoped admin access through it (the existing
 * TCP+bearer-token admin path is unaffected either way).
 */
function resolveAdminUid(env: NodeJS.ProcessEnv): number | undefined {
	const raw = env.ENIGMA_ADMIN_UID;
	if (raw === undefined) return undefined;
	const uid = Number(raw);
	if (!Number.isInteger(uid) || uid < 0) throw new Error(`ENIGMA_ADMIN_UID must be a non-negative integer, got "${raw}"`);
	return uid;
}

/**
 * ENIGMA_POLKIT_ENABLED opts into asking polkit whether a non-admin
 * Unix-socket caller is authorized for POST /clients specifically --
 * absent by default, matching this whole project's "reachable is not the
 * same as wanted" stance: polkit (and pkcheck) happening to be installed
 * on the host is never itself a reason to start consulting it.
 */
function polkitEnabled(env: NodeJS.ProcessEnv): boolean {
	return env.ENIGMA_POLKIT_ENABLED === "1" || env.ENIGMA_POLKIT_ENABLED === "true";
}

/** Vault-only mode — the only mode. Every consumer fetches its own credential over the authenticated API; Enigma never spawns or supervises anything. */
export function serveMain(): void {
	const paths = resolveEnigmaPaths();
	const token = ensureAuthToken(paths.token, "Enigma");
	const { vault, extra } = buildVault();
	const clients = createClientRegistry(extra.clientRegistryFile);
	// Tool/operation usage metrics -- see request-metrics.ts's own header comment for why this
	// daemon records/exposes them by hand instead of useExecutionMiddleware/
	// registerVehicleMetricsOperations (no VehicleRegistry exists here). Queryable via the
	// admin-only GET /metrics route in server.ts. mkdirSync first: unlike every other Vehicle
	// daemon in this ecosystem, Enigma is vault-only and never opens its own paths.database
	// (see paths.ts) -- nothing else has ever created this directory before.
	mkdirSync(dirname(paths.metrics), { recursive: true });
	const metrics = openVehicleMetricsStore(paths.metrics);
	const deps = {
		vault,
		token,
		clients,
		logger,
		metrics,
		...(polkitEnabled(process.env) ? { polkitCheck: createPkcheckAuthorizer() } : {}),
	};

	// World-connectable: any OS user's process may attempt to connect (SO_PEERCRED verifies
	// who they actually are afterward, which a file permission bit can't do more precisely
	// than "connect or don't") -- unlike the bearer-token file, connecting here proves nothing
	// by itself, so there is nothing to protect by narrowing who may open the socket.
	const unixSocketPath = join(dirname(paths.handle), ADMIN_SOCKET_FILENAME);
	const unixServer = serveUnixRpc({
		path: unixSocketPath,
		mode: 0o666,
		handler: createUnixSocketHandler(deps, { adminUid: resolveAdminUid(process.env) }),
		onError: (err) => logger.warn("unix-rpc error", { error: err instanceof Error ? err.message : String(err) }),
	});

	runDaemonProcess({
		daemonLabel: "Enigma",
		handlePath: paths.handle,
		// World-readable: Enigma is a cross-user system service (its consumers run under
		// their own OS users, not Enigma's), and the handle's own content (host/port/pid)
		// is never sensitive -- the token file stays owner-only regardless.
		handleMode: 0o644,
		logger,
		buildApp: () => createApp(deps),
		onListen: ({ host, port }) => logger.info("listening", { host, port, unixSocketPath }),
		onShutdown: () => {
			unixServer.stop();
			metrics.close();
		},
	});
}
