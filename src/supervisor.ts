/**
 * Owns everything daemon-kit's generic spawnUnit deliberately doesn't:
 * restart policy, credential resolution per unit, and a well-defined
 * shutdown contract. Runs in-process with the vault server (one `enigma
 * supervisor` process does both), so credential lookups go straight
 * through the in-process CredentialVault — no HTTP round-trip to itself.
 */
import { spawnUnit, type DaemonUnit, type SpawnedUnit, type SupervisorConfig } from "@danypops/daemon-kit/supervisor";
import { isTokenFresh } from "@danypops/daemon-kit/vault";
import type { Logger } from "@danypops/daemon-kit/logging";
import { ALL_CREDENTIAL_ENV_VAR_NAMES, mapCredentialToEnv } from "./backend-env-mapping.ts";
import type { CredentialVault } from "./credential-vault.ts";

const NOOP_LOGGER: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const DEFAULT_FRESHNESS_CHECK_MS = 30_000;

export interface RunningSupervisor {
	stop(): Promise<void>;
}

interface ManagedUnit {
	unit: DaemonUnit;
	current?: SpawnedUnit;
	stopping: boolean;
	/** Set just before a freshness-triggered kill so the exit handler relaunches unconditionally, bypassing restart policy — policy governs unplanned exits (crashes), not a refresh WE initiated. */
	refreshing: boolean;
}

/**
 * Every env var name that *could* apply across the whole supervisor
 * config, not just one unit — the four built-ins' fixed names plus
 * whatever `envVarName` each declared backend's *stored* credential
 * actually carries (arbitrary, operator-chosen names included). Computed
 * fresh from the current config + vault state rather than a static
 * constant, since an operator can add a new generic OIDC backend between
 * supervisor restarts and its var name must be scrubbable too.
 */
function collectAllPossibleEnvVarNames(config: SupervisorConfig, vault: CredentialVault): Set<string> {
	const names = new Set<string>(ALL_CREDENTIAL_ENV_VAR_NAMES);
	for (const unit of config.units) {
		for (const backend of unit.backends) {
			const credential = vault.get(backend);
			if (!credential) continue;
			for (const name of Object.keys(mapCredentialToEnv(backend, credential))) names.add(name);
		}
	}
	return names;
}

/**
 * Starts from an all-blank baseline covering every credential-shaped var
 * name any unit in this config could produce, then overlays only this
 * unit's own requested backends' real values — so an ambient value on
 * enigma's own process for a var this unit never asked for is always
 * overridden to "", never silently inherited through spawnUnit's
 * parent-env passthrough. Covers arbitrarily-named generic OIDC backends
 * exactly the same way it covers the four built-ins.
 */
function resolveUnitEnv(unit: DaemonUnit, vault: CredentialVault, allPossibleNames: Set<string>): Record<string, string> {
	const env: Record<string, string> = Object.fromEntries([...allPossibleNames].map((name) => [name, ""]));
	for (const backend of unit.backends) {
		const credential = vault.get(backend);
		if (!credential) continue; // missing credential: spawn anyway, best-effort — the unit's own env resolution will surface the gap
		Object.assign(env, mapCredentialToEnv(backend, credential));
	}
	return env;
}

function unitCredentialsAreFresh(unit: DaemonUnit, vault: CredentialVault): boolean {
	return unit.backends.every((backend) => {
		const credential = vault.get(backend);
		return !credential || isTokenFresh(credential);
	});
}

export interface RunSupervisorOptions {
	logger?: Logger;
	/** Overridable for tests; production default is 30s. */
	freshnessCheckMs?: number;
}

/**
 * Spawns every configured unit, restarts per its own policy on exit, and
 * periodically checks whether any running unit's credentials are nearing
 * expiry — if so, restarts that unit with freshly resolved env. This is
 * the simple, correct choice for this pass: a brief interruption on
 * refresh rather than a hot-swap (e.g. SIGUSR1 triggering the child to
 * re-read env without restarting), which is a documented future
 * optimization, not built here.
 */
export function runSupervisor(config: SupervisorConfig, vault: CredentialVault, options: RunSupervisorOptions = {}): RunningSupervisor {
	const logger = options.logger ?? NOOP_LOGGER;
	const managed: ManagedUnit[] = config.units.map((unit) => ({ unit, stopping: false, refreshing: false }));

	function launch(entry: ManagedUnit): void {
		const env = resolveUnitEnv(entry.unit, vault, collectAllPossibleEnvVarNames(config, vault));
		const spawned = spawnUnit(entry.unit, env);
		entry.current = spawned;
		logger.info("unit started", { name: entry.unit.name, pid: spawned.pid });

		void spawned.exited.then((code) => {
			if (entry.stopping) return;
			logger.info("unit exited", { name: entry.unit.name, code });
			if (entry.refreshing) {
				entry.refreshing = false;
				launch(entry);
				return;
			}
			const policy = entry.unit.restart ?? "no";
			const shouldRestart = policy === "always" || (policy === "on-failure" && code !== 0);
			if (shouldRestart) launch(entry);
		});
	}

	for (const entry of managed) launch(entry);

	const freshnessTimer = setInterval(() => {
		for (const entry of managed) {
			if (entry.stopping || !entry.current) continue;
			if (!unitCredentialsAreFresh(entry.unit, vault)) {
				logger.info("unit credentials nearing expiry, restarting with fresh env", { name: entry.unit.name });
				entry.refreshing = true;
				entry.current.kill("SIGTERM");
				// The exited-promise handler above launches the replacement once this
				// process actually exits; not launched here to avoid a double-spawn race.
			}
		}
	}, options.freshnessCheckMs ?? DEFAULT_FRESHNESS_CHECK_MS);

	return {
		/** Documented shutdown contract: every child gets SIGTERM and stop() waits for all of them to exit. */
		async stop(): Promise<void> {
			clearInterval(freshnessTimer);
			for (const entry of managed) {
				entry.stopping = true;
				entry.current?.kill("SIGTERM");
			}
			await Promise.all(managed.map((entry) => entry.current?.exited).filter((p): p is Promise<number> => p !== undefined));
		},
	};
}
