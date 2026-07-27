/**
 * Owns only what's genuinely Enigma-specific: credential resolution per unit
 * and the freshness predicate that triggers a restart. Restart-policy
 * interpretation, the planned-restart mechanism, and the shutdown contract
 * moved to @danypops/daemon-kit/process-supervisor (generalized directly from
 * this module's own prior implementation, once it became clear none of that
 * was actually about credentials). Runs in-process with the vault server (one
 * `enigma supervisor` process does both), so credential lookups go straight
 * through the in-process CredentialVault -- no HTTP round-trip to itself.
 */
import { runProcessSupervisor, type RunningProcessSupervisor, type SupervisedUnitConfig } from "@danypops/daemon-kit/process-supervisor";
import type { DaemonUnit, SupervisorConfig } from "@danypops/daemon-kit/supervisor";
import { isTokenFresh } from "@danypops/daemon-kit/vault";
import type { Logger } from "@danypops/daemon-kit/logging";
import { ALL_CREDENTIAL_ENV_VAR_NAMES, mapCredentialToEnv } from "./backend-env-mapping.ts";
import type { CredentialVault } from "./credential-vault.ts";

export type RunningSupervisor = RunningProcessSupervisor;

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
	const units: SupervisedUnitConfig[] = config.units.map((unit) => ({
		...unit,
		// Recomputed on every (re)launch, not once at supervisor start -- an
		// operator can register a new backend's credential between restarts.
		resolveEnv: () => resolveUnitEnv(unit, vault, collectAllPossibleEnvVarNames(config, vault)),
		shouldPlannedRestart: () => !unitCredentialsAreFresh(unit, vault),
	}));

	return runProcessSupervisor(units, { logger: options.logger, plannedRestartCheckMs: options.freshnessCheckMs });
}
