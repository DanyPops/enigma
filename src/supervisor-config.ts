import type { SupervisorConfig } from "@danypops/daemon-kit/supervisor";
import { existsSync, readFileSync } from "node:fs";

/** Missing config file means zero units, not an error — `enigma supervisor` with nothing configured yet should still boot the vault. */
export function loadSupervisorConfig(path: string): SupervisorConfig {
	if (!existsSync(path)) return { units: [] };
	const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
	if (typeof parsed !== "object" || parsed === null || !Array.isArray((parsed as SupervisorConfig).units)) {
		throw new Error(`supervisor config at ${path} must be an object with a "units" array`);
	}
	for (const unit of (parsed as SupervisorConfig).units) {
		if (!unit.name || !unit.bin || !Array.isArray(unit.backends)) {
			throw new Error(`supervisor config at ${path} has a unit missing required fields (name, bin, backends)`);
		}
	}
	return parsed as SupervisorConfig;
}
