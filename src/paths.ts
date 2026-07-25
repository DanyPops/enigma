import { dirname, join } from "node:path";
import { type DaemonPaths, type PathEnvironment, resolveDaemonPaths } from "@danypops/daemon-kit/paths";
import {
	CREDENTIALS_DIRECTORY_NAME,
	DATABASE_FILENAME,
	HANDLE_FILENAME,
	MASTER_KEY_FILENAME,
	MASTER_KEY_PROVIDER_FILENAME,
	STATE_DIRECTORY_NAME,
	SUPERVISOR_CONFIG_FILENAME,
	SYSTEMD_UNIT_NAME,
	TOKEN_FILENAME,
} from "./constants.ts";

export function resolveEnigmaPaths(options: PathEnvironment = {}): DaemonPaths {
	return resolveDaemonPaths(
		{
			stateDirectoryName: STATE_DIRECTORY_NAME,
			databaseFilename: DATABASE_FILENAME,
			tokenFilename: TOKEN_FILENAME,
			handleFilename: HANDLE_FILENAME,
			systemdUnitName: SYSTEMD_UNIT_NAME,
		},
		options,
	);
}

export interface EnigmaExtraPaths {
	credentialsDir: string;
	masterKeyFile: string;
	masterKeyProviderFile: string;
	supervisorConfig: string;
}

/** Provider metadata and encrypted credential state share one owner-only daemon state root. */
export function resolveEnigmaExtraPaths(paths: DaemonPaths): EnigmaExtraPaths {
	const stateDirectory = dirname(paths.token);
	return {
		credentialsDir: join(stateDirectory, CREDENTIALS_DIRECTORY_NAME),
		masterKeyFile: join(stateDirectory, MASTER_KEY_FILENAME),
		masterKeyProviderFile: join(stateDirectory, MASTER_KEY_PROVIDER_FILENAME),
		supervisorConfig: join(stateDirectory, SUPERVISOR_CONFIG_FILENAME),
	};
}
