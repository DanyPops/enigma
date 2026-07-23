/** Enigma's own CLI is just a VaultClient consumer, same interface any other daemon-kit process would use to talk to a running vault. */
import { ensureAuthToken, readDaemonHandle } from "@danypops/daemon-kit/paths";
import { createVaultClient, type VaultClient } from "@danypops/daemon-kit/vault";
import { resolveEnigmaPaths } from "./paths.ts";

export function connectEnigmaClient(paths = resolveEnigmaPaths()): VaultClient {
	const handle = readDaemonHandle(paths.handle);
	if (!handle) throw new Error("Enigma daemon is not running; run `enigma serve` or `enigma supervisor`.");
	const token = ensureAuthToken(paths.token, "Enigma");
	return createVaultClient({ baseUrl: `http://${handle.host}:${handle.port}`, authToken: token });
}
