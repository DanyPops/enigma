/**
 * Enigma's client-registry as a vehicle-client-pi ServicesRegistry -- the
 * [services] side of the /secrets model. VaultClientRecord and
 * ServiceRecord are already the same shape by design (see client.ts's own
 * doc comment), so this is a direct pass-through, not a real mapping.
 */
import type { ServicesRegistry } from "@danypops/vehicle-client-pi/secrets-backend";
import type { EnigmaAdminClient } from "./client.ts";

export function createEnigmaServicesRegistry(client: EnigmaAdminClient): ServicesRegistry {
	return { list: () => client.listClients() };
}
