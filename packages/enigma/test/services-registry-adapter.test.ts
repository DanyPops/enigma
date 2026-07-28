import { describe, expect, it } from "bun:test";
import type { EnigmaAdminClient, VaultClientRecord } from "../src/client.ts";
import { createEnigmaServicesRegistry } from "../src/services-registry-adapter.ts";

function fakeClient(clients: VaultClientRecord[]): EnigmaAdminClient {
	return {
		listCredentialKeys: async () => [],
		getCredentials: async () => undefined,
		rotateCredential: async () => {},
		revokeCredential: async () => {},
		listClients: async () => clients,
		health: async () => ({ ok: true, version: "test" }),
	};
}

describe("createEnigmaServicesRegistry", () => {
	it("passes Enigma's own client-registry records straight through -- already the same shape as ServiceRecord", async () => {
		const registry = createEnigmaServicesRegistry(fakeClient([{ name: "pipes", backends: ["github", "jenkins-ci"] }, { name: "tickets", backends: ["github", "jira"], uid: 1001 }]));
		expect(await registry.list()).toEqual([
			{ name: "pipes", backends: ["github", "jenkins-ci"] },
			{ name: "tickets", backends: ["github", "jira"], uid: 1001 },
		]);
	});

	it("returns [] when no clients are registered yet", async () => {
		const registry = createEnigmaServicesRegistry(fakeClient([]));
		expect(await registry.list()).toEqual([]);
	});
});
