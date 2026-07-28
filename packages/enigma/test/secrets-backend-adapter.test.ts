import { describe, expect, it } from "bun:test";
import type { EnigmaAdminClient, VaultCredential } from "../src/client.ts";
import { createEnigmaSecretsBackend } from "../src/secrets-backend-adapter.ts";

function fakeClient(records: Record<string, VaultCredential>): EnigmaAdminClient & { rotated: string[]; revoked: string[] } {
	const client = {
		rotated: [] as string[],
		revoked: [] as string[],
		listCredentialKeys: async () => Object.keys(records),
		getCredentials: async (backend: string) => records[backend],
		rotateCredential: async (backend: string) => {
			client.rotated.push(backend);
		},
		revokeCredential: async (backend: string) => {
			client.revoked.push(backend);
			delete records[backend];
		},
		listClients: async () => [],
		health: async () => ({ ok: true, version: "test" }),
	};
	return client;
}

describe("createEnigmaSecretsBackend", () => {
	it("source is 'enigma'", () => {
		expect(createEnigmaSecretsBackend(fakeClient({})).source).toBe("enigma");
	});

	it("list() maps every vault key to a redacted SecretRecord -- never accessToken/refreshToken/extra", async () => {
		const client = fakeClient({ github: { accessToken: "gho_x", scope: "repo", extra: { cloudId: "abc" } } });
		const records = await createEnigmaSecretsBackend(client).list();
		expect(records).toEqual([{ name: "github", source: "enigma", configured: true, scope: "repo" }]);
	});

	it("get() resolves undefined for a backend Enigma has no credential for", async () => {
		const client = fakeClient({});
		expect(await createEnigmaSecretsBackend(client).get("github")).toBeUndefined();
	});

	it("get() surfaces expiresAt", async () => {
		const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
		const client = fakeClient({ jenkins: { accessToken: "x", expiresAt } });
		expect(await createEnigmaSecretsBackend(client).get("jenkins")).toEqual({ name: "jenkins", source: "enigma", configured: true, expiresAt });
	});

	it("rotate() delegates to the client's own rotateCredential", async () => {
		const client = fakeClient({ github: { accessToken: "x" } });
		await createEnigmaSecretsBackend(client).rotate("github");
		expect(client.rotated).toEqual(["github"]);
	});

	it("revoke() delegates to the client's own revokeCredential", async () => {
		const client = fakeClient({ github: { accessToken: "x" } });
		await createEnigmaSecretsBackend(client).revoke("github");
		expect(client.revoked).toEqual(["github"]);
	});

	it("reveal() returns the full credential unredacted, unlike get()/list()", async () => {
		const client = fakeClient({ github: { accessToken: "gho_real_value", refreshToken: "refresh_real_value", scope: "repo", extra: { cloudId: "abc" } } });
		expect(await createEnigmaSecretsBackend(client).reveal("github")).toEqual({
			accessToken: "gho_real_value",
			refreshToken: "refresh_real_value",
			scope: "repo",
			extra: { cloudId: "abc" },
		});
	});

	it("reveal() resolves undefined for a backend Enigma has no credential for", async () => {
		const client = fakeClient({});
		expect(await createEnigmaSecretsBackend(client).reveal("github")).toBeUndefined();
	});

	it("reveal() calls the client's own getCredentials -- the same path get()/list() use, and the same audited GET /creds/:backend route enigma show uses", async () => {
		const calls: string[] = [];
		const client = fakeClient({ github: { accessToken: "x" } });
		const originalGetCredentials = client.getCredentials;
		client.getCredentials = async (backend: string) => {
			calls.push(backend);
			return originalGetCredentials(backend);
		};
		await createEnigmaSecretsBackend(client).reveal("github");
		expect(calls).toEqual(["github"]);
	});
});
