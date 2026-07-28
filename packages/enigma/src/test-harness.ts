/**
 * An in-process, real Enigma instance for a consumer's own integration
 * tests -- the same pattern HashiCorp Vault's own vault.NewTestCluster and
 * Testcontainers' Vault module use: never mock the vault itself, only the
 * setup shortcut (a fixed test master key, pre-seeded secrets written
 * directly rather than through a real login flow). Everything a consumer
 * touches -- the HTTP wire protocol, the credential vault's real
 * encryption, the client registry's real least-privilege scoping -- is the
 * genuine production code path, indistinguishable from a real deployment.
 *
 * Simulates the real privilege boundary honestly rather than by OS-level
 * separation (no root available in a portable test environment): a
 * consumer using this harness is only ever handed `baseUrl` and issued
 * tokens, the same two things it would have against a real deployment --
 * never a reference to the vault or registry objects themselves, so there
 * is no shortcut to read a secret except through an authenticated request,
 * exactly like production.
 *
 * Bun-native raw TypeScript (Bun.serve, no compiled dist boundary) -- a
 * Node/tsc-targeted consumer's own tsc --noEmit over its test files may need
 * the same scoped-boundary treatment already applied to other Bun-native
 * packages in this ecosystem if it hits unresolvable Bun-only globals.
 * Works today for any Bun-based consumer (bun test), which is every
 * realistic caller: exercising this harness at runtime always needs Bun
 * regardless of how the importing file itself is type-checked.
 */
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createClientRegistry } from "./client-registry.ts";
import { createCredentialVault } from "./credential-vault.ts";
import { createApp } from "./server.ts";

export interface EnigmaTestHarness {
	baseUrl: string;
	/** Unscoped -- reaches any seeded backend, mirroring the real admin/client distinction. */
	adminToken: string;
	/** Registers a client via the real registry, returns its token -- scoped exactly like a real `enigma client add`. */
	registerClient(name: string, backends: string[]): string;
	/** Writes a real encrypted credential directly into the vault -- bypasses the login flow's OAuth mechanics (out of scope for this harness), but the storage and later retrieval are the genuine production code path. */
	seedCredential(backend: string, accessToken: string, extra?: Record<string, string>): Promise<void>;
	stop(): void;
}

export async function startEnigmaTestHarness(): Promise<EnigmaTestHarness> {
	const dir = mkdtempSync(join(tmpdir(), "enigma-test-harness-"));
	const masterKey = randomBytes(32);
	const vault = createCredentialVault({ dir: join(dir, "credentials"), masterKey });
	const clients = createClientRegistry(join(dir, "clients.json"));
	const adminToken = randomBytes(32).toString("hex");
	const app = createApp({ vault, token: adminToken, clients });

	const server = Bun.serve({ port: 0, fetch: (request) => app.fetch(request) });

	return {
		baseUrl: `http://127.0.0.1:${server.port}`,
		adminToken,
		registerClient: (name, backends) => clients.add(name, backends),
		seedCredential: async (backend, accessToken, extra = {}) => {
			vault.save(backend, { accessToken, extra });
		},
		stop: () => {
			server.stop(true);
			rmSync(dir, { recursive: true, force: true });
		},
	};
}
