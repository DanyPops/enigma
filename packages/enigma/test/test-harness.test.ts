/**
 * Tests the harness itself, not Enigma's own logic (already covered
 * elsewhere) -- proves a consumer using this harness genuinely exercises
 * the real vault, real registry, and real HTTP wire protocol, with no
 * shortcut available to peek at a secret except through an authenticated
 * call, exactly mirroring the privilege boundary a real deployment has
 * (Enigma holds the secret; a consumer only ever gets it back through the
 * API with a token). See HashiCorp Vault's own vault.NewTestCluster and
 * Testcontainers' Vault module for the same "real server, real API,
 * pre-seeded secrets" pattern this mirrors.
 */
import { describe, expect, it } from "bun:test";
import { startEnigmaTestHarness } from "../src/test-harness.ts";

describe("startEnigmaTestHarness", () => {
	it("seeds a real encrypted credential and serves it back only to a token authorized for that backend", async () => {
		const harness = await startEnigmaTestHarness();
		try {
			await harness.seedCredential("brave", "real-brave-secret", { envVarName: "BRAVE_SEARCH_API_KEY" });
			const clientToken = harness.registerClient("web-spider", ["brave"]);

			const response = await fetch(`${harness.baseUrl}/creds/brave`, { headers: { authorization: `Bearer ${clientToken}` } });
			expect(response.status).toBe(200);
			expect(await response.json()).toEqual({ accessToken: "real-brave-secret", extra: { envVarName: "BRAVE_SEARCH_API_KEY" } });
		} finally {
			harness.stop();
		}
	});

	it("rejects a client's token for a backend it wasn't registered for -- the harness enforces the same least-privilege scoping as production", async () => {
		const harness = await startEnigmaTestHarness();
		try {
			await harness.seedCredential("jenkins", "jenkins-secret");
			const clientToken = harness.registerClient("web-spider", ["brave"]);

			const response = await fetch(`${harness.baseUrl}/creds/jenkins`, { headers: { authorization: `Bearer ${clientToken}` } });
			expect(response.status).toBe(403);
		} finally {
			harness.stop();
		}
	});

	it("rejects any request with no token or a wrong token, same as a real deployment", async () => {
		const harness = await startEnigmaTestHarness();
		try {
			await harness.seedCredential("brave", "real-brave-secret");
			const noAuth = await fetch(`${harness.baseUrl}/creds/brave`);
			expect(noAuth.status).toBe(401);
			const wrongToken = await fetch(`${harness.baseUrl}/creds/brave`, { headers: { authorization: "Bearer not-a-real-token" } });
			expect(wrongToken.status).toBe(401);
		} finally {
			harness.stop();
		}
	});

	it("the admin token can reach any seeded backend, unscoped -- mirrors the real admin/client distinction", async () => {
		const harness = await startEnigmaTestHarness();
		try {
			await harness.seedCredential("brave", "brave-secret");
			await harness.seedCredential("jenkins", "jenkins-secret");
			const brave = await fetch(`${harness.baseUrl}/creds/brave`, { headers: { authorization: `Bearer ${harness.adminToken}` } });
			const jenkins = await fetch(`${harness.baseUrl}/creds/jenkins`, { headers: { authorization: `Bearer ${harness.adminToken}` } });
			expect(brave.status).toBe(200);
			expect(jenkins.status).toBe(200);
		} finally {
			harness.stop();
		}
	});

	it("a real consumer library call (tryEnigmaCredential-shaped fetch) round-trips end to end against the harness", async () => {
		const harness = await startEnigmaTestHarness();
		try {
			await harness.seedCredential("tavily", "tavily-secret", { envVarName: "TAVILY_API_KEY" });
			const clientToken = harness.registerClient("web-spider", ["tavily"]);

			// Deliberately the exact shape enigma-client's own tryEnigmaCredential uses internally --
			// proves the harness is indistinguishable from a real deployment to a real consumer.
			const response = await fetch(`${harness.baseUrl}/creds/tavily`, {
				headers: { authorization: `Bearer ${clientToken}` },
				signal: AbortSignal.timeout(500),
			});
			const credential = await response.json();
			expect(credential).toEqual({ accessToken: "tavily-secret", extra: { envVarName: "TAVILY_API_KEY" } });
		} finally {
			harness.stop();
		}
	});

	it("two independently-started harnesses never share state", async () => {
		const first = await startEnigmaTestHarness();
		const second = await startEnigmaTestHarness();
		try {
			await first.seedCredential("brave", "first-secret");
			const secondResponse = await fetch(`${second.baseUrl}/creds/brave`, { headers: { authorization: `Bearer ${second.adminToken}` } });
			expect(secondResponse.status).toBe(404);
		} finally {
			first.stop();
			second.stop();
		}
	});
});
