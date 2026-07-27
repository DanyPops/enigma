import { describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ClientAlreadyRegisteredError, ClientNotFoundError, createClientRegistry } from "../src/client-registry.ts";

function registryPath(): string {
	return join(mkdtempSync(join(tmpdir(), "enigma-client-registry-")), "clients.json");
}

describe("createClientRegistry", () => {
	it("add() returns a usable token that authenticate() resolves back to the client", () => {
		const registry = createClientRegistry(registryPath());
		const token = registry.add("tickets", ["jira", "github"]);
		const resolved = registry.authenticate(token);
		expect(resolved?.name).toBe("tickets");
		expect(resolved?.backends).toEqual(["jira", "github"]);
	});

	it("never stores the plaintext token at rest -- only its hash", () => {
		const path = registryPath();
		const registry = createClientRegistry(path);
		const token = registry.add("tickets", ["jira"]);
		const onDisk = readFileSync(path, "utf8");
		expect(onDisk).not.toContain(token);
	});

	it("rejects a token belonging to a different client", () => {
		const registry = createClientRegistry(registryPath());
		registry.add("tickets", ["jira"]);
		registry.add("pipes", ["github", "jenkins"]);
		expect(registry.authenticate("not-a-real-token")).toBeUndefined();
	});

	it("refuses to register the same name twice", () => {
		const registry = createClientRegistry(registryPath());
		registry.add("tickets", ["jira"]);
		expect(() => registry.add("tickets", ["github"])).toThrow(ClientAlreadyRegisteredError);
	});

	it("rotate() invalidates the old token and issues a new one for the same client+backends", () => {
		const registry = createClientRegistry(registryPath());
		const oldToken = registry.add("tickets", ["jira", "github"]);
		const newToken = registry.rotate("tickets");
		expect(newToken).not.toBe(oldToken);
		expect(registry.authenticate(oldToken)).toBeUndefined();
		const resolved = registry.authenticate(newToken);
		expect(resolved?.name).toBe("tickets");
		expect(resolved?.backends).toEqual(["jira", "github"]);
	});

	it("rotate() on an unregistered name throws ClientNotFoundError", () => {
		const registry = createClientRegistry(registryPath());
		expect(() => registry.rotate("ghost")).toThrow(ClientNotFoundError);
	});

	it("remove() deletes the registration and invalidates its token", () => {
		const registry = createClientRegistry(registryPath());
		const token = registry.add("tickets", ["jira"]);
		registry.remove("tickets");
		expect(registry.authenticate(token)).toBeUndefined();
		expect(registry.list()).toEqual([]);
	});

	it("remove() on an unregistered name throws ClientNotFoundError", () => {
		const registry = createClientRegistry(registryPath());
		expect(() => registry.remove("ghost")).toThrow(ClientNotFoundError);
	});

	it("list() never includes token hashes", () => {
		const registry = createClientRegistry(registryPath());
		registry.add("tickets", ["jira", "github"]);
		registry.add("pipes", ["jenkins"]);
		const listed = registry.list();
		expect(listed).toEqual([
			{ name: "tickets", backends: ["jira", "github"], createdAt: expect.any(String) },
			{ name: "pipes", backends: ["jenkins"], createdAt: expect.any(String) },
		]);
		for (const entry of listed) expect(entry).not.toHaveProperty("tokenHash");
	});

	it("persists across separate createClientRegistry calls against the same path", () => {
		const path = registryPath();
		const token = createClientRegistry(path).add("tickets", ["jira"]);
		const reopened = createClientRegistry(path);
		expect(reopened.authenticate(token)?.name).toBe("tickets");
	});
});
