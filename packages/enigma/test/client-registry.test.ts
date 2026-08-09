import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ClientAlreadyRegisteredError, ClientNotFoundError, createClientRegistry, UidAlreadyBoundError } from "../src/client-registry.ts";

const tmpDirs: string[] = [];

afterEach(() => {
	for (const dir of tmpDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function registryPath(): string {
	const dir = mkdtempSync(join(tmpdir(), "enigma-client-registry-"));
	tmpDirs.push(dir);
	return join(dir, "clients.json");
}

describe("createClientRegistry", () => {
	it("add() returns a usable token that authenticate() resolves back to the client", () => {
		const registry = createClientRegistry(registryPath());
		const token = registry.add("tickets", ["jira", "github"]);
		const resolved = registry.authenticate(token);
		expect(resolved?.name).toBe("tickets");
		expect(resolved?.backends).toEqual(["jira", "github"]);
	});

	it("add() normalizes backend names to lowercase -- a backend name is a lookup key, not display text", () => {
		const registry = createClientRegistry(registryPath());
		const token = registry.add("acme-consumer", ["WidgetApi", "GADGETAPI"]);
		expect(registry.authenticate(token)?.backends).toEqual(["widgetapi", "gadgetapi"]);
		expect(registry.list()[0]?.backends).toEqual(["widgetapi", "gadgetapi"]);
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

describe("createClientRegistry: SO_PEERCRED uid binding, alongside bearer-token auth", () => {
	it("add() accepts an optional uid, and authenticateByUid() resolves it back to the client", () => {
		const registry = createClientRegistry(registryPath());
		registry.add("tickets", ["jira", "github"], { uid: 1001 });
		const resolved = registry.authenticateByUid(1001);
		expect(resolved?.name).toBe("tickets");
		expect(resolved?.backends).toEqual(["jira", "github"]);
	});

	it("authenticateByUid() resolves undefined for a uid no client is bound to", () => {
		const registry = createClientRegistry(registryPath());
		registry.add("tickets", ["jira"], { uid: 1001 });
		expect(registry.authenticateByUid(9999)).toBeUndefined();
	});

	it("a client registered with no uid is never resolved by authenticateByUid() -- token auth still works for it unaffected", () => {
		const registry = createClientRegistry(registryPath());
		const token = registry.add("pipes", ["github"]);
		expect(registry.authenticateByUid(1001)).toBeUndefined();
		expect(registry.authenticate(token)?.name).toBe("pipes");
	});

	it("refuses to bind a uid that's already bound to a different client -- a uid can only ever resolve to one client", () => {
		const registry = createClientRegistry(registryPath());
		registry.add("tickets", ["jira"], { uid: 1001 });
		expect(() => registry.add("pipes", ["github"], { uid: 1001 })).toThrow(UidAlreadyBoundError);
	});

	it("rotate() preserves the bound uid -- only the token changes", () => {
		const registry = createClientRegistry(registryPath());
		registry.add("tickets", ["jira"], { uid: 1001 });
		registry.rotate("tickets");
		expect(registry.authenticateByUid(1001)?.name).toBe("tickets");
	});

	it("remove() frees the uid for reuse by a future registration", () => {
		const registry = createClientRegistry(registryPath());
		registry.add("tickets", ["jira"], { uid: 1001 });
		registry.remove("tickets");
		expect(registry.authenticateByUid(1001)).toBeUndefined();
		registry.add("pipes", ["github"], { uid: 1001 });
		expect(registry.authenticateByUid(1001)?.name).toBe("pipes");
	});

	it("list() surfaces the bound uid for admin visibility, omitted entirely when unset", () => {
		const registry = createClientRegistry(registryPath());
		registry.add("tickets", ["jira"], { uid: 1001 });
		registry.add("pipes", ["github"]);
		const listed = registry.list();
		expect(listed.find((c) => c.name === "tickets")?.uid).toBe(1001);
		expect(listed.find((c) => c.name === "pipes")?.uid).toBeUndefined();
	});
});
