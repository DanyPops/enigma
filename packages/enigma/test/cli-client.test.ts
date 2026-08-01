/**
 * clientMain, tested directly rather than as a real subprocess: it's a
 * thin dispatcher (parse args -> try RPC -> fall back to a local registry),
 * and every dependency (the RPC functions, the admin client, the registry
 * itself) is injectable so no test touches the real filesystem or network.
 */
import { describe, expect, it } from "bun:test";
import { type ClientMainDeps, clientMain } from "../src/cli.ts";
import type { EnigmaAdminClient, VaultClientRecord } from "../src/client.ts";
import type { ClientRegistry } from "../src/client-registry.ts";
import { ClientAlreadyRegisteredError, ClientNotFoundError, UidAlreadyBoundError } from "../src/client-registry.ts";

function fakeRegistry(overrides: Partial<ClientRegistry> = {}): ClientRegistry {
	return {
		add: () => "local-token",
		rotate: () => "local-rotated-token",
		remove: () => {},
		list: () => [],
		authenticate: () => undefined,
		authenticateByUid: () => undefined,
		...overrides,
	};
}

function fakeAdminClient(overrides: Partial<EnigmaAdminClient> = {}): EnigmaAdminClient {
	return {
		listCredentialKeys: async () => [],
		getCredentials: async () => undefined,
		rotateCredential: async () => {},
		revokeCredential: async () => {},
		listClients: async () => [],
		health: async () => ({ ok: true, version: "test" }),
		...overrides,
	};
}

function captureConsole(): { logs: string[]; errors: string[]; restore: () => void } {
	const logs: string[] = [];
	const errors: string[] = [];
	const originalLog = console.log;
	const originalError = console.error;
	console.log = (msg: string) => logs.push(msg);
	console.error = (msg: string) => errors.push(msg);
	return {
		logs,
		errors,
		restore: () => {
			console.log = originalLog;
			console.error = originalError;
		},
	};
}

async function runExpectingExit(fn: () => Promise<void>): Promise<number | undefined> {
	const originalExit = process.exit;
	let exitCode: number | undefined;
	process.exit = ((code?: number) => {
		exitCode = code;
		throw new Error("exit");
	}) as never;
	try {
		await fn();
	} catch {
		// expected -- our fake process.exit throws to unwind instead of terminating
	} finally {
		process.exit = originalExit;
	}
	return exitCode;
}

describe("clientMain add", () => {
	it("registers via the running daemon when reachable, never touching the local registry", async () => {
		const registry = fakeRegistry({
			add: () => {
				throw new Error("must not touch the local registry when the daemon is reachable");
			},
		});
		const deps: ClientMainDeps = { registry, addEnigmaClient: async () => ({ ok: true, token: "rpc-token" }) };
		const { logs, restore } = captureConsole();
		try {
			await clientMain(["add", "web-spider", "--backends", "brave,tavily"], deps);
		} finally {
			restore();
		}
		expect(logs[0]).toContain("via the running daemon");
		expect(logs[1]).toBe("rpc-token");
	});

	it("falls back to the local registry when the daemon isn't reachable at all", async () => {
		const registry = fakeRegistry({
			add: (name, backends) => {
				expect(name).toBe("web-spider");
				expect(backends).toEqual(["brave", "tavily"]);
				return "local-token";
			},
		});
		const deps: ClientMainDeps = { registry, addEnigmaClient: async () => undefined };
		const { logs, restore } = captureConsole();
		try {
			await clientMain(["add", "web-spider", "--backends", "brave,tavily"], deps);
		} finally {
			restore();
		}
		expect(logs[0]).not.toContain("via the running daemon");
		expect(logs[1]).toBe("local-token");
	});

	it("surfaces a real rejection from the running daemon directly, never falling back to a phantom local registration", async () => {
		const registry = fakeRegistry({
			add: () => {
				throw new Error("must not touch the local registry after a real remote rejection");
			},
		});
		const deps: ClientMainDeps = {
			registry,
			addEnigmaClient: async () => ({ ok: false, status: 409, error: 'client "web-spider" is already registered' }),
		};
		const { errors, restore } = captureConsole();
		const exitCode = await runExpectingExit(async () => {
			await clientMain(["add", "web-spider", "--backends", "brave"], deps);
		});
		restore();
		expect(exitCode).toBe(1);
		expect(errors[0]).toContain("already registered");
	});

	it("still surfaces ClientAlreadyRegisteredError from the local-file fallback path", async () => {
		const registry = fakeRegistry({
			add: () => {
				throw new ClientAlreadyRegisteredError("web-spider");
			},
		});
		const deps: ClientMainDeps = { registry, addEnigmaClient: async () => undefined };
		const { errors, restore } = captureConsole();
		const exitCode = await runExpectingExit(async () => {
			await clientMain(["add", "web-spider", "--backends", "brave"], deps);
		});
		restore();
		expect(exitCode).toBe(1);
		expect(errors[0]).toContain("already registered");
	});

	it("still surfaces UidAlreadyBoundError from the local-file fallback path", async () => {
		const registry = fakeRegistry({
			add: () => {
				throw new UidAlreadyBoundError(1001, "pipes");
			},
		});
		const deps: ClientMainDeps = { registry, addEnigmaClient: async () => undefined };
		const { errors, restore } = captureConsole();
		const exitCode = await runExpectingExit(async () => {
			await clientMain(["add", "web-spider", "--backends", "brave", "--uid", "1001"], deps);
		});
		restore();
		expect(exitCode).toBe(1);
		expect(errors[0]).toContain("already bound");
	});

	it("falls back to the local registry on a 401 from a reachable daemon that doesn't trust this caller as admin, rather than hard-failing", async () => {
		const registry = fakeRegistry({ add: () => "local-token" });
		const deps: ClientMainDeps = {
			registry,
			addEnigmaClient: async () => ({ ok: false, status: 401, error: "missing or invalid bearer token" }),
		};
		const { logs, restore } = captureConsole();
		try {
			await clientMain(["add", "web-spider", "--backends", "brave"], deps);
		} finally {
			restore();
		}
		expect(logs[1]).toBe("local-token");
	});

	it("falls back to the local registry on a 404 from a daemon old enough to predate POST /clients, rather than hard-failing", async () => {
		const registry = fakeRegistry({ add: () => "local-token" });
		const deps: ClientMainDeps = { registry, addEnigmaClient: async () => ({ ok: false, status: 404, error: "not found" }) };
		const { logs, restore } = captureConsole();
		try {
			await clientMain(["add", "web-spider", "--backends", "brave"], deps);
		} finally {
			restore();
		}
		expect(logs[1]).toBe("local-token");
	});

	it("prints usage and exits when --backends is missing", async () => {
		const deps: ClientMainDeps = { registry: fakeRegistry(), addEnigmaClient: async () => undefined };
		const { errors, restore } = captureConsole();
		const exitCode = await runExpectingExit(async () => {
			await clientMain(["add", "web-spider"], deps);
		});
		restore();
		expect(exitCode).toBe(1);
		expect(errors[0]).toContain("usage: enigma client add");
	});
});

describe("clientMain rotate", () => {
	it("rotates via the running daemon when reachable", async () => {
		const registry = fakeRegistry({
			rotate: () => {
				throw new Error("must not touch the local registry when the daemon is reachable");
			},
		});
		const deps: ClientMainDeps = { registry, rotateEnigmaClient: async () => ({ ok: true, token: "rpc-rotated-token" }) };
		const { logs, restore } = captureConsole();
		try {
			await clientMain(["rotate", "web-spider"], deps);
		} finally {
			restore();
		}
		expect(logs[0]).toContain("via the running daemon");
		expect(logs[1]).toBe("rpc-rotated-token");
	});

	it("falls back to the local registry when the daemon isn't reachable", async () => {
		const deps: ClientMainDeps = { registry: fakeRegistry(), rotateEnigmaClient: async () => undefined };
		const { logs, restore } = captureConsole();
		try {
			await clientMain(["rotate", "web-spider"], deps);
		} finally {
			restore();
		}
		expect(logs[1]).toBe("local-rotated-token");
	});

	it("a 404 from a reachable daemon falls back to the local registry (ambiguous: an old daemon predating the route, vs a genuine not-found -- the local registry resolves the real answer either way)", async () => {
		const registry = fakeRegistry({
			rotate: (name) => {
				expect(name).toBe("web-spider");
				return "local-rotated-token";
			},
		});
		const deps: ClientMainDeps = {
			registry,
			rotateEnigmaClient: async () => ({ ok: false, status: 404, error: 'no registered client named "web-spider"' }),
		};
		const { logs, restore } = captureConsole();
		try {
			await clientMain(["rotate", "web-spider"], deps);
		} finally {
			restore();
		}
		expect(logs[1]).toBe("local-rotated-token");
	});

	it("surfaces a real 409/other non-fallback rejection from the running daemon directly", async () => {
		const registry = fakeRegistry({
			rotate: () => {
				throw new Error("must not touch the local registry after a real remote rejection");
			},
		});
		const deps: ClientMainDeps = { registry, rotateEnigmaClient: async () => ({ ok: false, status: 500, error: "internal error" }) };
		const { errors, restore } = captureConsole();
		const exitCode = await runExpectingExit(async () => {
			await clientMain(["rotate", "web-spider"], deps);
		});
		restore();
		expect(exitCode).toBe(1);
		expect(errors[0]).toContain("internal error");
	});

	it("still surfaces ClientNotFoundError from the local-file fallback path", async () => {
		const registry = fakeRegistry({
			rotate: () => {
				throw new ClientNotFoundError("web-spider");
			},
		});
		const deps: ClientMainDeps = { registry, rotateEnigmaClient: async () => undefined };
		const { errors, restore } = captureConsole();
		const exitCode = await runExpectingExit(async () => {
			await clientMain(["rotate", "web-spider"], deps);
		});
		restore();
		expect(exitCode).toBe(1);
		expect(errors[0]).toContain("no registered client");
	});
});

describe("clientMain remove", () => {
	it("removes via the running daemon when reachable", async () => {
		const registry = fakeRegistry({
			remove: () => {
				throw new Error("must not touch the local registry when the daemon is reachable");
			},
		});
		const deps: ClientMainDeps = { registry, removeEnigmaClient: async () => ({ ok: true }) };
		const { logs, restore } = captureConsole();
		try {
			await clientMain(["remove", "web-spider"], deps);
		} finally {
			restore();
		}
		expect(logs[0]).toContain("via the running daemon");
	});

	it("falls back to the local registry when the daemon isn't reachable", async () => {
		let removed: string | undefined;
		const registry = fakeRegistry({
			remove: (name) => {
				removed = name;
			},
		});
		const deps: ClientMainDeps = { registry, removeEnigmaClient: async () => undefined };
		const { logs, restore } = captureConsole();
		try {
			await clientMain(["remove", "web-spider"], deps);
		} finally {
			restore();
		}
		expect(removed).toBe("web-spider");
		expect(logs[0]).not.toContain("via the running daemon");
	});

	it("a 404 from a reachable daemon falls back to the local registry", async () => {
		let removed: string | undefined;
		const registry = fakeRegistry({
			remove: (name) => {
				removed = name;
			},
		});
		const deps: ClientMainDeps = {
			registry,
			removeEnigmaClient: async () => ({ ok: false, status: 404, error: 'no registered client named "web-spider"' }),
		};
		const { restore } = captureConsole();
		try {
			await clientMain(["remove", "web-spider"], deps);
		} finally {
			restore();
		}
		expect(removed).toBe("web-spider");
	});

	it("surfaces a real non-fallback rejection from the running daemon directly", async () => {
		const registry = fakeRegistry({
			remove: () => {
				throw new Error("must not touch the local registry after a real remote rejection");
			},
		});
		const deps: ClientMainDeps = { registry, removeEnigmaClient: async () => ({ ok: false, status: 500, error: "internal error" }) };
		const { errors, restore } = captureConsole();
		const exitCode = await runExpectingExit(async () => {
			await clientMain(["remove", "web-spider"], deps);
		});
		restore();
		expect(exitCode).toBe(1);
		expect(errors[0]).toContain("internal error");
	});
});

describe("clientMain list", () => {
	it("prefers the running daemon's own registry over the local file", async () => {
		const remoteRecords: VaultClientRecord[] = [{ name: "web-spider", backends: ["brave"] }];
		const registry = fakeRegistry({
			list: () => {
				throw new Error("must not touch the local registry when the daemon is reachable");
			},
		});
		const deps: ClientMainDeps = { registry, connectEnigmaClient: () => fakeAdminClient({ listClients: async () => remoteRecords }) };
		const { logs, restore } = captureConsole();
		try {
			await clientMain(["list"], deps);
		} finally {
			restore();
		}
		expect(JSON.parse(logs[0]!)).toEqual(remoteRecords);
	});

	it("falls back to the local registry when the daemon isn't reachable", async () => {
		const localRecords = [{ name: "pipes", backends: ["github"], createdAt: "2024-01-01T00:00:00.000Z" }];
		const registry = fakeRegistry({ list: () => localRecords });
		const deps: ClientMainDeps = {
			registry,
			connectEnigmaClient: () =>
				fakeAdminClient({
					listClients: async () => {
						throw new Error("Enigma daemon is not running; run `enigma serve`.");
					},
				}),
		};
		const { logs, restore } = captureConsole();
		try {
			await clientMain(["list"], deps);
		} finally {
			restore();
		}
		expect(JSON.parse(logs[0]!)).toEqual(localRecords);
	});
});
