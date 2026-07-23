import { describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadSupervisorConfig } from "../src/supervisor-config.ts";

function tmpDir(): string {
	return mkdtempSync(join(tmpdir(), "enigma-supervisor-config-"));
}

describe("loadSupervisorConfig", () => {
	it("returns zero units, not an error, when the config file doesn't exist yet", () => {
		const dir = tmpDir();
		try {
			expect(loadSupervisorConfig(join(dir, "daemons.json"))).toEqual({ units: [] });
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("parses a well-formed config", () => {
		const dir = tmpDir();
		try {
			const path = join(dir, "daemons.json");
			writeFileSync(
				path,
				JSON.stringify({
					units: [{ name: "pipes", bin: "/bin/pipes-daemon", args: ["serve"], backends: ["github", "gitlab"], restart: "on-failure" }],
				}),
			);
			const config = loadSupervisorConfig(path);
			expect(config.units).toHaveLength(1);
			expect(config.units[0]?.name).toBe("pipes");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("rejects a config missing the units array", () => {
		const dir = tmpDir();
		try {
			const path = join(dir, "daemons.json");
			writeFileSync(path, JSON.stringify({ notUnits: [] }));
			expect(() => loadSupervisorConfig(path)).toThrow(/units/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("rejects a unit missing required fields rather than spawning it with undefined values", () => {
		const dir = tmpDir();
		try {
			const path = join(dir, "daemons.json");
			writeFileSync(path, JSON.stringify({ units: [{ name: "incomplete" }] }));
			expect(() => loadSupervisorConfig(path)).toThrow(/missing required fields/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
