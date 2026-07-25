import { describe, expect, it } from "bun:test";
import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import type { VaultClient, VaultCredential } from "@danypops/daemon-kit/vault";
import { loadStatuses, runSecretsCommand, type PickFromList } from "../src/index.ts";

const REAL_LOOKING_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";

function fakeVaultClient(records: Record<string, VaultCredential>): VaultClient & { rotated: string[]; revoked: string[] } {
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
	};
	return client;
}

function fakeCtx(overrides: { confirm?: boolean } = {}): { ctx: ExtensionCommandContext; notifications: Array<{ text: string; level: string }> } {
	const notifications: Array<{ text: string; level: string }> = [];
	const ctx = {
		hasUI: true,
		mode: "tui",
		ui: {
			notify: (text: string, level: string) => {
				notifications.push({ text, level });
			},
			confirm: async () => overrides.confirm ?? true,
		},
	} as unknown as ExtensionCommandContext;
	return { ctx, notifications };
}

/** Scripted `pick`: returns each queued value in order, then null forever after. */
function scriptedPick(...values: Array<string | null>): PickFromList {
	const queue = [...values];
	return async () => (queue.length > 0 ? queue.shift()! : null);
}

describe("loadStatuses", () => {
	it("redacts every configured backend, never surfacing the real token", async () => {
		const client = fakeVaultClient({
			github: { accessToken: REAL_LOOKING_TOKEN, scope: "repo" },
			jenkins: { accessToken: REAL_LOOKING_TOKEN, extra: { url: "https://jenkins.example.com" } },
		});
		const statuses = await loadStatuses(client);
		const serialized = JSON.stringify(statuses);
		expect(serialized).not.toContain(REAL_LOOKING_TOKEN);
		expect(statuses).toEqual([
			{ backend: "github", configured: true, scope: "repo" },
			{ backend: "jenkins", configured: true },
		]);
	});
});

describe("runSecretsCommand", () => {
	it("reports a clear error and stops when the daemon isn't running, without throwing", async () => {
		const { ctx, notifications } = fakeCtx();
		const connect = () => {
			throw new Error("Enigma daemon is not running; run `enigma serve` or `enigma supervisor`.");
		};
		await runSecretsCommand(ctx, connect, scriptedPick());
		expect(notifications).toHaveLength(1);
		expect(notifications[0]?.level).toBe("error");
		expect(notifications[0]?.text).toContain("not running");
	});

	it("reports a clear error when the vault is unreachable mid-session", async () => {
		const { ctx, notifications } = fakeCtx();
		const client: VaultClient = {
			listCredentialKeys: async () => {
				throw new Error("vault request failed: GET /keys: HTTP 500");
			},
			getCredentials: async () => undefined,
			rotateCredential: async () => undefined,
			revokeCredential: async () => undefined,
		};
		await runSecretsCommand(ctx, () => client, scriptedPick());
		expect(notifications[0]?.level).toBe("error");
		expect(notifications[0]?.text).toContain("Could not reach the Enigma vault");
	});

	it("tells the user to log in when no backends are configured yet", async () => {
		const { ctx, notifications } = fakeCtx();
		const client = fakeVaultClient({});
		await runSecretsCommand(ctx, () => client, scriptedPick());
		expect(notifications[0]?.text).toContain("enigma login");
	});

	it("rotates the selected backend and reports success, never the token", async () => {
		const { ctx, notifications } = fakeCtx();
		const client = fakeVaultClient({ github: { accessToken: REAL_LOOKING_TOKEN } });
		// pick: 1) choose "github" from the backend list, 2) choose "rotate" from its action menu,
		// 3) "back" out of the action menu, 4) close the backend list.
		await runSecretsCommand(ctx, () => client, scriptedPick("github", "rotate", "back", null));
		expect(client.rotated).toEqual(["github"]);
		expect(notifications.some((n) => n.text === "github: rotated." && n.level === "info")).toBe(true);
		expect(JSON.stringify(notifications)).not.toContain(REAL_LOOKING_TOKEN);
	});

	it("surfaces a rotate failure without crashing or leaking secret-shaped detail", async () => {
		const { ctx, notifications } = fakeCtx();
		const client = fakeVaultClient({ jenkins: { accessToken: REAL_LOOKING_TOKEN } });
		client.rotateCredential = async () => {
			throw new Error("backend \"jenkins\" has no refresh function configured");
		};
		await runSecretsCommand(ctx, () => client, scriptedPick("jenkins", "rotate", "back", null));
		const failure = notifications.find((n) => n.level === "error");
		expect(failure?.text).toContain("rotate failed");
		expect(failure?.text).toContain("no refresh function configured");
	});

	it("revokes only after explicit confirmation", async () => {
		const { ctx, notifications } = fakeCtx({ confirm: false });
		const client = fakeVaultClient({ gitlab: { accessToken: REAL_LOOKING_TOKEN } });
		// Declining the confirm dialog must not revoke; "back" then exits the (still-configured) backend's menu.
		await runSecretsCommand(ctx, () => client, scriptedPick("gitlab", "revoke", "back", null));
		expect(client.revoked).toEqual([]);
		expect(notifications.some((n) => n.text.includes("revoked"))).toBe(false);
	});

	it("revokes when confirmed and reports success", async () => {
		const { ctx, notifications } = fakeCtx({ confirm: true });
		const client = fakeVaultClient({ gitlab: { accessToken: REAL_LOOKING_TOKEN } });
		await runSecretsCommand(ctx, () => client, scriptedPick("gitlab", "revoke", null));
		expect(client.revoked).toEqual(["gitlab"]);
		expect(notifications.some((n) => n.text === "gitlab: revoked." && n.level === "info")).toBe(true);
	});
});
