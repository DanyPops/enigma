/**
 * pi-enigma: `/secrets` command for interactive vault management from inside
 * Pi. Human-driven only -- no LLM-callable tool here. Talks to the same
 * running `enigma serve`/`enigma supervisor` daemon the CLI does, via the
 * same VaultClient daemon-kit already ships; this lives in enigma's own
 * package (not a separate one depending on it over npm), so importing
 * ../../src/client.ts directly is a plain relative TypeScript import, not a
 * cross-package boundary jiti would need to transpile through node_modules --
 * confirmed safe by @danypops/jittor's own extension/src/service-client.ts,
 * which does exactly this against its own daemon.
 *
 * Never surfaces accessToken/refreshToken/extra: every value shown here comes
 * from redactCredentialStatus's explicit allow-list, per the standing rule
 * "Enigma Pi extension: never expose decrypted credential material to the LLM".
 */
import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { DynamicBorder, getSelectListTheme } from "@earendil-works/pi-coding-agent";
import { Container, type SelectItem, SelectList, Text } from "@earendil-works/pi-tui";
import type { VaultClient } from "@danypops/daemon-kit/vault";
import { connectEnigmaClient } from "../../src/client.ts";
import { describeCredentialStatus, redactCredentialStatus, type RedactedCredentialStatus } from "./redact.ts";

export async function loadStatuses(client: VaultClient): Promise<RedactedCredentialStatus[]> {
	const backends = await client.listCredentialKeys();
	const statuses: RedactedCredentialStatus[] = [];
	for (const backend of backends) {
		const credential = await client.getCredentials(backend);
		statuses.push(redactCredentialStatus(backend, credential));
	}
	return statuses;
}

async function pickFromList(ctx: ExtensionCommandContext, title: string, items: SelectItem[], helpText: string): Promise<string | null> {
	if (ctx.mode !== "tui") {
		ctx.ui.notify(`${title}: ${items.map((item) => item.label).join(", ") || "(none)"}`, "info");
		return null;
	}
	return ctx.ui.custom<string | null>((tui, theme, _keybindings, done) => {
		const container = new Container();
		container.addChild(new DynamicBorder((s: string) => theme.fg("accent", s)));
		container.addChild(new Text(theme.fg("accent", theme.bold(title)), 1, 0));
		const selectList = new SelectList(items, Math.min(items.length, 10), getSelectListTheme());
		selectList.onSelect = (item) => done(item.value);
		selectList.onCancel = () => done(null);
		container.addChild(selectList);
		container.addChild(new Text(theme.fg("dim", helpText), 1, 0));
		container.addChild(new DynamicBorder((s: string) => theme.fg("accent", s)));
		return {
			render: (w) => container.render(w),
			invalidate: () => container.invalidate(),
			handleInput: (data) => {
				selectList.handleInput(data);
				tui.requestRender();
			},
		};
	});
}

export type PickFromList = (ctx: ExtensionCommandContext, title: string, items: SelectItem[], helpText: string) => Promise<string | null>;

async function manageBackend(ctx: ExtensionCommandContext, client: VaultClient, backend: string, pick: PickFromList = pickFromList): Promise<void> {
	for (;;) {
		const credential = await client.getCredentials(backend);
		const status = redactCredentialStatus(backend, credential);
		const items: SelectItem[] = [
			{ value: "rotate", label: "Rotate", description: "Refresh this credential in place" },
			{ value: "revoke", label: "Revoke", description: "Delete the stored credential" },
			{ value: "back", label: "Back" },
		];
		const action = await pick(ctx, `${backend} \u2014 ${describeCredentialStatus(status)}`, items, "\u2191\u2193 navigate \u2022 enter select \u2022 esc back");
		if (!action || action === "back") return;

		if (action === "rotate") {
			try {
				await client.rotateCredential(backend);
				ctx.ui.notify(`${backend}: rotated.`, "info");
			} catch (error) {
				ctx.ui.notify(`${backend}: rotate failed (${error instanceof Error ? error.message : String(error)})`, "error");
			}
			continue;
		}

		if (action === "revoke") {
			const confirmed = ctx.hasUI ? await ctx.ui.confirm(`Revoke ${backend}?`, "This deletes the stored credential. Re-authenticate with `enigma login` to restore it.") : false;
			if (!confirmed) continue;
			try {
				await client.revokeCredential(backend);
				ctx.ui.notify(`${backend}: revoked.`, "info");
			} catch (error) {
				ctx.ui.notify(`${backend}: revoke failed (${error instanceof Error ? error.message : String(error)})`, "error");
			}
			return; // nothing left to manage for this backend once revoked
		}
	}
}

export async function runSecretsCommand(ctx: ExtensionCommandContext, connect: () => VaultClient = connectEnigmaClient, pick: PickFromList = pickFromList): Promise<void> {
	let client: VaultClient;
	try {
		client = connect();
	} catch (error) {
		ctx.ui.notify(error instanceof Error ? error.message : String(error), "error");
		return;
	}

	for (;;) {
		let statuses: RedactedCredentialStatus[];
		try {
			statuses = await loadStatuses(client);
		} catch (error) {
			ctx.ui.notify(`Could not reach the Enigma vault: ${error instanceof Error ? error.message : String(error)}`, "error");
			return;
		}

		if (statuses.length === 0) {
			ctx.ui.notify("No backends configured yet. Run `enigma login <backend>` first.", "info");
			return;
		}

		const items: SelectItem[] = statuses.map((status) => ({
			value: status.backend,
			label: status.backend,
			description: describeCredentialStatus(status),
		}));
		const backend = await pick(ctx, "Enigma secrets", items, "\u2191\u2193 navigate \u2022 enter select \u2022 esc close");
		if (!backend) return;
		await manageBackend(ctx, client, backend, pick);
	}
}

export default function (pi: ExtensionAPI): void {
	pi.registerCommand("secrets", {
		description: "Manage Enigma-held credentials: view redacted status, rotate, or revoke",
		handler: async (_args, ctx) => runSecretsCommand(ctx),
	});
}
