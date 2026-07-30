/**
 * Optional, Linux-only, opt-in authorization hook layered on top of (never
 * replacing) the existing admin-uid/bearer-token checks: asks polkit
 * whether a *specific* kernel-verified caller is authorized for a specific
 * action, rather than only "is this uid the one configured
 * ENIGMA_ADMIN_UID." Only ever meaningful over the Unix-socket transport --
 * there is no OS-verified caller identity to hand polkit over plain TCP,
 * on any platform.
 */
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import type { PeerCredential } from "@danypops/vehicle-server/unix-peer-cred";

/** The one action this hook exists for today -- see contrib/polkit/ for the matching .policy file operators install. */
export const ENIGMA_MANAGE_CLIENTS_ACTION_ID = "com.danypops.enigma.manage-clients";

export type PolkitCheck = (peer: PeerCredential, actionId: string) => Promise<boolean>;

/**
 * polkit's own docs (`man pkcheck`, NOTES) are explicit: bare pid or
 * pid,start-time forms have real race conditions across a PID-reuse window
 * and must not be used -- the pid,start-time,uid form is the only one
 * without that gap. start-time comes from /proc/<pid>/stat's 22nd field,
 * parsed from the *end* of the line rather than by naive whitespace-split:
 * the comm field (2nd) is parenthesized and can itself contain spaces or
 * parens, so every field before it must be located relative to the last
 * ')', not counted positionally from the start.
 */
export function readProcessStartTime(pid: number): number | undefined {
	try {
		const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
		const afterComm = stat.slice(stat.lastIndexOf(")") + 2);
		const fields = afterComm.trim().split(/\s+/);
		const startTime = fields[19]; // field 22 overall = 20th field after the comm field closes
		if (!startTime) return undefined;
		const parsed = Number(startTime);
		return Number.isInteger(parsed) ? parsed : undefined;
	} catch {
		return undefined; // /proc unavailable (non-Linux), pid already gone, or a malformed line -- never throws
	}
}

export interface CreatePkcheckAuthorizerOptions {
	/** Injectable for tests; production default is node:child_process's real execFile. */
	execFileImpl?: typeof execFile;
	/** Defaults to "pkcheck" (resolved via PATH); override for a non-standard install location. */
	pkcheckPath?: string;
}

/**
 * Denies (returns false) rather than throwing for every failure mode --
 * pkcheck missing, no polkit authority running, the caller's own process
 * having already exited, a malformed invocation -- matching the same
 * fail-closed default every other identity check in server.ts already
 * uses. Never blocks on --allow-user-interaction (omitted entirely): a
 * synchronous admin decision from an agentless caller has nowhere to
 * render a prompt, and pkcheck's own contract (exit 2) already treats
 * "no way to authenticate" as a clean, non-throwing denial.
 */
export function createPkcheckAuthorizer(options: CreatePkcheckAuthorizerOptions = {}): PolkitCheck {
	const run = options.execFileImpl ?? execFile;
	const pkcheckPath = options.pkcheckPath ?? "pkcheck";

	return (peer, actionId) =>
		new Promise<boolean>((resolve) => {
			const startTime = readProcessStartTime(peer.pid);
			if (startTime === undefined) {
				resolve(false);
				return;
			}
			const subject = `${peer.pid},${startTime},${peer.uid}`;
			run(pkcheckPath, ["--action-id", actionId, "--process", subject], (error) => {
				// execFile's callback receives a non-null error for any non-zero exit code
				// (1 = not authorized, 2 = no agent, 3 = dismissed, 126/127 = invocation
				// failure) as well as spawn failures (pkcheck not installed) -- every one
				// of those is "not authorized," not a reason to throw.
				resolve(!error);
			});
		});
}
