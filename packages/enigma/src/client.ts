/** Enigma's own CLI talking to its own running server, admin-token-authenticated. */
import { existsSync, readFileSync } from "node:fs";
import { ENIGMA_SYSTEM_RUNTIME_HANDLE, resolveHandle } from "@danypops/enigma-client";
import type { RefreshableAccessToken } from "@danypops/daemon-kit/vault";
import { resolveEnigmaPaths } from "./paths.ts";

export type VaultCredential = RefreshableAccessToken;

export interface EnigmaAdminClient {
	getCredentials(backend: string): Promise<VaultCredential | undefined>;
	rotateCredential(backend: string): Promise<void>;
	revokeCredential(backend: string): Promise<void>;
	listCredentialKeys(): Promise<string[]>;
}

async function call<T>(baseUrl: string, authToken: string, method: string, path: string): Promise<T | undefined> {
	const response = await fetch(`${baseUrl}${path}`, {
		method,
		headers: { authorization: `Bearer ${authToken}`, accept: "application/json" },
	});
	if (response.status === 404) return undefined;
	if (!response.ok) throw new Error(`enigma request failed: ${method} ${path}: HTTP ${response.status}`);
	if (response.status === 204) return undefined;
	const text = await response.text();
	return text ? (JSON.parse(text) as T) : undefined;
}

/**
 * Reads the admin token this CLI process will present to Enigma -- read-only,
 * mirroring enigma-client's own resolveToken. Minting a throwaway token here
 * (as ensureAuthToken would) is actively wrong once cross-uid discovery is in
 * play: a handle found via the system-wide fallback almost certainly belongs
 * to a different OS user's Enigma, whose real admin token this process can
 * never see -- inventing one at this process's own path would silently
 * connect with a token the real daemon will just reject, instead of failing
 * clearly with an actionable message.
 */
function readAdminToken(tokenPath: string): string {
	if (!existsSync(tokenPath)) {
		throw new Error(
			`No Enigma admin token found at ${tokenPath}. If Enigma is running as a different OS user (e.g. a system service), this CLI needs that account's own admin token, not a freshly minted local one.`,
		);
	}
	const token = readFileSync(tokenPath, "utf8").trim();
	if (!/^[a-f0-9]{64}$/.test(token)) throw new Error("invalid Enigma admin token");
	return token;
}

/**
 * `fallbackHandlePath` defaults to Enigma's real system-wide runtime path but is
 * an explicit parameter (not hardcoded inline) so this exact wiring is testable
 * end to end without needing root to write into the real /run/enigma.
 */
export function connectEnigmaClient(paths = resolveEnigmaPaths(), fallbackHandlePath: string = ENIGMA_SYSTEM_RUNTIME_HANDLE): EnigmaAdminClient {
	const handle = resolveHandle(paths.handle, fallbackHandlePath);
	if (!handle) throw new Error("Enigma daemon is not running; run `enigma serve`.");
	const token = readAdminToken(paths.token);
	const baseUrl = `http://${handle.host}:${handle.port}`;

	return {
		getCredentials: (backend) => call<VaultCredential>(baseUrl, token, "GET", `/creds/${encodeURIComponent(backend)}`),
		rotateCredential: async (backend) => void (await call(baseUrl, token, "POST", `/rotate/${encodeURIComponent(backend)}`)),
		revokeCredential: async (backend) => void (await call(baseUrl, token, "POST", `/revoke/${encodeURIComponent(backend)}`)),
		listCredentialKeys: async () => (await call<string[]>(baseUrl, token, "GET", "/keys")) ?? [],
	};
}
