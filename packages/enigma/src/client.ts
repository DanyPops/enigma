/** Enigma's own CLI talking to its own running server, admin-token-authenticated. */
import { ensureAuthToken, readDaemonHandle } from "@danypops/daemon-kit/paths";
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

export function connectEnigmaClient(paths = resolveEnigmaPaths()): EnigmaAdminClient {
	const handle = readDaemonHandle(paths.handle);
	if (!handle) throw new Error("Enigma daemon is not running; run `enigma serve`.");
	const token = ensureAuthToken(paths.token, "Enigma");
	const baseUrl = `http://${handle.host}:${handle.port}`;

	return {
		getCredentials: (backend) => call<VaultCredential>(baseUrl, token, "GET", `/creds/${encodeURIComponent(backend)}`),
		rotateCredential: async (backend) => void (await call(baseUrl, token, "POST", `/rotate/${encodeURIComponent(backend)}`)),
		revokeCredential: async (backend) => void (await call(baseUrl, token, "POST", `/revoke/${encodeURIComponent(backend)}`)),
		listCredentialKeys: async () => (await call<string[]>(baseUrl, token, "GET", "/keys")) ?? [],
	};
}
