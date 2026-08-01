/** Enigma's own CLI talking to its own running server, admin-token-authenticated (or, when available, SO_PEERCRED-authenticated over the Unix socket -- no token needed at all). */
import { existsSync, readFileSync } from "node:fs";
import { ENIGMA_SYSTEM_RUNTIME_HANDLE, resolveAdminSocketPath, resolveHandle } from "@danypops/enigma-client";
import { connectUnixRpc } from "@danypops/vehicle-client/unix-rpc-client";
import type { RefreshableAccessToken } from "@danypops/vehicle-server/vault";
import { resolveEnigmaPaths } from "./paths.ts";

export type VaultCredential = RefreshableAccessToken;

export interface VaultClientRecord {
	name: string;
	backends: string[];
	uid?: number;
}

export interface EnigmaAdminClient {
	getCredentials(backend: string): Promise<VaultCredential | undefined>;
	rotateCredential(backend: string): Promise<void>;
	revokeCredential(backend: string): Promise<void>;
	listCredentialKeys(): Promise<string[]>;
	/** The [services] side of the /secrets model: every registered client and which backends it may use. Admin-only. */
	listClients(): Promise<VaultClientRecord[]>;
	health(): Promise<{ ok: boolean; version: string }>;
}

function rawRequest(
	fetchImpl: typeof fetch,
	baseUrl: string,
	authToken: string | undefined,
	method: string,
	path: string,
): Promise<Response> {
	return fetchImpl(`${baseUrl}${path}`, {
		method,
		headers: { ...(authToken !== undefined ? { authorization: `Bearer ${authToken}` } : {}), accept: "application/json" },
	});
}

async function toResult<T>(response: Response, method: string, path: string): Promise<T | undefined> {
	if (response.status === 404) return undefined;
	if (!response.ok) throw new Error(`enigma request failed: ${method} ${path}: HTTP ${response.status}`);
	if (response.status === 204) return undefined;
	const text = await response.text();
	return text ? (JSON.parse(text) as T) : undefined;
}

/** Placeholder authority for the Unix-socket transport -- meaningless once request framing goes over a Unix socket instead of TCP, never actually dialed. */
const UNIX_TRANSPORT_BASE_URL = "http://enigma.local";

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

interface Endpoint {
	fetchImpl: typeof fetch;
	baseUrl: string;
	token: string | undefined;
}

function connectUnixEndpoint(socketPath: string): Endpoint {
	// connectUnixRpc's own transport takes a real Request, not the (url, init) pair rawRequest()
	// invokes fetchImpl with -- adapted here, same shape as enigma-client's own identical adapter.
	const transport = connectUnixRpc({ path: socketPath });
	const fetchImpl: typeof fetch = ((input: string | URL | Request, init?: RequestInit) =>
		transport(input instanceof Request ? input : new Request(input instanceof URL ? input.href : input, init))) as typeof fetch;
	return { fetchImpl, baseUrl: UNIX_TRANSPORT_BASE_URL, token: undefined };
}

function connectTcpEndpoint(paths: ReturnType<typeof resolveEnigmaPaths>, fallbackHandlePath: string): Endpoint {
	const handle = resolveHandle(paths.handle, fallbackHandlePath);
	if (!handle) throw new Error("Enigma daemon is not running; run `enigma serve`.");
	return { fetchImpl: fetch, baseUrl: `http://${handle.host}:${handle.port}`, token: readAdminToken(paths.token) };
}

/** Builds the public client interface around a `call` function that resolves the actual endpoint however it needs to -- eagerly or lazily. */
function clientFromCall(call: <T>(method: string, path: string) => Promise<T | undefined>): EnigmaAdminClient {
	return {
		getCredentials: (backend) => call<VaultCredential>("GET", `/creds/${encodeURIComponent(backend)}`),
		rotateCredential: async (backend) => void (await call("POST", `/rotate/${encodeURIComponent(backend)}`)),
		revokeCredential: async (backend) => void (await call("POST", `/revoke/${encodeURIComponent(backend)}`)),
		listCredentialKeys: async () => (await call<string[]>("GET", "/keys")) ?? [],
		listClients: async () => (await call<VaultClientRecord[]>("GET", "/clients")) ?? [],
		health: async () => {
			const result = await call<{ ok: boolean; version: string }>("GET", "/health");
			if (!result) throw new Error("Enigma /health returned no body");
			return result;
		},
	};
}

/**
 * `fallbackHandlePath` defaults to Enigma's real system-wide runtime path but is
 * an explicit parameter (not hardcoded inline) so this exact wiring is testable
 * end to end without needing root to write into the real /run/enigma.
 */
export function connectEnigmaClient(
	paths = resolveEnigmaPaths(),
	fallbackHandlePath: string = ENIGMA_SYSTEM_RUNTIME_HANDLE,
): EnigmaAdminClient {
	const unixSocketPath = resolveAdminSocketPath(paths.handle, fallbackHandlePath);

	if (!unixSocketPath) {
		// No Unix-socket support at all (older Enigma, or none running) -- fully unchanged from
		// before this transport existed: resolves (or throws "not running"/"no admin token")
		// synchronously, with zero network I/O, right here at connect time.
		const endpoint = connectTcpEndpoint(paths, fallbackHandlePath);
		return clientFromCall((method, path) =>
			rawRequest(endpoint.fetchImpl, endpoint.baseUrl, endpoint.token, method, path).then((r) => toResult(r, method, path)),
		);
	}

	// A socket exists, but that only means this Enigma is new enough to serve one, not that
	// this process's own uid is actually trusted as admin over it (ENIGMA_ADMIN_UID is a
	// separate, explicit opt-in the daemon's operator configures independently) -- so it's
	// tried first on the real first call, deferred rather than checked eagerly here, and a
	// 401/403 over that transport falls back to the TCP+bearer-token path: the same admin
	// token that worked before this transport existed keeps working unchanged. The decision
	// is cached for the lifetime of this client so later calls skip straight to whichever
	// endpoint actually authenticated, without re-trying the socket every time.
	let resolved: Endpoint | undefined;
	return clientFromCall(async (method, path) => {
		if (!resolved) {
			const unix = connectUnixEndpoint(unixSocketPath);
			const response = await rawRequest(unix.fetchImpl, unix.baseUrl, unix.token, method, path);
			if (response.status !== 401 && response.status !== 403) return toResult(response, method, path);
			resolved = connectTcpEndpoint(paths, fallbackHandlePath); // this call's own result still comes from the fallback below
		}
		return toResult(await rawRequest(resolved.fetchImpl, resolved.baseUrl, resolved.token, method, path), method, path);
	});
}
