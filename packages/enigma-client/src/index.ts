/**
 * Client for a running Enigma vault (github.com/DanyPops/enigma), if one
 * happens to be configured on this machine. Purely additive -- a consumer
 * never imports Enigma's own source, only its documented discovery contract
 * (a state-directory name and handle/token filenames) via @danypops/daemon-kit,
 * which every daemon already depends on for its own plumbing. Enigma's own
 * wire protocol (GET /creds/:backend, GET /whoami) is implemented directly
 * here, not borrowed from a "generic" daemon-kit abstraction -- it's
 * Enigma's own protocol, not a standard other vaults implement.
 *
 * Never creates Enigma's handle or token files -- those are strictly
 * Enigma's own job on first boot. A consumer that could mint them would be
 * a real security problem, not a convenience. Absence of either file means
 * "Enigma isn't running or isn't configured for this backend," not an
 * error: every failure path here resolves `undefined` rather than
 * throwing, and the whole attempt is time-bounded so a slow or hung Enigma
 * can never stall a caller's own startup.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { readDaemonHandle, resolveDaemonPaths, type DaemonHandle } from "@danypops/daemon-kit/paths";
import { connectUnixRpc } from "@danypops/daemon-kit/unix-rpc-client";
import type { RefreshableAccessToken } from "@danypops/daemon-kit/vault";

const ENIGMA_STATE_DIRECTORY_NAME = "enigma";
const ENIGMA_HANDLE_FILENAME = "handle.json";
const ENIGMA_TOKEN_FILENAME = "token";
/** Sibling to handle.json in the same directory -- mirrors Enigma's own daemon.ts (ADMIN_SOCKET_FILENAME), duplicated deliberately: this package never imports Enigma's own source, same rationale as duplicating the handle/token filenames above. */
const ENIGMA_ADMIN_SOCKET_FILENAME = "admin.sock";
/** Placeholder authority for the Unix-socket transport -- the host is meaningless once request framing goes over a Unix socket instead of TCP (see daemon-kit's own unix-rpc-client.ts), never actually dialed. */
const UNIX_TRANSPORT_BASE_URL = "http://enigma.local";
const ENIGMA_LOOKUP_TIMEOUT_MS = 500;
const ENIGMA_UNIX_LOOKUP_TIMEOUT_MS = 500;
/**
 * Enigma is typically a system-level service (unlike a same-user daemon), so its
 * handle can live outside any one process's own $XDG_RUNTIME_DIR. Exported so
 * Enigma's own admin CLI (client.ts, a different consumer of this same discovery
 * problem) can reuse the identical fallback path rather than a second copy of it.
 */
export const ENIGMA_SYSTEM_RUNTIME_HANDLE = join("/run", ENIGMA_STATE_DIRECTORY_NAME, ENIGMA_HANDLE_FILENAME);

/** Identical shape to RefreshableAccessToken -- Enigma always hands back a credential, never a bare token. */
export type VaultCredential = RefreshableAccessToken;

/** A client's own registration, as Enigma sees it: its name and the backends it may fetch. `backends: null` means unrestricted (the admin token). */
export interface EnigmaWhoAmI {
	name: string;
	backends: string[] | null;
}

export interface TryEnigmaCredentialOptions {
	env?: Record<string, string | undefined>;
	/**
	 * Present this token instead of reading Enigma's shared admin-token
	 * file -- the seam for a caller that has registered its own scoped
	 * token via `enigma client add` (see Enigma's client registry). Falls
	 * back to reading the shared file only when omitted, so an unmigrated
	 * caller keeps working unchanged.
	 */
	token?: string;
	/** Injectable for tests; production default is the real fetch, bounded by AbortSignal.timeout. */
	fetchImpl?: typeof fetch;
	/**
	 * Overrides ENIGMA_SYSTEM_RUNTIME_HANDLE, the real system-wide fallback
	 * path -- exists so a test can guarantee isolation from whatever Enigma
	 * happens to be genuinely running on the host machine (confirmed live: a
	 * production Enigma with Unix-socket support and this host's uid trusted
	 * as its admin made every test omitting this silently connect to and read
	 * from the real vault instead of its own fixture server). Production
	 * callers should never set this.
	 */
	fallbackHandlePath?: string;
}

export type TryEnigmaCredential = (backend: string, opts?: TryEnigmaCredentialOptions) => Promise<VaultCredential | undefined>;
export type TryEnigmaAccessToken = (backend: string, opts?: TryEnigmaCredentialOptions) => Promise<string | undefined>;
export type TryEnigmaWhoAmI = (opts?: TryEnigmaCredentialOptions) => Promise<EnigmaWhoAmI | undefined>;

function resolveToken(opts: TryEnigmaCredentialOptions, tokenPath: string): string | undefined {
	if (opts.token) return opts.token;
	if (!existsSync(tokenPath)) return undefined; // never ensureAuthToken here -- read-only, never mint Enigma's own token
	try {
		return readFileSync(tokenPath, "utf8").trim();
	} catch {
		return undefined;
	}
}

interface ConnectedVault {
	baseUrl: string;
	/** Absent for the Unix-socket transport -- SO_PEERCRED needs no bearer credential at all. */
	token?: string;
	fetchImpl: typeof fetch;
}

/**
 * Tries `primaryPath` first (this process's own $XDG_RUNTIME_DIR-scoped
 * path -- a same-user dev/test Enigma, or any future same-user deployment),
 * then `fallbackPath` (the system-wide runtime path a real production
 * Enigma actually uses -- it runs as its own dedicated service account, not
 * scoped to any one consumer's uid, so a consumer's own XDG_RUNTIME_DIR was
 * never going to contain it). Exported for direct testing without needing
 * root to write into the real /run/enigma.
 */
export function resolveHandle(primaryPath: string, fallbackPath: string): DaemonHandle | null {
	return readDaemonHandle(primaryPath) ?? readDaemonHandle(fallbackPath);
}

/**
 * Resolves the admin Unix socket's path, if Enigma is actually listening on
 * one -- same primary-then-fallback directory preference as resolveHandle,
 * since the socket is always a sibling of that directory's handle.json.
 * Returns undefined (never throws) when neither candidate exists: an older
 * Enigma with no Unix-socket support at all, or one simply not running,
 * look identical from here -- both fall through to the TCP path below.
 */
export function resolveAdminSocketPath(primaryHandlePath: string, fallbackHandlePath: string): string | undefined {
	const primarySocket = join(dirname(primaryHandlePath), ENIGMA_ADMIN_SOCKET_FILENAME);
	if (existsSync(primarySocket)) return primarySocket;
	const fallbackSocket = join(dirname(fallbackHandlePath), ENIGMA_ADMIN_SOCKET_FILENAME);
	if (existsSync(fallbackSocket)) return fallbackSocket;
	return undefined;
}

function connect(opts: TryEnigmaCredentialOptions): ConnectedVault | undefined {
	const env = opts.env ?? process.env;
	const paths = resolveDaemonPaths(
		{ stateDirectoryName: ENIGMA_STATE_DIRECTORY_NAME, handleFilename: ENIGMA_HANDLE_FILENAME, tokenFilename: ENIGMA_TOKEN_FILENAME, databaseFilename: "", systemdUnitName: "" },
		{ env },
	);

	// Unix socket first, whenever Enigma is new enough to be serving one: kernel-verified
	// peer identity (SO_PEERCRED) needs no token at all, so a same-uid caller registered
	// via `enigma client add --uid` (or the operator's own uid, granted full admin) never
	// has to hold, store, or risk leaking any credential material just to reach the vault.
	// An explicitly passed opts.token still always wins the TCP path below, but is simply
	// irrelevant here -- the transport itself is the proof of identity, not a header.
	//
	// Skipped entirely when the caller passes its own fetchImpl: that option exists
	// specifically so a caller can pin the exact transport (almost always a test), and
	// auto-detecting a real Unix socket out from under it -- silently ignoring the
	// override -- would defeat the entire point of the seam.
	const fallbackHandlePath = opts.fallbackHandlePath ?? ENIGMA_SYSTEM_RUNTIME_HANDLE;
	const unixSocketPath = opts.fetchImpl ? undefined : resolveAdminSocketPath(paths.handle, fallbackHandlePath);
	if (unixSocketPath) {
		// connectUnixRpc's own transport takes a real Request, not the (url, init) pair getJson
		// calls fetchImpl with (that shape matches plain fetch, not this transport) -- adapted
		// here rather than changing getJson's call convention, since real fetch is still what
		// every other caller of TryEnigmaCredentialOptions.fetchImpl (tests, future callers) expects.
		const transport = connectUnixRpc({ path: unixSocketPath, timeoutMs: ENIGMA_UNIX_LOOKUP_TIMEOUT_MS });
		const fetchImpl: typeof fetch = ((input: string | URL | Request, init?: RequestInit) =>
			transport(input instanceof Request ? input : new Request(input instanceof URL ? input.href : input, init))) as typeof fetch;
		return { baseUrl: UNIX_TRANSPORT_BASE_URL, fetchImpl };
	}

	const handle = resolveHandle(paths.handle, fallbackHandlePath);
	if (!handle) return undefined; // Enigma isn't running -- not an error, just not present
	const token = resolveToken(opts, paths.token);
	if (!token) return undefined;
	return { baseUrl: `http://${handle.host}:${handle.port}`, token, fetchImpl: opts.fetchImpl ?? fetch };
}

async function getJson<T>(vault: ConnectedVault, path: string): Promise<T | undefined> {
	const response = await vault.fetchImpl(`${vault.baseUrl}${path}`, {
		headers: vault.token !== undefined ? { authorization: `Bearer ${vault.token}` } : {},
		signal: AbortSignal.timeout(ENIGMA_LOOKUP_TIMEOUT_MS),
	});
	if (!response.ok) return undefined; // 401/403/404/5xx alike -- "nothing usable," never surfaced as an error
	return (await response.json()) as T;
}

/**
 * Unlike getJson (whose every caller treats a non-2xx as "nothing usable,"
 * collapsed to undefined), an admin mutation's caller genuinely needs to
 * know *why* it failed -- already registered, a uid already bound, not
 * authorized -- to give a useful message instead of a generic "didn't
 * work." Returns the parsed body and status on any response Enigma actually
 * sent; only a transport-level failure (unreachable, timed out) is the
 * caller's job to distinguish, via the outer function returning undefined.
 */
async function postJson<TBody, TResult>(vault: ConnectedVault, path: string, body: TBody): Promise<{ status: number; body: TResult | { error: string } | undefined }> {
	const response = await vault.fetchImpl(`${vault.baseUrl}${path}`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			...(vault.token !== undefined ? { authorization: `Bearer ${vault.token}` } : {}),
		},
		body: JSON.stringify(body),
		signal: AbortSignal.timeout(ENIGMA_LOOKUP_TIMEOUT_MS),
	});
	const parsed = await response.json().catch(() => undefined);
	return { status: response.status, body: parsed as TResult | { error: string } | undefined };
}

/** Fetches the full stored credential (accessToken + extra), for a backend whose credential is more than a bare token (url/username live in extra, e.g. Jenkins). */
export const tryEnigmaCredential: TryEnigmaCredential = async (backend, opts = {}) => {
	const vault = connect(opts);
	if (!vault) return undefined;
	try {
		return await getJson<VaultCredential>(vault, `/creds/${encodeURIComponent(backend)}`);
	} catch {
		return undefined; // unreachable, timed out, or any other transport failure -- fall through silently
	}
};

/** Resolves just the access token -- what a caller needs when it already resolves baseUrl/etc. separately from env. */
export const tryEnigmaAccessToken: TryEnigmaAccessToken = async (backend, opts = {}) => (await tryEnigmaCredential(backend, opts))?.accessToken;

/** This client's own real scope, from Enigma itself -- lets a caller discover its registered backends instead of hardcoding them. */
export const tryEnigmaWhoAmI: TryEnigmaWhoAmI = async (opts = {}) => {
	const vault = connect(opts);
	if (!vault) return undefined;
	try {
		return await getJson<EnigmaWhoAmI>(vault, "/whoami");
	} catch {
		return undefined;
	}
};

export interface EnigmaClientRegistrationRequest {
	name: string;
	backends: string[];
	/** Kernel-verified caller uid (SO_PEERCRED) to bind, for the Unix-socket transport's zero-token path. */
	uid?: number;
}

export type EnigmaAdminMutationResult = { ok: true; token: string } | { ok: false; status: number; error: string };

/**
 * Registers a new client against a *running* Enigma vault's admin identity
 * -- the daemon performs the write itself, so the caller never needs
 * filesystem access to wherever Enigma's own state actually lives (a
 * different service account's directory, on a real deployment). Requires
 * admin identity: the Unix-socket admin uid, an explicit admin opts.token,
 * or a readable shared admin-token file -- a registered client's own scoped
 * token can never call this, matching the server's own admin-only gate.
 *
 * Returns undefined when Enigma isn't reachable *at all* (not running, or no
 * admin identity available from this process) -- the caller's cue to fall
 * back to local-file registration, same "absence is not an error" contract
 * as tryEnigmaCredential/tryEnigmaWhoAmI. Once Enigma is actually reached,
 * every response -- success or a real rejection (already registered, uid
 * already bound, not authorized) -- is surfaced, never collapsed to
 * undefined: unlike a read, a failed *mutation* is something the caller
 * needs to react to, not silently fall through from.
 */
export async function addEnigmaClient(registration: EnigmaClientRegistrationRequest, opts: TryEnigmaCredentialOptions = {}): Promise<EnigmaAdminMutationResult | undefined> {
	const vault = connect(opts);
	if (!vault) return undefined;
	try {
		const { status, body } = await postJson<EnigmaClientRegistrationRequest, { token: string }>(vault, "/clients", registration);
		if (status >= 200 && status < 300) {
			const token = (body as { token?: string } | undefined)?.token;
			if (!token) return { ok: false, status, error: "malformed success response from Enigma (missing token)" };
			return { ok: true, token };
		}
		return { ok: false, status, error: (body as { error?: string } | undefined)?.error ?? `request failed with status ${status}` };
	} catch {
		return undefined; // unreachable, timed out, or any other transport failure
	}
}

/** Reissues a client's token, invalidating the old one immediately. Same reachability/error-surfacing contract as addEnigmaClient. */
export async function rotateEnigmaClient(name: string, opts: TryEnigmaCredentialOptions = {}): Promise<EnigmaAdminMutationResult | undefined> {
	const vault = connect(opts);
	if (!vault) return undefined;
	try {
		const { status, body } = await postJson<Record<string, never>, { token: string }>(vault, `/clients/${encodeURIComponent(name)}/rotate`, {});
		if (status >= 200 && status < 300) {
			const token = (body as { token?: string } | undefined)?.token;
			if (!token) return { ok: false, status, error: "malformed success response from Enigma (missing token)" };
			return { ok: true, token };
		}
		return { ok: false, status, error: (body as { error?: string } | undefined)?.error ?? `request failed with status ${status}` };
	} catch {
		return undefined;
	}
}

export type EnigmaRemoveResult = { ok: true } | { ok: false; status: number; error: string };

/** Deletes a client's registration; its token stops working immediately. Same reachability contract as addEnigmaClient/rotateEnigmaClient. */
export async function removeEnigmaClient(name: string, opts: TryEnigmaCredentialOptions = {}): Promise<EnigmaRemoveResult | undefined> {
	const vault = connect(opts);
	if (!vault) return undefined;
	try {
		const { status, body } = await postJson<Record<string, never>, undefined>(vault, `/clients/${encodeURIComponent(name)}/remove`, {});
		if (status >= 200 && status < 300) return { ok: true };
		return { ok: false, status, error: (body as { error?: string } | undefined)?.error ?? `request failed with status ${status}` };
	} catch {
		return undefined;
	}
}
