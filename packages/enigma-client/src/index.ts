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
import { join } from "node:path";
import { readDaemonHandle, resolveDaemonPaths, type DaemonHandle } from "@danypops/daemon-kit/paths";
import type { RefreshableAccessToken } from "@danypops/daemon-kit/vault";

const ENIGMA_STATE_DIRECTORY_NAME = "enigma";
const ENIGMA_HANDLE_FILENAME = "handle.json";
const ENIGMA_TOKEN_FILENAME = "token";
const ENIGMA_LOOKUP_TIMEOUT_MS = 500;
/** Enigma is typically a system-level service (unlike a same-user daemon), so its handle can live outside any one process's own $XDG_RUNTIME_DIR. */
const ENIGMA_SYSTEM_RUNTIME_HANDLE = join("/run", ENIGMA_STATE_DIRECTORY_NAME, ENIGMA_HANDLE_FILENAME);

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
	token: string;
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

function connect(opts: TryEnigmaCredentialOptions): ConnectedVault | undefined {
	const env = opts.env ?? process.env;
	const paths = resolveDaemonPaths(
		{ stateDirectoryName: ENIGMA_STATE_DIRECTORY_NAME, handleFilename: ENIGMA_HANDLE_FILENAME, tokenFilename: ENIGMA_TOKEN_FILENAME, databaseFilename: "", systemdUnitName: "" },
		{ env },
	);
	const handle = resolveHandle(paths.handle, ENIGMA_SYSTEM_RUNTIME_HANDLE);
	if (!handle) return undefined; // Enigma isn't running -- not an error, just not present
	const token = resolveToken(opts, paths.token);
	if (!token) return undefined;
	return { baseUrl: `http://${handle.host}:${handle.port}`, token, fetchImpl: opts.fetchImpl ?? fetch };
}

async function getJson<T>(vault: ConnectedVault, path: string): Promise<T | undefined> {
	const response = await vault.fetchImpl(`${vault.baseUrl}${path}`, {
		headers: { authorization: `Bearer ${vault.token}` },
		signal: AbortSignal.timeout(ENIGMA_LOOKUP_TIMEOUT_MS),
	});
	if (!response.ok) return undefined; // 401/403/404/5xx alike -- "nothing usable," never surfaced as an error
	return (await response.json()) as T;
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
