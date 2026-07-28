/**
 * Vault HTTP server: loopback-only. Two distinct credentials, two distinct
 * privilege levels -- the admin token may call every route; a registered
 * client's own token may only call GET /creds/:backend (scoped to its
 * registered backends) and GET /whoami (its own name + backend list).
 */
import { errorResponse, extractBearerToken, healthResponse, jsonResponse, readyResponse, requireBearerToken } from "@danypops/daemon-kit/http";
import type { PeerCredential } from "@danypops/daemon-kit/unix-peer-cred";
import { normalizeBackendName } from "./backend-env-mapping.ts";
import { resolveRefreshFn } from "./backend-refresh.ts";
import type { ClientRegistration, ClientRegistry } from "./client-registry.ts";
import type { CredentialVault } from "./credential-vault.ts";
import type { OidcFetch } from "./login-command.ts";
import { VERSION } from "./version.ts";

export interface ServerDeps {
	vault: CredentialVault;
	token: string;
	clients: ClientRegistry;
	/** Test-only injection point; production leaves this unset and uses global fetch. */
	fetchImpl?: OidcFetch;
}

/**
 * Who a request is allowed to act as -- resolved once per request, from
 * whichever transport-specific identity proof applies (a bearer token over
 * TCP, a kernel-verified peer uid over a Unix socket), then threaded
 * through the same route logic either way. Route handling never re-derives
 * identity from the request itself, so a Unix-socket caller's Authorization
 * header (if it even sent one) is never consulted -- identity comes only
 * from what the transport itself already verified.
 */
type Identity = { kind: "admin" } | { kind: "client"; registration: ClientRegistration } | { kind: "none" };

function identityFromBearer(request: Request, deps: ServerDeps): Identity {
	if (requireBearerToken(request, deps.token)) return { kind: "admin" };
	const presented = extractBearerToken(request);
	const client = presented ? deps.clients.authenticate(presented) : undefined;
	return client ? { kind: "client", registration: client } : { kind: "none" };
}

/** Case-insensitive: a backend name is a lookup key, not display text (see normalizeBackendName). */
function pathBackend(pathname: string, prefix: string): string | undefined {
	if (!pathname.startsWith(prefix)) return undefined;
	const rest = pathname.slice(prefix.length);
	return rest ? normalizeBackendName(decodeURIComponent(rest)) : undefined;
}

async function handleRequest(request: Request, deps: ServerDeps, identity: Identity): Promise<Response> {
	const url = new URL(request.url);
	const isAdmin = identity.kind === "admin";

	// GET /creds/:backend accepts either the admin identity or a registered
	// client's own identity, scoped to only the backends that client was
	// registered for -- every other route is admin-only.
	const credsBackend = pathBackend(url.pathname, "/creds/");
	if (request.method === "GET" && credsBackend) {
		if (!isAdmin) {
			if (identity.kind !== "client") return errorResponse("missing or invalid bearer token", 401);
			// Normalized again here, not just at registration time: an already-registered
			// client's stored backends predate this normalization and may still carry
			// whatever casing was typed at `enigma client add` time.
			if (!identity.registration.backends.map(normalizeBackendName).includes(credsBackend)) {
				return errorResponse(`client "${identity.registration.name}" is not registered for backend "${credsBackend}"`, 403);
			}
		}
		const credential = deps.vault.get(credsBackend);
		if (!credential) return errorResponse(`no credential stored for backend "${credsBackend}"`, 404);
		return jsonResponse(credential);
	}

	// A client's own name + backend list -- nothing sensitive, so any
	// resolved identity works. Lets a consumer discover its real scope
	// instead of hardcoding backend names.
	if (request.method === "GET" && url.pathname === "/whoami") {
		if (isAdmin) return jsonResponse({ name: "admin", backends: null });
		if (identity.kind !== "client") return errorResponse("missing or invalid bearer token", 401);
		return jsonResponse({ name: identity.registration.name, backends: identity.registration.backends.map(normalizeBackendName) });
	}

	if (!isAdmin) return errorResponse("missing or invalid bearer token", 401);

	if (request.method === "GET" && url.pathname === "/health") return healthResponse(VERSION);
	if (request.method === "GET" && url.pathname === "/ready") return readyResponse(true);
	if (request.method === "GET" && url.pathname === "/keys") {
		return jsonResponse(deps.vault.listBackends());
	}

	const rotateBackend = pathBackend(url.pathname, "/rotate/");
	if (request.method === "POST" && rotateBackend) {
		const current = deps.vault.get(rotateBackend);
		if (!current) return errorResponse(`no credential stored for backend "${rotateBackend}"`, 404);
		const refresh = resolveRefreshFn(current, deps.fetchImpl);
		if (!refresh) return errorResponse(`backend "${rotateBackend}" has no refresh function configured`, 400);
		try {
			const refreshed = await refresh(current);
			deps.vault.save(rotateBackend, refreshed);
			return new Response(null, { status: 204 });
		} catch (error) {
			return errorResponse(error instanceof Error ? error.message : String(error), 502);
		}
	}

	const revokeBackend = pathBackend(url.pathname, "/revoke/");
	if (request.method === "POST" && revokeBackend) {
		deps.vault.delete(revokeBackend);
		return new Response(null, { status: 204 });
	}

	return errorResponse("not found", 404);
}

export function createApp(deps: ServerDeps): { fetch(request: Request): Promise<Response> } {
	return {
		fetch: (request: Request) => handleRequest(request, deps, identityFromBearer(request, deps)),
	};
}

export interface UnixSocketIdentityOptions {
	/** The one uid trusted for full admin access over the Unix transport -- typically the operator's own uid. */
	adminUid?: number;
}

/**
 * Builds a request handler for `@danypops/daemon-kit/unix-rpc-server`'s
 * `serveUnixRpc`: identity comes only from the kernel-verified peer uid
 * SO_PEERCRED already resolved before this is ever called, never from an
 * Authorization header a peer could present over this transport (there is
 * no bearer-token concept here at all -- any header is simply ignored).
 */
export function createUnixSocketHandler(deps: ServerDeps, options: UnixSocketIdentityOptions = {}) {
	return (request: Request, peer: PeerCredential): Promise<Response> => {
		const identity: Identity =
			options.adminUid !== undefined && peer.uid === options.adminUid
				? { kind: "admin" }
				: (() => {
						const registration = deps.clients.authenticateByUid(peer.uid);
						return registration ? ({ kind: "client", registration } as const) : ({ kind: "none" } as const);
					})();
		return handleRequest(request, deps, identity);
	};
}
