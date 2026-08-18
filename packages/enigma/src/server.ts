/**
 * Vault HTTP server: loopback-only. Two distinct credentials, two distinct
 * privilege levels -- the admin token may call every route; a registered
 * client's own token may only call GET /creds/:backend (scoped to its
 * registered backends) and GET /whoami (its own name + backend list).
 */

import type { Logger } from "@danypops/vehicle-server/logging";
import type { VehicleMetricsQuery, VehicleMetricsStore } from "@danypops/vehicle-server/metrics";
import {
	errorResponse,
	extractBearerToken,
	healthResponse,
	jsonResponse,
	readyResponse,
	requireBearerToken,
} from "@danypops/vehicle-server/rpc-http";
import type { PeerCredential } from "@danypops/vehicle-server/unix-peer-cred";
import { normalizeBackendName } from "./backend-env-mapping.ts";
import { resolveRefreshFn } from "./backend-refresh.ts";
import {
	ClientAlreadyRegisteredError,
	ClientNotFoundError,
	type ClientRegistration,
	type ClientRegistry,
	UidAlreadyBoundError,
} from "./client-registry.ts";
import type { CredentialVault } from "./credential-vault.ts";
import type { OidcFetch } from "./login-command.ts";
import { ENIGMA_MANAGE_CLIENTS_ACTION_ID, type PolkitCheck } from "./polkit-check.ts";
import { queryEnigmaMetrics, withEnigmaRequestMetrics } from "./request-metrics.ts";
import { VERSION } from "./version.ts";

export interface ServerDeps {
	vault: CredentialVault;
	token: string;
	clients: ClientRegistry;
	/** Test-only injection point; production leaves this unset and uses global fetch. */
	fetchImpl?: OidcFetch;
	/**
	 * Every credential read/rotate/revoke is audit-logged when this is
	 * supplied -- matching a real secrets manager's own audit-device model
	 * (who accessed what, when, outcome), not just a redacted UI. Optional so
	 * existing tests constructing ServerDeps without one keep working; a
	 * production daemon should always supply the real logger.
	 */
	logger?: Logger;
	/**
	 * Optional, Linux-only, opt-in: asks polkit whether a specific
	 * kernel-verified Unix-socket caller is authorized for one narrow action
	 * (today: registering a client), layered on top of -- never replacing --
	 * the existing admin-uid/bearer-token checks. Absent by default; every
	 * existing caller's behavior is exactly unchanged without it. Never
	 * consulted for the bearer-token/TCP transport (no `peer` to check
	 * against there) or for any route besides POST /clients -- see
	 * polkit-check.ts for why (a polkit round-trip can block on a human
	 * clicking a dialog, unacceptable latency for anything on the hot path).
	 */
	polkitCheck?: PolkitCheck;
	/**
	 * Tool/operation usage metrics -- see request-metrics.ts's own header comment for why this
	 * daemon records/exposes them by hand instead of through useExecutionMiddleware/
	 * registerVehicleMetricsOperations (no VehicleRegistry exists here). Optional so existing
	 * tests constructing ServerDeps without one keep working; a production daemon should always
	 * supply the real store (see daemon.ts).
	 */
	metrics?: VehicleMetricsStore;
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
type Identity = { kind: "admin"; uid?: number } | { kind: "client"; registration: ClientRegistration; uid?: number } | { kind: "none" };

function identityFromBearer(request: Request, deps: ServerDeps): Identity {
	if (requireBearerToken(request, deps.token)) return { kind: "admin" };
	const presented = extractBearerToken(request);
	const client = presented ? deps.clients.authenticate(presented) : undefined;
	return client ? { kind: "client", registration: client } : { kind: "none" };
}

/** Never includes credential material -- only who (kind/name/uid), never what value they got back. */
function auditIdentity(identity: Identity): Record<string, unknown> {
	if (identity.kind === "none") return { identity: "none" };
	const uidField = identity.uid !== undefined ? { uid: identity.uid } : {};
	return identity.kind === "admin"
		? { identity: "admin", ...uidField }
		: { identity: "client", client: identity.registration.name, ...uidField };
}

/**
 * Structured audit trail for every credential read/rotate/revoke -- matching
 * a real secrets manager's own audit-device model (who touched what secret,
 * when, and what happened), not merely a redacted display. Never logs the
 * credential value itself, only the fact and outcome of the access.
 */
function auditCredentialEvent(
	deps: ServerDeps,
	event: string,
	backend: string,
	identity: Identity,
	outcome: "ok" | "denied" | "not_found" | "unauthenticated",
): void {
	deps.logger?.info(event, { backend, outcome, ...auditIdentity(identity) });
}

/** Case-insensitive: a backend name is a lookup key, not display text (see normalizeBackendName). */
function pathBackend(pathname: string, prefix: string): string | undefined {
	if (!pathname.startsWith(prefix)) return undefined;
	const rest = pathname.slice(prefix.length);
	return rest ? normalizeBackendName(decodeURIComponent(rest)) : undefined;
}

/** Matches "/clients/:name<suffix>", e.g. pathClientName("/clients/pipes/rotate", "/rotate") -> "pipes". A client name is never case-normalized (unlike a backend name) -- it's the operator's own chosen label, not a lookup key with multiple valid spellings. */
function pathClientName(pathname: string, suffix: string): string | undefined {
	if (!pathname.startsWith("/clients/") || !pathname.endsWith(suffix)) return undefined;
	const middle = pathname.slice("/clients/".length, pathname.length - suffix.length);
	return middle ? decodeURIComponent(middle) : undefined;
}

async function handleRequest(request: Request, deps: ServerDeps, identity: Identity, peer?: PeerCredential): Promise<Response> {
	const url = new URL(request.url);
	const isAdmin = identity.kind === "admin";

	// GET /creds/:backend accepts either the admin identity or a registered
	// client's own identity, scoped to only the backends that client was
	// registered for -- every other route is admin-only.
	const credsBackend = pathBackend(url.pathname, "/creds/");
	if (request.method === "GET" && credsBackend) {
		if (!isAdmin) {
			if (identity.kind !== "client") {
				auditCredentialEvent(deps, "credential_access", credsBackend, identity, "unauthenticated");
				return errorResponse("missing or invalid bearer token", 401);
			}
			// Normalized again here, not just at registration time: an already-registered
			// client's stored backends predate this normalization and may still carry
			// whatever casing was typed at `enigma client add` time.
			if (!identity.registration.backends.map(normalizeBackendName).includes(credsBackend)) {
				auditCredentialEvent(deps, "credential_access", credsBackend, identity, "denied");
				return errorResponse(`client "${identity.registration.name}" is not registered for backend "${credsBackend}"`, 403);
			}
		}
		const credential = deps.vault.get(credsBackend);
		if (!credential) {
			auditCredentialEvent(deps, "credential_access", credsBackend, identity, "not_found");
			return errorResponse(`no credential stored for backend "${credsBackend}"`, 404);
		}
		auditCredentialEvent(deps, "credential_access", credsBackend, identity, "ok");
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

	// Registers a new client the same way `enigma client add` does locally --
	// the daemon itself performs the write, so an admin caller never needs
	// filesystem access to wherever the registry actually lives (a different
	// service account's state directory, on a real deployment). Admin-gated
	// like every other client-registry mutation, but with one narrow, opt-in
	// exception: a non-admin Unix-socket caller polkit specifically
	// authorizes for this one action (see polkit-check.ts) -- checked here,
	// before the blanket admin gate below, the same way /creds/:backend and
	// /whoami carve out their own non-admin paths above.
	if (request.method === "POST" && url.pathname === "/clients") {
		if (!isAdmin) {
			const authorizedByPolkit = peer && deps.polkitCheck ? await deps.polkitCheck(peer, ENIGMA_MANAGE_CLIENTS_ACTION_ID) : false;
			if (!authorizedByPolkit) return errorResponse("missing or invalid bearer token", 401);
		}
		let body: { name?: unknown; backends?: unknown; uid?: unknown };
		try {
			body = (await request.json()) as typeof body;
		} catch {
			return errorResponse("malformed JSON body", 400);
		}
		const { name, backends, uid } = body;
		if (
			typeof name !== "string" ||
			!name ||
			!Array.isArray(backends) ||
			backends.length === 0 ||
			!backends.every((b) => typeof b === "string")
		) {
			return errorResponse("name (string) and backends (non-empty string array) are required", 400);
		}
		if (uid !== undefined && (typeof uid !== "number" || !Number.isInteger(uid) || uid < 0)) {
			return errorResponse("uid must be a non-negative integer when given", 400);
		}
		try {
			const token = deps.clients.add(name, backends, uid !== undefined ? { uid } : undefined);
			return jsonResponse({ token }, { status: 201 });
		} catch (error) {
			if (error instanceof ClientAlreadyRegisteredError || error instanceof UidAlreadyBoundError) {
				return errorResponse(error.message, 409);
			}
			throw error;
		}
	}

	if (!isAdmin) return errorResponse("missing or invalid bearer token", 401);

	if (request.method === "GET" && url.pathname === "/health") return healthResponse(VERSION);
	if (request.method === "GET" && url.pathname === "/ready") return readyResponse(true);
	if (request.method === "GET" && url.pathname === "/metrics") {
		if (!deps.metrics) return jsonResponse([]);
		const params = url.searchParams;
		const groupBy = params.get("groupBy");
		return jsonResponse(
			queryEnigmaMetrics(deps.metrics, {
				...(params.has("since") ? { since: Number(params.get("since")) } : {}),
				...(params.has("until") ? { until: Number(params.get("until")) } : {}),
				...(params.has("toolName") ? { toolName: params.get("toolName") as string } : {}),
				...(groupBy ? { groupBy: groupBy.split(",") as VehicleMetricsQuery["groupBy"] } : {}),
			}),
		);
	}
	if (request.method === "GET" && url.pathname === "/keys") {
		return jsonResponse(deps.vault.listBackends());
	}
	// The [services] side of the /secrets model: every registered client and which
	// backends it may use. Admin-only, like /keys -- a registered client's own token
	// only ever sees its own scope via /whoami, never the full roster.
	if (request.method === "GET" && url.pathname === "/clients") {
		return jsonResponse(deps.clients.list());
	}

	// Named the same verb-as-path way as /rotate/:backend and /revoke/:backend above,
	// for one consistent style rather than mixing in a DELETE-based REST convention
	// for just this one resource.
	const rotateClientName = pathClientName(url.pathname, "/rotate");
	if (request.method === "POST" && rotateClientName) {
		try {
			const token = deps.clients.rotate(rotateClientName);
			return jsonResponse({ token });
		} catch (error) {
			if (error instanceof ClientNotFoundError) return errorResponse(error.message, 404);
			throw error;
		}
	}

	const removeClientName = pathClientName(url.pathname, "/remove");
	if (request.method === "POST" && removeClientName) {
		try {
			deps.clients.remove(removeClientName);
			return new Response(null, { status: 204 });
		} catch (error) {
			if (error instanceof ClientNotFoundError) return errorResponse(error.message, 404);
			throw error;
		}
	}

	const rotateBackend = pathBackend(url.pathname, "/rotate/");
	if (request.method === "POST" && rotateBackend) {
		const current = deps.vault.get(rotateBackend);
		if (!current) {
			auditCredentialEvent(deps, "credential_rotate", rotateBackend, identity, "not_found");
			return errorResponse(`no credential stored for backend "${rotateBackend}"`, 404);
		}
		const refresh = resolveRefreshFn(current, deps.fetchImpl);
		if (!refresh) {
			auditCredentialEvent(deps, "credential_rotate", rotateBackend, identity, "denied");
			return errorResponse(`backend "${rotateBackend}" has no refresh function configured`, 400);
		}
		try {
			const refreshed = await refresh(current);
			deps.vault.save(rotateBackend, refreshed);
			auditCredentialEvent(deps, "credential_rotate", rotateBackend, identity, "ok");
			return new Response(null, { status: 204 });
		} catch (error) {
			auditCredentialEvent(deps, "credential_rotate", rotateBackend, identity, "denied");
			return errorResponse(error instanceof Error ? error.message : String(error), 502);
		}
	}

	const revokeBackend = pathBackend(url.pathname, "/revoke/");
	if (request.method === "POST" && revokeBackend) {
		deps.vault.delete(revokeBackend);
		auditCredentialEvent(deps, "credential_revoke", revokeBackend, identity, "ok");
		return new Response(null, { status: 204 });
	}

	return errorResponse("not found", 404);
}

export function createApp(deps: ServerDeps): { fetch(request: Request): Promise<Response> } {
	const dispatch = (request: Request) => handleRequest(request, deps, identityFromBearer(request, deps));
	return {
		// No peer at all over this transport -- polkitCheck (peer-keyed) can never apply here,
		// by construction, not merely by convention.
		fetch: deps.metrics ? withEnigmaRequestMetrics(dispatch, deps.metrics, (request) => request) : dispatch,
	};
}

export interface UnixSocketIdentityOptions {
	/** The one uid trusted for full admin access over the Unix transport -- typically the operator's own uid. */
	adminUid?: number;
}

/**
 * Builds a request handler for `@danypops/vehicle-server/unix-rpc-server`'s
 * `serveUnixRpc`: identity comes only from the kernel-verified peer uid
 * SO_PEERCRED already resolved before this is ever called, never from an
 * Authorization header a peer could present over this transport (there is
 * no bearer-token concept here at all -- any header is simply ignored).
 */
export function createUnixSocketHandler(deps: ServerDeps, options: UnixSocketIdentityOptions = {}) {
	const dispatch = (request: Request, peer: PeerCredential): Promise<Response> => {
		const identity: Identity =
			options.adminUid !== undefined && peer.uid === options.adminUid
				? { kind: "admin", uid: peer.uid }
				: (() => {
						const registration = deps.clients.authenticateByUid(peer.uid);
						return registration ? ({ kind: "client", registration, uid: peer.uid } as const) : ({ kind: "none" } as const);
					})();
		return handleRequest(request, deps, identity, peer);
	};
	return deps.metrics ? withEnigmaRequestMetrics(dispatch, deps.metrics, (request) => request) : dispatch;
}
