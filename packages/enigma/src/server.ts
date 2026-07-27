/**
 * Vault HTTP server: loopback-only. Two distinct credentials, two distinct
 * privilege levels -- the admin token may call every route; a registered
 * client's own token may only call GET /creds/:backend (scoped to its
 * registered backends) and GET /whoami (its own name + backend list).
 */
import { errorResponse, extractBearerToken, healthResponse, jsonResponse, readyResponse, requireBearerToken } from "@danypops/daemon-kit/http";
import { resolveRefreshFn } from "./backend-refresh.ts";
import type { ClientRegistry } from "./client-registry.ts";
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

function pathBackend(pathname: string, prefix: string): string | undefined {
	if (!pathname.startsWith(prefix)) return undefined;
	const rest = pathname.slice(prefix.length);
	return rest ? decodeURIComponent(rest) : undefined;
}

export function createApp(deps: ServerDeps): { fetch(request: Request): Promise<Response> } {
	return {
		async fetch(request: Request): Promise<Response> {
			const url = new URL(request.url);
			const isAdmin = requireBearerToken(request, deps.token);

			// GET /creds/:backend accepts either the admin token or a registered
			// client's own token, scoped to only the backends that client was
			// registered for -- every other route is admin-only.
			const credsBackend = pathBackend(url.pathname, "/creds/");
			if (request.method === "GET" && credsBackend) {
				if (!isAdmin) {
					const presented = extractBearerToken(request);
					const client = presented ? deps.clients.authenticate(presented) : undefined;
					if (!client) return errorResponse("missing or invalid bearer token", 401);
					if (!client.backends.includes(credsBackend)) {
						return errorResponse(`client "${client.name}" is not registered for backend "${credsBackend}"`, 403);
					}
				}
				const credential = deps.vault.get(credsBackend);
				if (!credential) return errorResponse(`no credential stored for backend "${credsBackend}"`, 404);
				return jsonResponse(credential);
			}

			// A client's own name + backend list -- nothing sensitive, so any
			// bearer works. Lets a consumer discover its real scope instead of
			// hardcoding backend names.
			if (request.method === "GET" && url.pathname === "/whoami") {
				if (isAdmin) return jsonResponse({ name: "admin", backends: null });
				const presented = extractBearerToken(request);
				const client = presented ? deps.clients.authenticate(presented) : undefined;
				if (!client) return errorResponse("missing or invalid bearer token", 401);
				return jsonResponse({ name: client.name, backends: client.backends });
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
		},
	};
}
