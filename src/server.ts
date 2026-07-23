/**
 * Vault HTTP server: loopback-only, authenticated with daemon-kit's usual
 * bearer-token pattern. This bearer token is the supervisor's own vault
 * credential — never something an agent process holds or could obtain;
 * if that boundary is already broken, the vault's isolation is moot
 * regardless of what this server does.
 */
import { errorResponse, healthResponse, jsonResponse, readyResponse, requireBearerToken } from "@danypops/daemon-kit/http";
import { resolveRefreshFn } from "./backend-refresh.ts";
import type { CredentialVault } from "./credential-vault.ts";
import type { OidcFetch } from "./login-command.ts";
import { VERSION } from "./version.ts";

export interface ServerDeps {
	vault: CredentialVault;
	token: string;
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
			if (!requireBearerToken(request, deps.token)) {
				return errorResponse("missing or invalid bearer token", 401);
			}
			const url = new URL(request.url);

			if (request.method === "GET" && url.pathname === "/health") return healthResponse(VERSION);
			if (request.method === "GET" && url.pathname === "/ready") return readyResponse(true);
			if (request.method === "GET" && url.pathname === "/keys") {
				return jsonResponse(deps.vault.listBackends());
			}

			const credsBackend = pathBackend(url.pathname, "/creds/");
			if (request.method === "GET" && credsBackend) {
				const credential = deps.vault.get(credsBackend);
				if (!credential) return errorResponse(`no credential stored for backend "${credsBackend}"`, 404);
				return jsonResponse(credential);
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
