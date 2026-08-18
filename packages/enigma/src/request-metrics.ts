/**
 * Enigma's own tool/operation usage metrics wiring -- deliberately NOT
 * useExecutionMiddleware/registerVehicleMetricsOperations (see
 * @danypops/vehicle-server's own metrics README section for that shape,
 * used by every other Vehicle-protocol daemon in this ecosystem): Enigma
 * has no VehicleRegistry at all -- server.ts's handleRequest is a plain
 * fetch(request) route dispatcher (GET /creds/:backend, POST /clients,
 * ...), not an operation-dispatch surface. This module reuses the exact
 * same underlying VehicleMetricsStore/schema, just recorded and queried by
 * hand around that route dispatcher instead of through a registry's own
 * execution middleware.
 */
import type { VehicleMetricsQuery, VehicleMetricsStore, VehicleMetricsSummaryRow } from "@danypops/vehicle-server/metrics";

const VEHICLE_NAME = "enigma";

/**
 * Normalizes a request path into a bounded route template before it's ever recorded --
 * e.g. "/creds/openai" and "/creds/anthropic" both become "/creds/:backend", so a caller
 * inventing arbitrary backend/client names can never grow tool_name's own cardinality
 * without bound (the exact reason VehicleMetricsStore's schema treats tool_name as a
 * bounded, enumerable dimension in every other Vehicle daemon).
 */
export function normalizeEnigmaRoute(pathname: string): string {
	if (pathname.startsWith("/creds/")) return "/creds/:backend";
	if (pathname.startsWith("/rotate/")) return "/rotate/:backend";
	if (pathname.startsWith("/revoke/")) return "/revoke/:backend";
	if (pathname.startsWith("/clients/") && pathname.endsWith("/rotate")) return "/clients/:name/rotate";
	if (pathname.startsWith("/clients/") && pathname.endsWith("/remove")) return "/clients/:name/remove";
	return pathname;
}

/**
 * Wraps a request handler (handleRequest, shared by both the TCP and Unix-socket
 * transports) to record every call's outcome/duration -- best-effort: a store failure is
 * logged and swallowed, never altering the real handler's own result. Matches
 * vehicle-metrics-middleware.ts's own "never masks the real call's outcome" contract.
 */
export function withEnigmaRequestMetrics<Args extends unknown[]>(
	handler: (...args: Args) => Promise<Response>,
	store: VehicleMetricsStore,
	requestOf: (...args: Args) => Request,
): (...args: Args) => Promise<Response> {
	return async (...args: Args) => {
		const request = requestOf(...args);
		const toolName = normalizeEnigmaRoute(new URL(request.url).pathname);
		const startedAt = Date.now();
		let response: Response;
		try {
			response = await handler(...args);
		} catch (error) {
			safeRecord(store, toolName, "failure", Date.now() - startedAt, error);
			throw error;
		}
		safeRecord(store, toolName, response.status < 400 ? "success" : "failure", Date.now() - startedAt);
		return response;
	};
}

function safeRecord(
	store: VehicleMetricsStore,
	toolName: string,
	outcome: "success" | "failure",
	durationMs: number,
	error?: unknown,
): void {
	try {
		store.record({
			source: "server",
			vehicleName: VEHICLE_NAME,
			toolName,
			outcome,
			durationMs,
			...(error !== undefined ? { errorCode: error instanceof Error ? error.name : "unknown-error" } : {}),
		});
	} catch {
		// Best-effort -- a metrics-store failure must never affect the real request's own result.
	}
}

/** Backs the admin-only GET /metrics route -- no VehicleRegistry exists here to expose a discoverable metrics.query operation on. */
export function queryEnigmaMetrics(store: VehicleMetricsStore, query: VehicleMetricsQuery): readonly VehicleMetricsSummaryRow[] {
	return store.query(query);
}
