/**
 * Per-consumer registration: which daemons may call /creds/:backend, and for
 * which backends. Each registered client gets its own token, minted once and
 * never stored in plaintext -- only its SHA-256 hash is kept at rest, so
 * reading this file back never recovers a usable credential. Replaces "any
 * bearer of the vault's own admin token can fetch any backend" with
 * per-client least privilege: one consumer's token can't fetch a backend
 * it was never registered for, let alone another consumer's entirely.
 */
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { normalizeBackendName } from "./backend-env-mapping.ts";

const CLIENT_TOKEN_BYTES = 32;
const MAX_REGISTRY_BYTES = 1024 * 1024;

export interface ClientRegistration {
	name: string;
	backends: string[];
	tokenHash: string;
	createdAt: string;
	/** Kernel-verified caller uid (SO_PEERCRED), bound at registration time. A uid resolves to at most one client. */
	uid?: number;
}

export interface AddClientOptions {
	uid?: number;
}

export type PublicClientRegistration = Omit<ClientRegistration, "tokenHash">;

interface ClientRegistryFile {
	version: 1;
	clients: ClientRegistration[];
}

export class ClientAlreadyRegisteredError extends Error {
	constructor(name: string) {
		super(`client "${name}" is already registered`);
		this.name = "ClientAlreadyRegisteredError";
	}
}

export class ClientNotFoundError extends Error {
	constructor(name: string) {
		super(`no registered client named "${name}"`);
		this.name = "ClientNotFoundError";
	}
}

export class UidAlreadyBoundError extends Error {
	constructor(uid: number, existingName: string) {
		super(`uid ${uid} is already bound to client "${existingName}" -- a uid can only resolve to one client`);
		this.name = "UidAlreadyBoundError";
	}
}

export interface ClientRegistry {
	/** Registers a new client, returns its plaintext token -- the only time it's ever visible. */
	add(name: string, backends: string[], options?: AddClientOptions): string;
	/** Issues a new token for an existing client, invalidating the old one immediately. Preserves any bound uid. */
	rotate(name: string): string;
	remove(name: string): void;
	list(): PublicClientRegistration[];
	/** Resolves a presented bearer token to its owning client, or undefined if unrecognized. */
	authenticate(token: string): ClientRegistration | undefined;
	/** Resolves a kernel-verified caller uid (SO_PEERCRED) to its owning client, or undefined if no client is bound to it. */
	authenticateByUid(uid: number): ClientRegistration | undefined;
}

function hashToken(token: string): string {
	return createHash("sha256").update(token).digest("hex");
}

function atomicWriteFile(path: string, contents: string): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const temp = `${path}.${process.pid}.tmp`;
	writeFileSync(temp, contents, { mode: 0o600 });
	renameSync(temp, path);
}

function load(path: string): ClientRegistryFile {
	if (!existsSync(path)) return { version: 1, clients: [] };
	const raw = readFileSync(path, "utf8");
	if (raw.length > MAX_REGISTRY_BYTES) throw new Error(`client registry at ${path} exceeds ${MAX_REGISTRY_BYTES} bytes`);
	const parsed = JSON.parse(raw) as Partial<ClientRegistryFile>;
	if (parsed.version !== 1 || !Array.isArray(parsed.clients)) throw new Error(`client registry at ${path} is malformed`);
	return parsed as ClientRegistryFile;
}

function save(path: string, registry: ClientRegistryFile): void {
	atomicWriteFile(path, `${JSON.stringify(registry, null, 2)}\n`);
}

export function createClientRegistry(path: string): ClientRegistry {
	return {
		add(name, backends, options) {
			const registry = load(path);
			if (registry.clients.some((c) => c.name === name)) throw new ClientAlreadyRegisteredError(name);
			if (options?.uid !== undefined) {
				const boundTo = registry.clients.find((c) => c.uid === options.uid);
				if (boundTo) throw new UidAlreadyBoundError(options.uid, boundTo.name);
			}
			const token = randomBytes(CLIENT_TOKEN_BYTES).toString("hex");
			registry.clients.push({
				name,
				backends: backends.map(normalizeBackendName),
				tokenHash: hashToken(token),
				createdAt: new Date().toISOString(),
				...(options?.uid !== undefined ? { uid: options.uid } : {}),
			});
			save(path, registry);
			return token;
		},
		rotate(name) {
			const registry = load(path);
			const client = registry.clients.find((c) => c.name === name);
			if (!client) throw new ClientNotFoundError(name);
			const token = randomBytes(CLIENT_TOKEN_BYTES).toString("hex");
			client.tokenHash = hashToken(token);
			save(path, registry);
			return token;
		},
		remove(name) {
			const registry = load(path);
			const next = registry.clients.filter((c) => c.name !== name);
			if (next.length === registry.clients.length) throw new ClientNotFoundError(name);
			save(path, { version: 1, clients: next });
		},
		list() {
			return load(path).clients.map(({ name, backends, createdAt, uid }) =>
				uid !== undefined ? { name, backends, createdAt, uid } : { name, backends, createdAt },
			);
		},
		authenticate(token) {
			const hash = hashToken(token);
			return load(path).clients.find((c) => c.tokenHash === hash);
		},
		authenticateByUid(uid) {
			return load(path).clients.find((c) => c.uid === uid);
		},
	};
}
