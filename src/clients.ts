import { randomToken, sha256, timingSafeEqual } from './crypto';

/** A site or application that registered with the proxy. Stored in KV under `client:<id>`. */
export interface Client {
	id: string;
	name: string;
	redirectUris: string[];
	secretHash: string;
	createdAt: string;
}

export interface Registration {
	name: string;
	redirectUris: string[];
}

export class RegistrationError extends Error {
	constructor(
		public readonly code: 'invalid_client_metadata' | 'invalid_redirect_uri',
		message: string,
	) {
		super(message);
	}
}

const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

/**
 * A redirect URI is https, or http on the local machine for development. Twinfield never sees it:
 * it only knows the callback of the proxy.
 */
export function isAllowedRedirectUri(value: string): boolean {
	if (value.length > 500) {
		return false;
	}

	let url: URL;

	try {
		url = new URL(value);
	} catch {
		return false;
	}

	if (url.hash !== '' || value.includes('#') || url.username !== '' || url.password !== '') {
		return false;
	}

	return url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK_HOSTS.includes(url.hostname));
}

/** Validates the body of a registration request (RFC 7591). */
export function parseRegistration(body: unknown): Registration {
	if (typeof body !== 'object' || body === null || Array.isArray(body)) {
		throw new RegistrationError('invalid_client_metadata', 'The request body must be a JSON object.');
	}

	const { client_name: name, redirect_uris: redirectUris } = body as Record<string, unknown>;

	if (typeof name !== 'string' || name.trim() === '' || name.length > 100) {
		throw new RegistrationError('invalid_client_metadata', '"client_name" must be a string of 1 to 100 characters.');
	}

	if (!Array.isArray(redirectUris) || redirectUris.length < 1 || redirectUris.length > 10) {
		throw new RegistrationError('invalid_redirect_uri', '"redirect_uris" must be a list of 1 to 10 URLs.');
	}

	for (const uri of redirectUris) {
		if (typeof uri !== 'string' || !isAllowedRedirectUri(uri)) {
			throw new RegistrationError(
				'invalid_redirect_uri',
				'A redirect URI must be an https URL, or an http URL on localhost, without a fragment.',
			);
		}
	}

	return { name: name.trim(), redirectUris: [...new Set(redirectUris as string[])] };
}

export class ClientStore {
	constructor(private readonly kv: KVNamespace) {}

	/** Stores a new client and returns it with its secret, which is only known at this moment. */
	async create(registration: Registration): Promise<{ client: Client; secret: string }> {
		const secret = randomToken(32);
		const client: Client = {
			id: randomToken(16),
			name: registration.name,
			redirectUris: registration.redirectUris,
			secretHash: await sha256(secret),
			createdAt: new Date().toISOString(),
		};

		await this.kv.put(`client:${client.id}`, JSON.stringify(client));

		return { client, secret };
	}

	async find(id: string): Promise<Client | null> {
		if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) {
			return null;
		}

		return await this.kv.get<Client>(`client:${id}`, 'json');
	}

	async authenticate(id: string, secret: string): Promise<Client | null> {
		const client = await this.find(id);

		// The secret has 256 bits of entropy, so a plain SHA-256 is enough.
		return client !== null && timingSafeEqual(client.secretHash, await sha256(secret)) ? client : null;
	}
}
