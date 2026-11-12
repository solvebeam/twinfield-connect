const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function base64UrlEncode(bytes: Uint8Array): string {
	let binary = '';

	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}

	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> {
	if (!/^[A-Za-z0-9_-]*$/.test(value)) {
		throw new Error('Not a base64url value.');
	}

	const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
	const bytes = new Uint8Array(binary.length);

	for (let index = 0; index < binary.length; index++) {
		bytes[index] = binary.charCodeAt(index);
	}

	return bytes;
}

export function randomToken(bytes = 32): string {
	return base64UrlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function sha256(value: string): Promise<string> {
	return base64UrlEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))));
}

/** Compares two strings without stopping at the first difference. */
export function timingSafeEqual(a: string, b: string): boolean {
	const left = encoder.encode(a);
	const right = encoder.encode(b);
	let difference = left.length ^ right.length;

	for (let index = 0; index < left.length; index++) {
		difference |= left[index]! ^ (right[index] ?? 0);
	}

	return difference === 0;
}

/**
 * Encrypts small JSON payloads (AES-256-GCM) so the Worker needs no storage for the state, the
 * authorization code and the refresh token.
 *
 * A sealed value is `<key id>.<iv>.<ciphertext>`. The key ID makes key rotation possible: add a new
 * key in front of `ENCRYPTION_KEYS` and keep the old one as long as refresh tokens sealed with it
 * are in use. The purpose is authenticated, so a state can never be used as a code.
 */
export class Keyring {
	private constructor(
		private readonly currentId: string,
		private readonly keys: Map<string, CryptoKey>,
	) {}

	/**
	 * @param config Comma-separated `id:key` pairs, the key as 32 bytes base64 or base64url. The first pair encrypts.
	 */
	static async fromConfig(config: string): Promise<Keyring> {
		const keys = new Map<string, CryptoKey>();
		let currentId: string | null = null;

		for (const pair of config.split(',')) {
			const [id, value, ...rest] = pair.trim().split(':');

			if (id === undefined || value === undefined || rest.length > 0 || !/^[a-z0-9]+$/.test(id)) {
				throw new Error('ENCRYPTION_KEYS must be comma-separated "id:key" pairs.');
			}

			// Accept plain base64 too, so `openssl rand -base64 32` works as is.
			const raw = base64UrlDecode(value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));

			if (raw.length !== 32) {
				throw new Error(`Encryption key "${id}" must be 32 bytes.`);
			}

			keys.set(id, await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']));
			currentId ??= id;
		}

		if (currentId === null) {
			throw new Error('ENCRYPTION_KEYS is empty.');
		}

		return new Keyring(currentId, keys);
	}

	async seal(purpose: string, payload: object): Promise<string> {
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const ciphertext = await crypto.subtle.encrypt(
			{ name: 'AES-GCM', iv, additionalData: encoder.encode(purpose) },
			this.keys.get(this.currentId)!,
			encoder.encode(JSON.stringify(payload)),
		);

		return [this.currentId, base64UrlEncode(iv), base64UrlEncode(new Uint8Array(ciphertext))].join('.');
	}

	/**
	 * Returns the payload, or null when the value is not ours, was changed or has another purpose.
	 */
	async open(purpose: string, sealed: string): Promise<Record<string, unknown> | null> {
		const [id, iv, ciphertext, ...rest] = sealed.split('.');
		const key = id === undefined ? undefined : this.keys.get(id);

		if (key === undefined || iv === undefined || ciphertext === undefined || rest.length > 0) {
			return null;
		}

		try {
			const plaintext = await crypto.subtle.decrypt(
				{ name: 'AES-GCM', iv: base64UrlDecode(iv), additionalData: encoder.encode(purpose) },
				key,
				base64UrlDecode(ciphertext),
			);
			const payload: unknown = JSON.parse(decoder.decode(plaintext));

			return typeof payload === 'object' && payload !== null && !Array.isArray(payload)
				? (payload as Record<string, unknown>)
				: null;
		} catch {
			return null;
		}
	}
}
