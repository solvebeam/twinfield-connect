import { type Client, ClientStore, RegistrationError, parseRegistration } from './clients';
import { Keyring, sha256, timingSafeEqual } from './crypto';
import { consentPage, errorPage, homePage } from './pages';

export interface Env {
	CLIENTS: KVNamespace;
	TWINFIELD_CLIENT_ID: string;
	TWINFIELD_CLIENT_SECRET: string;
	ENCRYPTION_KEYS: string;
	REGISTER_LIMITER?: RateLimit;
	/** Only for `wrangler dev`, where the request URL has the host of the route instead of localhost. */
	PUBLIC_URL?: string;
}

const TWINFIELD_AUTHORIZE_URL = 'https://login.twinfield.com/auth/authentication/connect/authorize';
const TWINFIELD_TOKEN_URL = 'https://login.twinfield.com/auth/authentication/connect/token';

/** Seconds the user has to log in at Twinfield, including two-factor authentication. */
const STATE_LIFETIME = 30 * 60;

/** Twinfield's own authorization code is valid for 5 minutes. */
const CODE_LIFETIME = 5 * 60;

const keyrings = new Map<string, Promise<Keyring>>();

function keyring(env: Env): Promise<Keyring> {
	let ring = keyrings.get(env.ENCRYPTION_KEYS);

	if (ring === undefined) {
		ring = Keyring.fromConfig(env.ENCRYPTION_KEYS);
		keyrings.set(env.ENCRYPTION_KEYS, ring);
	}

	return ring;
}

function publicOrigin(url: URL, env: Env): string {
	return env.PUBLIC_URL === undefined || env.PUBLIC_URL === '' ? url.origin : new URL(env.PUBLIC_URL).origin;
}

function now(): number {
	return Math.floor(Date.now() / 1000);
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'Content-Type': 'application/json; charset=utf-8',
			'Cache-Control': 'no-store',
			Pragma: 'no-cache',
			...headers,
		},
	});
}

function oauthError(error: string, description: string, status = 400, headers: Record<string, string> = {}): Response {
	return json({ error, error_description: description }, status, headers);
}

function redirect(location: string): Response {
	return new Response(null, { status: 302, headers: { Location: location, 'Cache-Control': 'no-store' } });
}

function redirectWith(redirectUri: string, parameters: Record<string, string | null>): Response {
	const url = new URL(redirectUri);

	for (const [name, value] of Object.entries(parameters)) {
		if (value !== null) {
			url.searchParams.set(name, value);
		}
	}

	return redirect(url.toString());
}

function metadata(origin: string): Response {
	return json({
		issuer: origin,
		authorization_endpoint: `${origin}/authorize`,
		token_endpoint: `${origin}/token`,
		registration_endpoint: `${origin}/register`,
		response_types_supported: ['code'],
		grant_types_supported: ['authorization_code', 'refresh_token'],
		code_challenge_methods_supported: ['S256'],
		token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
	});
}

async function register(request: Request, env: Env): Promise<Response> {
	if (env.REGISTER_LIMITER !== undefined) {
		const { success } = await env.REGISTER_LIMITER.limit({
			key: request.headers.get('CF-Connecting-IP') ?? 'unknown',
		});

		if (!success) {
			return oauthError('rate_limit_exceeded', 'Too many registrations. Try again in a minute.', 429);
		}
	}

	let body: unknown;

	try {
		body = await request.json();
	} catch {
		return oauthError('invalid_client_metadata', 'The request body must be JSON.');
	}

	try {
		const { client, secret } = await new ClientStore(env.CLIENTS).create(parseRegistration(body));

		return json(
			{
				client_id: client.id,
				client_secret: secret,
				client_id_issued_at: Math.floor(Date.parse(client.createdAt) / 1000),
				client_secret_expires_at: 0,
				client_name: client.name,
				redirect_uris: client.redirectUris,
				grant_types: ['authorization_code', 'refresh_token'],
				response_types: ['code'],
				token_endpoint_auth_method: 'client_secret_post',
			},
			201,
		);
	} catch (error) {
		if (error instanceof RegistrationError) {
			return oauthError(error.code, error.message);
		}

		throw error;
	}
}

/**
 * Step 1: the application sends the user here. Shows who gets access and links to Twinfield, with
 * everything needed for the way back sealed in the state.
 */
async function authorize(url: URL, env: Env): Promise<Response> {
	const parameters = url.searchParams;
	const client = await new ClientStore(env.CLIENTS).find(parameters.get('client_id') ?? '');

	// Without a known client and redirect URI there is nowhere safe to send an error to.
	if (client === null) {
		return errorPage('This application is not registered (unknown "client_id").');
	}

	const redirectUri = parameters.get('redirect_uri') ?? '';
	const redirectIndex = client.redirectUris.indexOf(redirectUri);

	if (redirectIndex === -1) {
		return errorPage('The "redirect_uri" is not registered for this application.');
	}

	const state = parameters.get('state');
	const fail = (error: string, description: string): Response =>
		redirectWith(redirectUri, { error, error_description: description, state });

	if (state !== null && state.length > 512) {
		return redirectWith(redirectUri, {
			error: 'invalid_request',
			error_description: '"state" is longer than 512 characters.',
		});
	}

	if (parameters.get('response_type') !== 'code') {
		return fail('unsupported_response_type', 'Only "response_type=code" is supported.');
	}

	const scope = parameters.get('scope') ?? '';

	if (scope.trim() === '' || scope.length > 1000) {
		return fail('invalid_scope', '"scope" is required.');
	}

	const challenge = parameters.get('code_challenge') ?? '';

	if (parameters.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
		return fail('invalid_request', 'PKCE is required: send "code_challenge" with "code_challenge_method=S256".');
	}

	const nonce = parameters.get('nonce');

	if (nonce !== null && nonce.length > 255) {
		return fail('invalid_request', '"nonce" is longer than 255 characters.');
	}

	// Short keys and the index of the redirect URI keep the state Twinfield has to carry small.
	const sealedState = await (await keyring(env)).seal('state', {
		c: client.id,
		r: redirectIndex,
		s: state,
		h: challenge,
		e: now() + STATE_LIFETIME,
	});

	const twinfieldUrl = new URL(TWINFIELD_AUTHORIZE_URL);
	twinfieldUrl.searchParams.set('client_id', env.TWINFIELD_CLIENT_ID);
	twinfieldUrl.searchParams.set('response_type', 'code');
	twinfieldUrl.searchParams.set('scope', scope);
	twinfieldUrl.searchParams.set('redirect_uri', `${publicOrigin(url, env)}/`);
	twinfieldUrl.searchParams.set('state', sealedState);

	if (nonce !== null) {
		twinfieldUrl.searchParams.set('nonce', nonce);
	}

	return consentPage(client.name, redirectUri, twinfieldUrl.toString());
}

/**
 * Step 2: Twinfield sends the user back here. Passes the user on to the application with a code of
 * our own, which wraps Twinfield's code and binds it to the client and its PKCE challenge.
 */
async function callback(url: URL, env: Env): Promise<Response> {
	const parameters = url.searchParams;
	const ring = await keyring(env);
	const state = await ring.open('state', parameters.get('state') ?? '');

	if (
		state === null ||
		typeof state.c !== 'string' ||
		typeof state.r !== 'number' ||
		typeof state.h !== 'string' ||
		typeof state.e !== 'number' ||
		(state.s !== null && typeof state.s !== 'string')
	) {
		return errorPage('This login does not belong to a connection that was started here.');
	}

	if (state.e < now()) {
		return errorPage('Logging in took too long.');
	}

	const client = await new ClientStore(env.CLIENTS).find(state.c);
	const redirectUri = client?.redirectUris[state.r];

	if (redirectUri === undefined) {
		return errorPage('This application is no longer registered.');
	}

	const error = parameters.get('error');

	if (error !== null) {
		return redirectWith(redirectUri, {
			error,
			error_description: parameters.get('error_description'),
			state: state.s,
		});
	}

	const twinfieldCode = parameters.get('code');

	if (twinfieldCode === null || twinfieldCode === '') {
		return redirectWith(redirectUri, {
			error: 'server_error',
			error_description: 'Twinfield did not return an authorization code.',
			state: state.s,
		});
	}

	const code = await ring.seal('code', {
		t: twinfieldCode,
		c: state.c,
		r: state.r,
		h: state.h,
		e: now() + CODE_LIFETIME,
	});

	return redirectWith(redirectUri, { code, state: state.s });
}

/** Client credentials from the body (`client_secret_post`) or the Authorization header (`client_secret_basic`). */
function clientCredentials(request: Request, form: URLSearchParams): { id: string; secret: string } | null {
	const header = request.headers.get('Authorization');

	if (header !== null && /^Basic /i.test(header)) {
		try {
			const [id, ...secret] = atob(header.slice(6).trim()).split(':');

			if (id === undefined || secret.length === 0) {
				return null;
			}

			return { id: decodeURIComponent(id), secret: decodeURIComponent(secret.join(':')) };
		} catch {
			return null;
		}
	}

	const id = form.get('client_id');
	const secret = form.get('client_secret');

	return id === null || secret === null ? null : { id, secret };
}

/**
 * Asks Twinfield for tokens with the real client secret and returns them with the refresh token
 * sealed for this client, so the Twinfield refresh token never leaves the Worker.
 */
async function requestTokens(env: Env, client: Client, grant: Record<string, string>): Promise<Response> {
	const response = await fetch(TWINFIELD_TOKEN_URL, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
		body: new URLSearchParams({
			...grant,
			client_id: env.TWINFIELD_CLIENT_ID,
			client_secret: env.TWINFIELD_CLIENT_SECRET,
		}),
	});

	let data: unknown;

	try {
		data = await response.json();
	} catch {
		data = null;
	}

	const tokens = typeof data === 'object' && data !== null && !Array.isArray(data) ? (data as Record<string, unknown>) : null;

	if (!response.ok) {
		const error = typeof tokens?.error === 'string' ? tokens.error : null;

		// A rejected grant is the client's problem; anything else (such as our own credentials) is ours.
		if (response.status === 400 && error !== null && error !== 'invalid_client' && error !== 'unauthorized_client') {
			return oauthError(
				error,
				typeof tokens?.error_description === 'string' ? tokens.error_description : 'Twinfield rejected the request.',
			);
		}

		console.error('Twinfield token request failed', response.status, error);

		return oauthError('server_error', 'The token request to Twinfield failed.', 502);
	}

	if (tokens === null || typeof tokens.access_token !== 'string') {
		console.error('Twinfield token response without an access token');

		return oauthError('server_error', 'Twinfield returned an unexpected token response.', 502);
	}

	const result: Record<string, unknown> = { ...tokens };

	// Twinfield leaves the refresh token out when the old one stays valid, or without `offline_access`.
	if (typeof tokens.refresh_token === 'string') {
		result.refresh_token = await (await keyring(env)).seal('refresh', { t: tokens.refresh_token, c: client.id });
	} else {
		delete result.refresh_token;
	}

	return json(result);
}

/** Step 3: the application exchanges our code for tokens, and later refreshes them. */
async function token(request: Request, url: URL, env: Env): Promise<Response> {
	if (!(request.headers.get('Content-Type') ?? '').toLowerCase().startsWith('application/x-www-form-urlencoded')) {
		return oauthError('invalid_request', 'The request body must be "application/x-www-form-urlencoded".');
	}

	const form = new URLSearchParams(await request.text());
	const credentials = clientCredentials(request, form);
	const client =
		credentials === null ? null : await new ClientStore(env.CLIENTS).authenticate(credentials.id, credentials.secret);

	if (client === null) {
		return oauthError('invalid_client', 'Unknown client or wrong client secret.', 401, {
			'WWW-Authenticate': 'Basic realm="Twinfield Connect"',
		});
	}

	const ring = await keyring(env);
	const grantType = form.get('grant_type');

	if (grantType === 'authorization_code') {
		const code = await ring.open('code', form.get('code') ?? '');

		if (
			code === null ||
			typeof code.t !== 'string' ||
			typeof code.r !== 'number' ||
			typeof code.h !== 'string' ||
			typeof code.e !== 'number' ||
			code.c !== client.id ||
			code.e < now()
		) {
			return oauthError('invalid_grant', 'The authorization code is invalid or expired.');
		}

		if (form.get('redirect_uri') !== client.redirectUris[code.r]) {
			return oauthError('invalid_grant', '"redirect_uri" differs from the one in the authorization request.');
		}

		const verifier = form.get('code_verifier') ?? '';

		if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || !timingSafeEqual(await sha256(verifier), code.h)) {
			return oauthError('invalid_grant', 'The PKCE "code_verifier" does not match.');
		}

		return requestTokens(env, client, {
			grant_type: 'authorization_code',
			code: code.t,
			redirect_uri: `${publicOrigin(url, env)}/`,
		});
	}

	if (grantType === 'refresh_token') {
		const refreshToken = await ring.open('refresh', form.get('refresh_token') ?? '');

		if (refreshToken === null || typeof refreshToken.t !== 'string' || refreshToken.c !== client.id) {
			return oauthError('invalid_grant', 'The refresh token is invalid.');
		}

		return requestTokens(env, client, { grant_type: 'refresh_token', refresh_token: refreshToken.t });
	}

	return oauthError('unsupported_grant_type', 'Use "authorization_code" or "refresh_token".');
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		const route = `${request.method} ${url.pathname}`;

		try {
			switch (route) {
				case 'GET /':
					// Twinfield redirects to the root; without its parameters this is the home page.
					return ['state', 'code', 'error'].some((name) => url.searchParams.has(name))
						? await callback(url, env)
						: homePage();
				case 'GET /.well-known/oauth-authorization-server':
					return metadata(publicOrigin(url, env));
				case 'POST /register':
					return await register(request, env);
				case 'GET /authorize':
					return await authorize(url, env);
				case 'POST /token':
					return await token(request, url, env);
			}
		} catch (error) {
			console.error('Unhandled error', route, error instanceof Error ? error.message : error);

			return oauthError('server_error', 'Something went wrong.', 500);
		}

		return oauthError('not_found', 'No such endpoint.', 404);
	},
} satisfies ExportedHandler<Env>;
