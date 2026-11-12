# Twinfield Connect

An OAuth proxy for Twinfield, running as a Cloudflare Worker on `connect.twinfield.solvebeam.com`.

To connect an application to Twinfield you need a Twinfield client ID, and to get one you have to pass Twinfield's certification. This proxy lets applications log in through the certified Twinfield client of SolveBeam instead. The client secret stays in the Worker, and Twinfield only needs to know one redirect URL: the proxy itself.

It is built for the [Twinfield PHP SDK](https://php.twinfield.solvebeam.com), but any OAuth 2.0 client works: to an application the proxy looks like an ordinary authorization server.

## How it works

```
Application                 Twinfield Connect                    Twinfield
    │  POST /register  (once)       │                                │
    │──────────────────────────────▶│                                │
    │  GET /authorize               │                                │
    │──────────────────────────────▶│  page: who gets access         │
    │                               │───────────────────────────────▶│  login and consent
    │                               │  GET /?code=…&state=…          │
    │  redirect URI: code, state    │◀───────────────────────────────│
    │◀──────────────────────────────│                                │
    │  POST /token                  │  token request with the secret │
    │──────────────────────────────▶│───────────────────────────────▶│
    │  access token, refresh token  │                                │
    │◀──────────────────────────────│◀───────────────────────────────│
    │  API calls with the access token, directly                     │
    │───────────────────────────────────────────────────────────────▶│
```

1. An application registers once and gets its own client ID and secret for the proxy.
2. It sends the user to `/authorize`. The proxy shows which application and which host get access, then sends the user to Twinfield.
3. Twinfield sends the user back to the proxy, and the proxy passes them on to the redirect URI of the application.
4. The application exchanges the code at `/token`, and refreshes the access token there later.

API calls never go through the proxy: the application calls Twinfield directly with the access token.

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /register` | Dynamic client registration ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)). |
| `GET /authorize` | Authorization endpoint. PKCE with `S256` is required. |
| `GET /` | The home page. Twinfield also redirects here, with `code` and `state`. |
| `POST /token` | Token endpoint for the `authorization_code` and `refresh_token` grants. |
| `GET /.well-known/oauth-authorization-server` | Server metadata ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)). |

### Register

```sh
curl https://connect.twinfield.solvebeam.com/register \
  -H 'Content-Type: application/json' \
  -d '{"client_name": "My application", "redirect_uris": ["https://example.com/twinfield/callback"]}'
```

The response has the `client_id` and the `client_secret`. Store both; the secret is not shown again.

- `client_name`: 1 to 100 characters. Users see it on the page before they go to Twinfield.
- `redirect_uris`: 1 to 10 URLs. `https`, or `http` on `localhost`, `127.0.0.1` or `[::1]` for development. No fragment.

### Authorize

Send the user to `/authorize` with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge` and `code_challenge_method=S256`. A `nonce` is passed on to Twinfield.

The `scope` is passed on to Twinfield unchanged, see the [Twinfield scopes](https://php.twinfield.solvebeam.com/guides/oauth2/). Request `offline_access` to get a refresh token.

The user comes back on the redirect URI with `code` and `state`, or with `error` and `error_description`. When the client ID or the redirect URI is unknown, the proxy shows an error page and does not redirect.

### Token

```sh
curl https://connect.twinfield.solvebeam.com/token \
  -d grant_type=authorization_code \
  -d code=… -d redirect_uri=… -d code_verifier=… \
  -d client_id=… -d client_secret=…
```

Send the client ID and secret in the body or as HTTP Basic authentication. The response is the token response of Twinfield (`access_token`, `expires_in`, `id_token`, …) with one difference: the `refresh_token` is one of the proxy. To refresh:

```sh
curl https://connect.twinfield.solvebeam.com/token \
  -d grant_type=refresh_token -d refresh_token=… \
  -d client_id=… -d client_secret=…
```

Like Twinfield, the proxy only returns a new refresh token when the old one is replaced. Keep the one you have when the response has none.

## What the proxy sees and stores

- It stores the registered clients: name, redirect URIs, a hash of the secret and the registration date.
- It stores no tokens, no codes and nothing about users. The state, the authorization code and the refresh token are encrypted values that the application carries itself.
- The refresh token an application gets is the Twinfield refresh token, encrypted and bound to that application. Only the proxy can use it, and only for the application it was given to.
- Access tokens pass through the proxy when they are issued and refreshed. The proxy does not use them or log them.
- It never sees bookkeeping data.

An application that outgrows the proxy can switch to its own Twinfield client ID. Its users then have to log in again, because a refresh token belongs to the client it was issued to.

## Running your own

You need a Twinfield client ID with `https://<your host>/` as redirect URL, including the trailing slash.

```sh
npm install
npx wrangler kv namespace create twinfield-connect-clients   # put the ID in wrangler.jsonc
npx wrangler secret put TWINFIELD_CLIENT_ID
npx wrangler secret put TWINFIELD_CLIENT_SECRET
npx wrangler secret put ENCRYPTION_KEYS
npm run deploy
```

Change the route in `wrangler.jsonc` to your own host.

`ENCRYPTION_KEYS` is a comma-separated list of `id:key` pairs, such as `k1:…`. A key is 32 random bytes in base64:

```sh
openssl rand -base64 32
```

The first key encrypts, all keys decrypt. To rotate, put a new pair in front (`k2:…,k1:…`). Refresh tokens encrypted with a key stop working when you remove it, so keep old keys as long as applications use them.

To block an application, delete its client. It can no longer log in or refresh:

```sh
npx wrangler kv key delete --binding CLIENTS "client:<client_id>" --remote
```

### Development

```sh
cp .dev.vars.example .dev.vars   # fill in the values
npm run dev                      # http://localhost:8787
npm run check                    # type check
```

For a real login during development, the Twinfield client needs `http://localhost:8787/` as redirect URL.

## License

MIT
