# Architecture

## Purpose

This repository is a security-focused reference implementation of an OAuth 2.1
authorization server for agentic systems. Its central concern is preserving
verifiable delegated authority as work moves from a human to an orchestrator,
then through sub-agents and tools.

The currently implemented slice is intentionally small: an ES256 signing key,
OAuth authorization-server metadata, JWKS publication, and the
`client_credentials` grant. The design keeps those pieces in the same shape
they will need as authorization code, token exchange, DPoP, and revocation are
added.

## Runtime components

```text
┌─────────────────┐       POST /oauth/token        ┌──────────────────────────┐
│ OAuth client    │ ─────────────────────────────► │ Authorization server     │
│ agent:reporting │ ◄───────────────────────────── │                          │
└────────┬────────┘      ES256 access token        │  ClientRegistry          │
         │                                         │  TokenIssuer             │
         │ GET /.well-known/...                    │  KeyStore                │
         │                                         └────────────┬─────────────┘
         │                                                      │
         │                                             public JWK only
         ▼                                                      ▼
┌─────────────────┐       GET JWKS / verify JWT    ┌──────────────────────────┐
│ Resource server │ ◄───────────────────────────── │ JWKS endpoint            │
│ /reports        │                                │ private key never leaves │
└─────────────────┘                                └──────────────────────────┘
```

The authorization server is the only component that holds the ES256 private
key. OAuth clients receive access tokens; resource servers receive only public
JWKs and never call into the signing code.

## Source layout

| Area | Responsibility |
|---|---|
| `src/crypto/keys.py` | Generate, persist, load, and publish a single P-256 signing key. |
| `src/services/token_issuer.py` | Authenticate the configured client, attenuate scopes, and mint JWTs. |
| `src/api/routes.py` | Parse strict form requests and expose OAuth/JWKS endpoints. |
| `src/main.py` | Construct the deployable application from environment configuration. |
| `tests/oauth_client/` | A real HTTP OAuth client used by integration tests. |
| `tests/resource_server/` | An independent FastAPI resource server and JWKS-backed verifier. |

## Issuance flow

1. The client discovers the token endpoint through
   `/.well-known/oauth-authorization-server`.
2. It submits a URL-encoded `client_credentials` request to `/oauth/token`.
3. The authorization server authenticates the client, resolves its permitted
   scopes, and calculates `requested ∩ allowed`.
4. The server signs a short-lived JWT with ES256 and sets `iss`, `sub`, `aud`,
   `iat`, `exp`, `jti`, `client_id`, and the granted `scope`.
5. The server returns a no-store token response.
6. The resource server discovers the issuer metadata and JWKS, selects the
   published key by `kid`, and verifies the signature, algorithm, token type,
   issuer, audience, expiry, and required claims.
7. The resource endpoint makes its own scope decision after validation.

## Security boundaries and invariants

- The private key is local to the authorization server, saved with restrictive
  owner permissions on POSIX systems, and never appears in JWKS output.
- Resource servers use a fixed `ES256` allow-list. An incoming JWT header can
  select a `kid`; it cannot select the verification algorithm.
- Token endpoint inputs come only from one URL-encoded form body. Duplicate
  security-sensitive parameters are refused; query parameters are ignored.
- An empty client scope allow-list grants no authority. Requested scopes are
  never enlarged during issuance.
- OAuth error responses and token responses are marked `Cache-Control: no-store`.
- The resource server caches JWKS briefly, then performs one forced refresh for
  an unknown `kid` to support future key rotation without accepting unknown keys.

## Current boundaries

This is not yet suitable to protect production data. It does not yet persist
clients or issued tokens in a database, hash client secrets at rest, rotate
keys, revoke tokens, apply rate limits, or provide operational audit trails.
Those gaps are intentional milestones in the roadmap, not claims the current
implementation makes.

See [Design notes](docs/design.md) for endpoint contracts and implementation
decisions, and [Roadmap](roadmap/README.md) for the planned capabilities.
