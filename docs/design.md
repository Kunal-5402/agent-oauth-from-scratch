# Design notes

## Design goal

The server must answer two questions reliably:

1. What authority was granted?
2. Which principal is exercising it?

The first implemented grant, `client_credentials`, establishes the signing and
verification path. Later phases retain that path while adding a human root,
delegated actors, sender constraints, and revocation.

## Implemented protocol surface

| Endpoint | Purpose | Current behavior |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | OAuth AS discovery | Publishes issuer, token endpoint, JWKS URI, supported grant, client-auth method, and scopes. |
| `GET /.well-known/jwks.json` | Public-key discovery | Publishes the active P-256 public key as an ES256 JWK. |
| `POST /oauth/token` | Token issuance | Supports URL-encoded `client_credentials` authenticated with `client_secret_post`. |

The server advertises only capabilities it implements. In particular, HTTP
Basic client authentication, authorization code, refresh tokens, token exchange,
and DPoP are not advertised yet.

## Token contract

Access tokens are compact JWTs signed with ES256. Every token contains:

| Claim | Meaning |
|---|---|
| `iss` | Exact authorization-server issuer URL. |
| `sub` | Agent identity associated with the authenticated client. |
| `aud` | Resource-server audience the token is intended for. |
| `iat`, `exp` | Issued-at and expiry timestamps. |
| `jti` | Unique token identifier; it becomes the issuance-record identifier in Phase 1 completion. |
| `client_id` | OAuth client that obtained the token. |
| `scope` | Granted space-delimited scopes, when any were granted. |

The protected header includes `alg: ES256`, `typ: at+jwt`, and a stable `kid`.
The `kid` is the RFC 7638 thumbprint of the public key, so it remains stable
across process restarts.

## Scope behavior

Scopes are capabilities, not labels. The issuer computes:

```text
granted scopes = requested scopes ∩ client allowed scopes
```

Unknown scopes are dropped when at least one requested scope is allowed. A
request for only disallowed scopes fails with `invalid_scope`. A client with no
allowed scopes cannot obtain authority by omitting a policy.

This exact intersection becomes a three-way intersection in the token-exchange
phase: `requested ∩ subject token ∩ next actor policy`.

## Client authentication today

The first slice reads one bootstrap client from environment-injected settings.
That makes local setup small and keeps a real secret out of version control, but
it is not a client registry. Before production use, replace `ClientRegistry`
with a database-backed repository that stores password-hashed client secrets,
supports lifecycle state, and records token issuance before any response is sent.

## Resource-server verification

The independently runnable resource server in `tests/resource_server/` is a
reference consumer. It does not import an AS private key or call an in-process
test helper. It performs these operations through loopback HTTP:

1. Fetch authorization-server metadata from the configured issuer.
2. Fetch and cache the JWKS URI from metadata.
3. Select the JWK only by the token header's `kid`.
4. Verify using a fixed ES256 algorithm allow-list.
5. Require and validate `iss`, `sub`, `aud`, `iat`, `exp`, and `jti`.
6. Enforce endpoint-specific scope requirements after cryptographic validation.

An unknown `kid` triggers one JWKS refresh to allow a future rotated key to
appear. It does not allow an unpublished key.

## Test strategy

The integration tests run three independently constructed components on real
loopback TCP sockets:

```text
OAuth client → Authorization server → Resource server
                     ↑                    │
                     └──── JWKS fetch ────┘
```

This validates network URLs, discovery metadata, form serialization, JWKS
parsing, JWT verification, audience checks, and scope enforcement together.
Pure key-persistence tests remain local because they do not describe a network
interaction.

## Next design changes

- Persist `IssuedToken` rows before returning a token response.
- Add HTTP Basic client authentication and hashed client-secret storage.
- Add authorization code + PKCE for human authorization.
- Add RFC 8693 exchange and a signed nested `act` chain.
- Add depth, audience, scope, and lifetime attenuation rules.
- Add DPoP and then introspection, revocation, and refresh-token reuse detection.
