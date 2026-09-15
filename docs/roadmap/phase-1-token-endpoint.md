# Phase 1 — The token endpoint and the signing core

**The one idea:** a token is a decision somebody already made, compressed into a
string that anybody holding the public key can check without asking.

## Why it exists

The expensive work of an identity system is authenticating a caller and checking
policy. It involves a database, and it takes real time. You cannot afford it on
every API call.

So you do it **once**, compress the result into a signed string, and every later
call verifies that string in microseconds. Everything else in this repository is
built on top of that trade, including its cost: a signed statement cannot be
un-issued, which is what phase 6 is about.

## What to build

### The signing core

- [ ] Generate an EC P-256 key pair on first run. Write it under `keys/`, which is
      already in `.gitignore`.
- [ ] Give every key a `kid`. This is 3 characters of JSON and it is the reason
      key rotation is possible at all.
- [ ] `GET /.well-known/jwks.json` publishing the **public** half only.
- [ ] `GET /.well-known/oauth-authorization-server` describing the server.
- [ ] A `mint(claims)` helper that sets `iss`, `iat`, `exp`, `jti` and puts `kid`
      and `alg` in the header.

### The universal pipeline

Every grant type in this server runs the same 5 steps. Only step 1 differs. Build
it as shared code from the first day, because the alternative is that grant number
4 quietly skips a check and nobody notices for a year.

1. **Authenticate the caller.** This step *is* the grant type.
2. **Resolve the identity** behind the caller.
3. **Check the identity is usable.** Active, not expired, not suspended.
4. **Resolve the policy.** This is the authority ceiling.
5. **Attenuate the scopes.** Requested AND allowed. Never more.

Then one shared issuing path. One chokepoint, one place to audit.

### The `client_credentials` grant

- [ ] `POST /oauth2/token` with `grant_type=client_credentials`.
- [ ] Client authentication by HTTP Basic, and by credentials in the body.
- [ ] Strict scope intersection: `granted = requested & allowed`.
- [ ] `Cache-Control: no-store` on every token response.
- [ ] Standard error bodies: `invalid_client`, `invalid_request`,
      `unsupported_grant_type`, `invalid_scope`.

## Done when

```
POST /oauth2/token, valid client, scope=finance:read
  -> 200, a token whose signature verifies against the published JWKS

POST /oauth2/token, valid client, scope="finance:read admin:*"
  -> 200, scope is finance:read only. The extra scope is dropped, not an error

POST /oauth2/token, wrong secret            -> 401 invalid_client
POST /oauth2/token, grant_type=magic_beans  -> 400 unsupported_grant_type
POST /oauth2/token, client registered with zero scopes, asks for everything
  -> refused. NOT "everything granted". See the trap below

GET /.well-known/jwks.json
  -> the public key only. Grep the response for "d" and find nothing
```

## Traps

**The empty allow-list that grants everything.** This is the most valuable thing in
the phase, and it is not in any specification.

A reasonable implementation reads like this:

```python
def attenuate(requested, allowed):
    if not allowed:          # "no restriction configured"
        return requested     # <- the landmine
    return requested & allowed
```

Line 2 treats empty as *no opinion*. But a client deliberately registered with zero
scopes means *deliberately powerless*. Same value in the database, opposite
intention.

Most grants survive this because they have a second ceiling underneath, such as a
user's own policy. **`client_credentials` has no second ceiling.** No human, no
delegation chain. The client's registration is the only limit, so empty must mean
zero. Refuse before the shared intersection is ever called.

Ask this of every authorization path you write: *if every optional check here is
empty, what does the caller get?* If the answer is "everything", you have found a
bug.

**Never read `alg` from the incoming token to decide how to verify it.** Keep an
allow-list of permitted algorithms and exclude every symmetric one, so algorithm
confusion is impossible rather than merely mitigated.

**Do not merge parameter sources.** Read the form body or the query string, never a
combined view. A merged view lets a caller send 2 values for one parameter and hope
you read the wrong one.

**Record what you issued before you respond.** If you respond first and record
afterwards, a crash produces a live token nobody knows about, and phase 6 cannot
revoke what it cannot find.

## Write-up

The empty allow-list bug. It is a complete authorization bypass produced by no
error in any single function, only by 2 layers disagreeing about what empty means.
That is a better story than "I built a token endpoint".
