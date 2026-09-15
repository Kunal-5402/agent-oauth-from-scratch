# Phase 5 — DPoP sender-constraining

**The one idea:** tie the token to a key the client never transmits, so a copied
token is inert.

## Why it exists

Everything so far issues **bearer** tokens. Bearer is a term borrowed from finance
and it means exactly what it says: whoever bears it, owns it. Copy the
`Authorization` header out of a log and send it from anywhere in the world, and it
works.

Tokens leak in dull ways, not clever ones. A logging library records request
headers. A service mesh writes traces to disk. Somebody pastes a failing request
into a chat channel to ask for help. A crash dump, a backup, a screenshot.

Short lifetimes do not fix this. They **bound** it. A 15-minute token in an
attacker's hands is 15 minutes of being you, and whatever leaked the first one is
usually still leaking.

## What to build

### The proof

A DPoP proof is a small JWT that sits **beside** the access token, not instead of
it. One per request.

```
header:  { "typ": "dpop+jwt", "alg": "ES256", "jwk": <the public key, inline> }
claims:  { "jti": <unique>, "htm": <method>, "htu": <url>, "iat": <now>,
           "ath": <sha256 of the access token>, "nonce": <if the server asked> }
```

- [ ] Verify the proof signature using the key inside its own header.
- [ ] Compute the JWK thumbprint of that key.
- [ ] Compare it against `cnf.jkt` inside the signed access token.

That last comparison is the whole mechanism. The inline `jwk` is trustworthy only
because its fingerprint is checked against something the authorization server
signed.

### At the token endpoint

- [ ] Accept a DPoP proof, fingerprint the key, and put `cnf.jkt` in the token.
- [ ] Return `"token_type": "DPoP"`, not `"Bearer"`.
- [ ] Bind refresh tokens to the same key for public clients.

### At the resource server

- [ ] Accept `Authorization: DPoP <token>`, and refuse the `Bearer` scheme for a
      token that carries `cnf`.
- [ ] Check `htm` and `htu` match the actual request.
- [ ] Check `iat` is recent, within a few seconds.
- [ ] Check `jti` has not been seen. This needs a replay cache.
- [ ] Check `ath` matches the presented access token.

### The server-chosen nonce

- [ ] Return `401` with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a
      `DPoP-Nonce` header.
- [ ] Accept the retry carrying that nonce.

Because the server invented the value, it knows exactly how old any proof can be.
The client picks its own `iat`, and a wrong clock or a determined attacker makes
that untrustworthy.

## Done when

```
request with a valid token and no proof            -> 401
proof signed by a different key than cnf.jkt       -> 401
proof with htm=GET replayed against DELETE         -> 401
the same proof sent twice                          -> second is 401
proof with iat 10 minutes old                      -> 401
valid token presented as "Bearer" when it has cnf  -> 401
first request when nonce is required               -> 401 + DPoP-Nonce
retry carrying that nonce                          -> 200
```

Each of those maps to exactly one field. If you cannot predict which error you will
get, you have not understood the mechanism yet.

## Traps

**Every field pins the proof along one axis.** Which key, which endpoint, which
moment, which single use, which token. A proof is only as strong as the number of
axes it is pinned along. When you meet a home-grown version of this pattern, count
the axes: the missing ones are where the bugs are.

**The scheme change from `Bearer` to `DPoP` is not cosmetic.** It stops a resource
server that does not understand DPoP from cheerfully accepting the token as an
ordinary bearer credential and skipping the entire check.

**Be honest about what this buys.** DPoP raises the cost of an attack from *copying
a string* to *running code on the victim's machine*. That is a very large increase.
It is not prevention. If malicious code is executing where the key lives, it can
ask the key to sign whatever it likes. Anybody who says sender-constraining makes
token theft impossible has skipped this paragraph.

**The replay cache is real infrastructure.** In a cluster it has to be shared, or
the acceptance window has to be handled per node. Decide which, and write the
number down.

**Anything that rewrites the request URL breaks `htu`.** Gateways and proxies need
care. A control that fails when a proxy rewrites a path is a control an
infrastructure team will quietly switch off at 2am during an outage. Add a metric
that shows when constraining is being skipped, so switching it off is visible.

## Write-up

The 5 fields as 5 axes. Take the proof apart, remove one field at a time, and show
which specific attack each removal lets back in. It is a good post because the
reader can predict the answers before you give them.
