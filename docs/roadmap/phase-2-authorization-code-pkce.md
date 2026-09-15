# Phase 2 — Authorization code with PKCE

**The one idea:** the client invents a fresh secret, sends only its hash through the
browser, and sends the secret itself on the back channel. A thief who reads the
browser gets something they cannot spend.

## Why it exists

The authorization code travels through the most hostile place in the whole flow.
It sits in a URL, and URLs end up in browsing history, in the `Referer` header of
the next request, in proxy logs, in screen recordings and in terminal scrollback.

Originally the client secret on the back channel made a stolen code useless. Then
mobile apps arrived, and a mobile app cannot keep a secret: anybody can download it
and read the string out. So the code alone became the credential, and any app that
registered the same custom URI scheme could take it.

PKCE closes that. And it is now required for **every** client, including
confidential ones, because it also stops authorization code injection, which a
client secret does not.

## What to build

### The authorization endpoint

- [ ] `GET /oauth2/authorize` with `response_type=code`.
- [ ] Required: `client_id`, `redirect_uri`, `code_challenge`,
      `code_challenge_method`, `state`.
- [ ] Refuse if `code_challenge` is absent. Refuse if the method is not exactly
      `S256`. There is no fallback path and no configuration flag to add one.
- [ ] A consent screen. It can be ugly. It must name the specific thing being
      approved rather than a vague category.

### Redirect URI matching

- [ ] Exact string match against the registered value.
- [ ] The loopback exception from RFC 8252: for `127.0.0.1`, `localhost` and `::1`,
      the **port floats** and everything else must match exactly.

### The code itself

- [ ] Short lifetime. 60 seconds is generous, 5 minutes is the ceiling.
- [ ] Single use, enforced by one atomic write, not a read-then-write.

```sql
INSERT INTO consumed_codes (jti) VALUES (?) ON CONFLICT DO NOTHING
```

The database decides the winner of a race, not your application code.

### The exchange

- [ ] `grant_type=authorization_code` with `code_verifier` on the token endpoint.
- [ ] Verify `base64url(sha256(verifier)) == stored challenge`.
- [ ] Check `redirect_uri` matches the one used at the authorization endpoint.
- [ ] On a second use of a code, revoke **everything that code produced**.

## Done when

```
authorize without code_challenge          -> 400. no code is ever created
authorize with code_challenge_method=plain -> 400. S256 only
exchange with the wrong verifier           -> 400 invalid_grant
  then exchange the SAME code with the right verifier -> 200
  (this is the ordering test. see the trap)
exchange the same code twice, both correct -> second is 400, and the token from
                                              the first is now revoked
redirect_uri http://127.0.0.1:51792/cb  against registered http://127.0.0.1/cb
                                           -> accepted, port floats
redirect_uri http://127.0.0.1.evil.com/cb  -> rejected
```

## Traps

**Order the checks so a thief cannot burn a code.** Verify PKCE **first**, then mark
the code consumed. Get it the wrong way round and an attacker who stole a code they
cannot possibly redeem can still send a wrong verifier and destroy it. The real
user's login then fails, forever, and the attacker gained a denial of service out
of a credential that was useless to them.

Generalise it: **any check with a side effect goes after every check without one.**
Single-use markers, rate-limit counters, lockout counters after failed passwords.
All of them can be weaponised by somebody who cannot authenticate but can still
make you record something.

**Hostname matching by prefix or suffix is always a bug.** `127.0.0.1.evil.com` is
an ordinary internet hostname that happens to start with familiar characters. Match
the host exactly, after parsing, never with `startswith`.

**"PKCE is supported" is not the property you want.** The property is *a code
without a challenge cannot exist*. Enforce it at the authorization endpoint, again
where the code is created, and again at the token endpoint. An attacker who can
modify the request will try to remove the challenge entirely, and a server that
treats it as optional hands them the old vulnerability back.

**Do not use a constant-time compare for the PKCE check.** It looks careful and it
is pointless. The challenge already travelled through a plain URL, so there is no
secret to leak through timing. Knowing why a control is unnecessary is worth more
than adding it out of habit.

## Write-up

The ordering bug. "I put my single-use marker one line too early and turned a
useless stolen code into a working denial of service." It is concrete, it is a
mistake anybody could make, and the lesson generalises well beyond OAuth.
