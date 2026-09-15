# Phase 6 — Introspection, revocation and reuse detection

**The one idea:** you cannot un-issue a signed statement, so taking access back is
always a trade between freshness and a network call. This phase is about making
that trade deliberately, per endpoint, instead of accidentally, everywhere.

## Why it exists

Phase 1 made a bargain and said the price would come due. Here it is.

An operator revokes a credential at 10:00. A token was issued at 09:58 with a
15-minute lifetime. Every service verifying offline sees a valid signature and an
unexpired token, and allows every call until 10:13.

That 13-minute window is the debt. There is no way to reduce it to zero, only ways
to choose its size.

## What to build

### Introspection

- [ ] `POST /oauth2/introspect`, taking `token` and optional `token_type_hint`.
- [ ] The endpoint is **protected**. The caller authenticates.
- [ ] Return `{"active": true, ...}` or `{"active": false}`.
- [ ] An unknown, expired or revoked token all return `active: false`.

### Revocation

- [ ] `POST /oauth2/revoke`.
- [ ] Always return `200`, whether or not the token existed.
- [ ] Decide and document what cascades:

| Revoking | Should also kill |
|---|---|
| An access token | Just that token. It is a leaf |
| A refresh token | Every access token it produced, and the whole rotation family |
| A session | Every token issued from it, including delegated chains |
| An identity | Everything ever issued to it, plus every chain rooted at it |

### Refresh rotation and reuse detection

- [ ] Every use of a refresh token issues a new one and kills the old one.
- [ ] All tokens descended from one login share a `family_id`.
- [ ] A second use of an already-rotated token kills the **entire family**.

Exactly 2 things can produce that second use: an honest client retried after a
network failure, or somebody stole a copy. The server cannot tell which, so it
assumes the worse case.

This is the most elegant idea in the project and it generalises. You rarely detect
an attack. What you can do is arrange the system so that *using* the stolen thing
creates a state that is impossible under honest behaviour, then detect the
impossible state.

### Revoking a delegation tree

- [ ] Record `root_subject` and `task_id` on every token at issuance.
- [ ] Revoke downward from a root.
- [ ] Revoke a single branch, leaving the rest of the task running.

```sql
-- only possible because both columns were recorded at issuance
UPDATE issued_tokens SET revoked_at = now(), reason = 'root_deactivated'
WHERE root_subject = 'user_42' AND revoked_at IS NULL;
```

This is the orphaned authority problem from phase 4, finally answered. Note that
the answer was decided in phase 1, when you chose what to record. You cannot add it
retrospectively.

### Measure it

- [ ] A script that revokes a token, then polls until requests actually fail, and
      prints the number of seconds.

## Done when

```
introspect a live token            -> active: true
introspect a revoked token         -> active: false
introspect a string you invented   -> active: false, NOT an error
introspect without authenticating  -> 401

revoke a token that never existed  -> 200
revoke a refresh token             -> its access tokens stop working too
use a rotated refresh token again  -> the whole family is dead, not just that token

deactivate a root human
  -> every token in the tree, at every depth, stops. measured in seconds
```

## Traps

**Revocation without checking is theatre.** Marking a row revoked achieves nothing
if every resource server verifies offline and never asks. When somebody says a
system supports revocation, the follow-up is always: *what checks, and how often?*
If the answer is "nothing until the token expires", the real revocation time is the
token lifetime, whatever the admin screen says.

**Identical responses are deliberate.** "Never existed" and "revoked yesterday" must
be indistinguishable, and revocation always returns `200`. Different answers turn
both endpoints into an oracle that tells an attacker which of their stolen strings
are real.

**Every layer of caching extends the window, and they add up.** The client library,
the gateway, the service mesh, your own code. The effective window is the **sum**,
and almost nobody measures it. Write the number down where somebody can find it
when they ask why a revocation took a minute.

**Reuse detection has a real cost.** Honest clients do retry, particularly on flaky
mobile networks, and users get logged out for no visible reason. The usual answer is
a short grace period where the immediately previous token is accepted once. That
weakens detection slightly for much less pain. It is a judgement call, not a rule,
so make it consciously and write down which you chose.

**Choose per endpoint, not globally.** The question is not how important an endpoint
feels. It is: *if this ran with a token that should have died 5 minutes ago, how
bad is it?* Harmless read, verify offline. Reversible edit, verify offline with
short lifetimes. Money, deletion, granting access, introspect every time. An agent
making 500 calls cannot introspect on all of them, so introspect at the boundaries
instead: when a task begins, and before any irreversible step.

## Write-up

The measured number. Revoke a token, poll until it stops working, and publish the
seconds. Almost nobody has done this for their own system, and the result is
usually a surprise. It is the most useful thing in the whole repository and it is
about 12 lines of code.
