# Phase 4 — The five shrink rules

**The one idea:** a delegation chain is only worth having if it cannot grow. Five
rules do almost all of that work, and phase 3 without them is a working delegation
system with no ceiling on it.

## Why it exists

Phase 3 made delegation possible. On its own that is not an improvement, it is a
new way to spread authority. These rules are what turn it into a reduction.

Four of them shrink something. The fifth is about whether any of it can be trusted.

## What to build

### Rule 1 — Scope attenuation

New scopes are the intersection of what was requested, what the subject token
holds, and what the actor is allowed to hold.

```python
granted = requested & subject_scopes & actor_ceiling
```

Intersection cannot grow a set. There is no input at all that produces more scopes
than either side already had. Chain several and you get a ratchet that turns one
way.

- [ ] Intersect against all three, in one shared function.
- [ ] Handle empty the way phase 1 does, and for the same reason.

### Rule 2 — Depth capping

- [ ] Increment a `delegation_depth` claim on every exchange.
- [ ] Refuse above a configured maximum.

Without a cap, an agent can spawn an agent that spawns an agent, and the tree grows
until nobody can reason about it and no revocation can catch up. A cap turns an
unbounded tree into something a person can audit.

### Rule 3 — Audience narrowing

- [ ] Each hop produces a token aimed at one downstream service.
- [ ] Refuse to issue a token valid everywhere. Already required in phase 3.

### Rule 4 — Lifetime shrinking

- [ ] The new token must never outlive the token it came from.
- [ ] `new_exp = min(requested_exp, subject_token_exp)`.

This is the rule that gets forgotten, and it is the most interesting one. If a
15-minute token can be exchanged for a 60-minute one, anybody holding a token near
its end can refresh their authority indefinitely without ever going back to the
human. A single approval then lives forever, moving from token to token, and
nothing re-checks it.

Whenever you design a transformation, ask what happens if somebody applies it a
thousand times.

### Rule 5 — The chain must be verifiable, not merely present

- [ ] `act` is only ever written by the authorization server, inside the signature.
- [ ] Nothing downstream can add to it, edit it, or drop an entry.

### Resource-server enforcement

Most teams stop at "verify the token and read the scopes". A chain lets you do
better, and the extra checks are cheap:

```python
def enforce(claims, *, max_depth, require_human_root, known_actors):
    c = chain(claims)
    holder, root, depth = c[0], c[-1], len(c) - 1

    if depth > max_depth:
        return "403 too many hops"
    if require_human_root and not root.startswith("user_"):
        return "403 no human at the root"
    if holder not in known_actors:
        return "403 unknown immediate actor"
    return "200 allow"
```

- [ ] Ship this as a small library alongside the server, with a worked example.
- [ ] Log the whole chain and the `task_id`, never only the subject.

## Done when

```
exchange requesting a scope the subject token does not hold
  -> that scope is absent from the result. not an error, just gone

exchange at depth == max_depth
  -> 400. the counter is checked before issuance, not after

exchange requesting a longer lifetime than the subject token has
  -> granted exp equals the subject token's exp, not the requested one

subject token with 30 seconds left, exchanged
  -> new token has at most 30 seconds. never more

the same token at a read endpoint (max_depth 3) and a write endpoint (max_depth 1)
  -> 200 and 403 respectively, with identical scopes
```

That last test is the point of the whole phase. Same token, same scopes, two
answers, because the question is not "does this actor have permission" but "is
*this actor*, acting for this human, through *this chain*, permitted to do this".

## Traps

**Rule 4 is the one that gets skipped.** It feels like a detail and it is the
difference between a temporary approval and a permanent credential built out of one.

**"The user has permission" is not a sufficient reason to allow an action.** A
system that only asks that question is exactly where the confused deputy problem
lives.

**Orphaned authority.** The human is suspended at 10:00 and the chain keeps working,
because nothing goes back and re-checks the root. Most systems today would say the
task continues. You should be able to answer this for your own server, and "we
never thought about it" is a real answer people give. Phase 6 is where it gets
fixed properly, but decide now what you record at issuance, because you cannot add
it retrospectively.

## Write-up

The two-endpoint test. One token, identical scopes, allowed at the read endpoint
and refused at the write endpoint, purely because of how many hops from a human it
is. Most people have never seen authorization work that way.
