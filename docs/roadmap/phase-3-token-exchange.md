# Phase 3 — Token exchange, RFC 8693

**The one idea:** an agent should not wear the user's identity. It should carry it,
in a claim that names both of them and cannot be edited by anybody downstream.

This is the phase the whole repository exists for.

## Why it exists

Impersonation and delegation produce the same permission check and completely
different mornings.

```jsonc
// impersonation. the agent IS the user
{ "sub": "user_42", "scope": "finance:read" }

// delegation. the agent is itself, acting for the user
{ "sub": "reporting-service",
  "act": { "sub": "user_42" },
  "scope": "finance:read" }
```

Impersonation destroys information that can never be recovered afterwards. No
amount of logging bolted on later reconstructs it, because it was thrown away at
the moment the token was issued. Delegation keeps it, and you can always choose to
ignore what you kept.

## What to build

- [ ] `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` on the existing
      token endpoint. It is one more door into the same room.
- [ ] Accept `subject_token` and `subject_token_type`.
- [ ] Accept `actor_token` and `actor_token_type`.
- [ ] Require `audience`. See the trap.
- [ ] Verify **both** tokens independently before anything else happens.
- [ ] Build the new `act` claim by nesting the subject token's own identity, and
      its `act` if it had one.
- [ ] Return `issued_token_type` in the response.
- [ ] Support `may_act` on a subject token: a statement made in advance about who
      is permitted to act for this subject.
- [ ] Propagate a `task_id`, set once at the root of a tree and copied unchanged
      into every derived token.

### The sentence to memorise

> The **subject token** carries the authority.
> The **actor token** carries the identity of whoever is about to hold it.

The actor token grants nothing at all. It is proof of who is asking. Every scope in
the result comes from the subject token, and the actor's own policy can only reduce
what passes through.

### Reading a chain

```python
def chain(claims):
    """Outermost first: who holds the token, then who authorised them."""
    out = [claims["sub"]]
    node = claims.get("act")
    while node:
        out.append(node["sub"])
        node = node.get("act")
    return out

# ['sql-tool-agent', 'orchestrator-agent', 'user_42']
# "sql-tool-agent acting for orchestrator-agent acting for user_42"
```

## Done when

```
exchange with a valid subject and actor token
  -> 200, and sub is the ACTOR, act names the previous subject

exchange twice in sequence
  -> act nests 2 deep, innermost entry is still the original human

subject token with may_act naming somebody else
  -> 400. the named actor is the only one permitted

exchange with an invalid actor token signature
  -> 400, and nothing is issued. both tokens verify independently

exchange with no audience parameter
  -> 400. see the trap

chain(claims)[-1] is the original human for any depth
```

## Traps

**The nesting reads backwards from how everybody expects.** The **outermost** `sub`
is whoever holds the token right now. The **innermost** entry is the original human.
People expect the most important thing on the outside and get this wrong on first
sight, including in code review. Write the `chain()` helper once, use it everywhere,
and never walk the structure by hand.

**Refuse to issue a token with no audience.** A token that works everywhere is a
token whose theft costs you everything. Making `audience` required is a 1-line
decision that prevents a category of incident, and the specification permits you to
demand it.

**Both tokens must be verified independently, before any policy runs.** It is
tempting to verify the subject token and treat the actor token as a hint, because
the actor token grants nothing. Do not. It decides who the new token names, and an
unverified actor token means anybody can be named.

**Derive the tenant from verified claims only.** If a caller can send a header or a
body field saying which account it belongs to, a compromised caller can claim
somebody else's. Reading it from the verified token makes cross-tenant escalation
structurally impossible rather than merely forbidden.

**A chain assembled by copying values between services is decoration.** It only
counts as evidence because it sits inside a signature the authorization server
made. If any service in the path can write to it, it proves nothing. This is the
same lesson as phase 2's authorization code, in different clothes: a value carried
beside the request is advisory, a value carried inside the credential is evidence.

## Write-up

The nesting direction. Show the JSON, then show the same thing read outward as an
English sentence. That sentence is the audit log people actually want, and almost
nobody knows the standard for it already exists.
