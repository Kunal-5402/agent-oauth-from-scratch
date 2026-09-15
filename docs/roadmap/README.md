# Roadmap

Six phases. Each one is a **working slice**, not a layer. The server runs at the
end of every phase, and each phase adds a capability rather than a tier of
abstraction.

Files are named `phase-N-topic.md` so they sort in build order in any file
listing.

## Current baseline

The Phase 1 foundation is partially implemented: the server persists an ES256
P-256 signing key, publishes JWKS and authorization-server metadata, and issues
scope-attenuated `client_credentials` tokens. The integration suite verifies
that flow through a real HTTP client and an independent resource server.

Phase 1 remains in progress because it still needs durable issuance records and
HTTP Basic client authentication. Those omissions are deliberate and documented;
the project does not mark a phase complete until its full refusal criteria hold.

For the current component and trust-boundary view, read the
[architecture](../architecture.md) and [design notes](../design.md).

## The order, and why it is this order

| # | Phase | Adds | Depends on |
|---|---|---|---|
| 1 | [Token endpoint and the signing core](phase-1-token-endpoint.md) | Something that mints and publishes verifiable tokens | Nothing |
| 2 | [Authorization code with PKCE](phase-2-authorization-code-pkce.md) | A human in the picture, and a front channel that cannot be robbed | 1 |
| 3 | [Token exchange, RFC 8693](phase-3-token-exchange.md) | The `act` chain. Authority moves between actors | 1 |
| 4 | [The five shrink rules](phase-4-shrink-rules.md) | The chain can only ever narrow | 3 |
| 5 | [DPoP sender-constraining](phase-5-dpop.md) | A copied token is inert | 1 |
| 6 | [Introspection, revocation, reuse detection](phase-6-introspection-revocation.md) | Taking access back | 1, 2, 3 |

Phase 1 comes first because nothing else can be tested until the server can sign a
token and publish the key to verify it.

Phases 3 and 4 are deliberately separate. Phase 3 makes delegation **possible**.
Phase 4 makes it **safe**. Splitting them is the honest order, because an
implementation that stops after phase 3 is a working delegation system with no
ceiling on it, and that is exactly the state most real systems are in.

## What each phase document contains

- **The one idea**, in a sentence.
- **Why it exists**, which is usually an attack or a lost audit trail.
- **What to build**, as a checklist.
- **Done when**, as tests that either pass or do not.
- **Traps**, which are the mistakes that are easy to make and hard to see. These
  are the most valuable part of each document.
- **Write-up**, which is the thing worth posting about when the phase lands.

## A rule for the whole project

> Every phase ships with the failing test written first.

Not because test-first is a virtue in general, but because in an authorization
server the interesting behaviour **is** the refusal. A server that issues tokens
correctly and refuses nothing is not half finished, it is dangerous. So each phase
lists what must be rejected, and those tests come before the happy path.
