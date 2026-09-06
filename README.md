# agent-oauth-from-scratch

> **This is a learning implementation. Do not use it in production.**

An OAuth 2.1 authorization server built from scratch in Python, to understand how
authority travels down a chain of agents without growing on the way.

I spent six weeks reading the specifications and writing notes on them. Reading is
not knowing. This is me finding out which parts I actually understood, by building
them and watching them break.

## Why not just use Keycloak or Ory

Use them. They are excellent and this is not a replacement for any of them.

The reason to build one anyway is that the interesting part of agent identity is
thin on the ground in all of them: **token exchange with a nested actor chain**,
and the rules that keep that chain from quietly gaining authority at each hop.
That is the part I wanted to understand properly, and the only way to understand
it properly is to implement it.

## The one problem this is pointed at

A human asks for something. An orchestrator agent picks it up, calls a reporting
agent, which calls a tool agent, which finally touches the data.

By the time the data is touched, the human is three hops away. The API has one
question and it is not easy:

> On whose authority is this happening, and is that authority sufficient?

There are only three ways to answer it and two of them are bad:

| Design | What happens | Why it fails |
|---|---|---|
| Pass the same token down | Every service holds the human's full authority | One compromised service compromises everything, and the log cannot tell the services apart from the human |
| Give each service its own account | The human's authority is dropped at hop 1 | The API can no longer enforce anything about the human, and the audit trail names a robot |
| **Exchange the token at each hop** | Each service trades its token for a narrower one naming itself and the chain behind it | This is what the repo implements |

## Roadmap

Six phases. Each one is a working slice, not a layer, so the server runs at the end
of every phase.

| # | Phase | State |
|---|---|---|
| 1 | [Token endpoint and the signing core](roadmap/phase-1-token-endpoint.md) | in progress |
| 2 | [Authorization code with PKCE](roadmap/phase-2-authorization-code-pkce.md) | not started |
| 3 | [Token exchange, RFC 8693](roadmap/phase-3-token-exchange.md) | not started |
| 4 | [The five shrink rules](roadmap/phase-4-shrink-rules.md) | not started |
| 5 | [DPoP sender-constraining](roadmap/phase-5-dpop.md) | not started |
| 6 | [Introspection, revocation, reuse detection](roadmap/phase-6-introspection-revocation.md) | not started |

Each phase document says what gets built, which part of the specification it comes
from, how to know it works, and the specific mistakes that are easy to make. Start
with [roadmap/README.md](roadmap/README.md).

## What works today

Nothing yet. Phase 1 is in progress.

This section gets updated honestly as things land. If a phase is half done it says
half done.

## Specifications implemented

| Document | What it gives |
|---|---|
| RFC 6749 / OAuth 2.1 draft | The core framework and the grant vocabulary |
| RFC 7519, 7515, 7517 | JWT, signatures, and published key sets |
| RFC 7636 | PKCE |
| RFC 8693 | Token exchange and the `act` chain |
| RFC 9449 | DPoP |
| RFC 7662 / RFC 7009 | Introspection and revocation |
| RFC 8252 | Native app redirect rules, including the loopback exception |
| RFC 9700 | Security best current practice, which is the one to read second |

## Running it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m agent_oauth.server
```

Instructions get real as the code does.

## Why the disclaimer is at the top

Because it is true, and because "I built an OAuth server" is a sentence that
deserves suspicion. This server has not been audited, has not been fuzzed, has no
rate limiting worth the name, and stores things in ways a real deployment would
not tolerate. It exists to be read and argued with, not to guard anything.

If you find something wrong, open an issue. That is the entire point of doing this
in the open.