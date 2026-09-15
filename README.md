# Agent OAuth Authorization Server

> **Security-focused reference implementation. Just for learning and fun. Not approved for production use.**

An OAuth 2.1 authorization server built in Python to make agent delegation
concrete: authority should travel through a chain of agents without growing at
each hop.

The implementation uses standard cryptographic libraries rather than an OAuth
server framework. The objective is a small, readable reference for the security
properties that matter in agentic systems: distinct agent identity, attenuated
delegation, verifiable actor chains, and deliberate revocation semantics.

Start with the [architecture](docs/architecture.md), [design notes](docs/design.md),
and [roadmap](docs/roadmap/README.md).

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
| 1 | [Token endpoint and the signing core](docs/roadmap/phase-1-token-endpoint.md) | in progress |
| 2 | [Authorization code with PKCE](docs/roadmap/phase-2-authorization-code-pkce.md) | not started |
| 3 | [Token exchange, RFC 8693](docs/roadmap/phase-3-token-exchange.md) | not started |
| 4 | [The five shrink rules](docs/roadmap/phase-4-shrink-rules.md) | not started |
| 5 | [DPoP sender-constraining](docs/roadmap/phase-5-dpop.md) | not started |
| 6 | [Introspection, revocation, reuse detection](docs/roadmap/phase-6-introspection-revocation.md) | not started |

Each phase document says what gets built, which part of the specification it comes
from, how to know it works, and the specific mistakes that are easy to make. Start
with [docs/roadmap/README.md](docs/roadmap/README.md).

## What works today

The first Phase 1 slice is implemented:

- `GET /.well-known/jwks.json` publishes a public ES256 P-256 JWK.
- `GET /.well-known/oauth-authorization-server` publishes OAuth AS metadata.
- `POST /oauth/token` supports `client_credentials` with form-body client
  authentication (`client_secret_post`).
- Tokens are ES256 JWTs with `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, and an
  attenuated `scope`; their signatures can be independently verified from JWKS.
- Integration tests run a real HTTP OAuth client, authorization server, and
  independent FastAPI resource server on loopback TCP sockets.

The server is still a learning implementation. It does not yet have a database
backed token ledger, revocation, rate limiting, key rotation, or an audit.

## Documentation

| Document | What it covers |
|---|---|
| [Architecture](docs/architecture.md) | Runtime components, trust boundaries, data flow, and source layout. |
| [Design notes](docs/design.md) | Protocol contracts, token claims, verification rules, and test strategy. |
| [Roadmap](docs/roadmap/README.md) | The planned working slices and refusal-first acceptance criteria. |

## Specifications in scope

The roadmap derives behavior from these documents. Only the Phase 1 subset
listed above is implemented today.

| Document | What it provides |
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
make setup      # dependencies, pre-commit hooks, and a .env with a random secret
make run        # http://127.0.0.1:8000
```

In a second terminal:

```bash
make token      # request an access token from the running server
```

`make` on its own lists every target:

| Target | What it does |
|---|---|
| `make setup` | `install`, `hooks` and `env` together |
| `make run` | Start the server with reload. `PORT=9000 make run` to change the port |
| `make token` | Ask the running server for an access token |
| `make test` | Run the test suite |
| `make check` | Everything CI runs: lint, format check, tests |
| `make clean` | Remove caches. Your signing key and `.env` are never touched |

`make env` generates a random `OAUTH_CLIENT_SECRET` for you and refuses to
overwrite a `.env` you already have.

Every target is a thin wrapper over a `uv` command, so nothing here is required.
The long form still works:

```bash
uv sync --all-groups
set -a && source .env && set +a
uv run uvicorn src.main:app --reload
uv run pytest
```

## Checks

Install the pre-commit hooks one time:

```bash
uv run pre-commit install
```

Every commit then runs `ruff check`, `ruff format`, and a `detect-private-key`
scan. The last one matters most here: this repository is an authorization
server, so a committed private key is the worst available mistake.

Run the same checks over the whole repository at any time:

```bash
uv run pre-commit run --all-files
```

GitHub Actions runs the lint, the format check, the test suite, and the
private-key scan on every push to `main` and on every pull request. See
[.github/workflows/ci.yaml](.github/workflows/ci.yaml).

## Why the disclaimer is at the top

Because building an OAuth server is a security-critical activity. This project
has not been audited or fuzzed; it does not yet implement durable client/token
storage, revocation, key rotation, rate limiting, or operational monitoring. It
is designed to make the protocol and its failure modes inspectable, not to guard
production data.

If you find something wrong, open an issue. That is the entire point of doing this
in the open.
