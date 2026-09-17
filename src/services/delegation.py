"""Reading a delegation chain.

The nesting reads backwards from how most people expect. The **outermost**
``sub`` is whoever holds the token right now. The **innermost** entry is the
original human.

```jsonc
{ "sub": "sql-tool-agent",
  "act": { "sub": "orchestrator-agent",
           "act": { "sub": "user_42" } } }
```

People get this wrong on first sight, code review included, which is why the
traversal exists exactly once. Nothing else in this repository walks an ``act``
structure by hand: the question then becomes "does this call chain()", and that
is answerable by grep.
"""

from __future__ import annotations

from typing import Any

from src.errors import OAuthError

# A chain deeper than this is not a delegation, it is a denial of service. The
# depth cap that policy applies is separate and smaller; this is the structural
# limit that stops an unbounded walk before any policy runs.
MAXIMUM_CHAIN_DEPTH = 32

# The claim name lives here, so every reader and the one writer agree, and a
# grep for the literal finds nothing outside this module.
ACT_CLAIM = "act"


class MalformedChainError(OAuthError):
    """An ``act`` structure that cannot be read."""

    def __init__(self, description: str) -> None:
        super().__init__("invalid_grant", description, 400)


def chain(claims: dict[str, Any]) -> list[str]:
    """Outermost first: who holds the token, then who authorised them."""
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise MalformedChainError("token has no subject")

    identities = [subject]
    seen: set[int] = {id(claims)}
    node = claims.get(ACT_CLAIM)

    while node is not None:
        if not isinstance(node, dict):
            raise MalformedChainError("act must be an object")
        if id(node) in seen:
            raise MalformedChainError("act chain refers to itself")
        seen.add(id(node))

        actor = node.get("sub")
        if not isinstance(actor, str) or not actor:
            raise MalformedChainError("an act entry has no subject")
        identities.append(actor)

        if len(identities) > MAXIMUM_CHAIN_DEPTH:
            raise MalformedChainError("act chain is too deep to read")
        node = node.get(ACT_CLAIM)

    return identities


def root(claims: dict[str, Any]) -> str:
    """The identity the whole chain ultimately rests on. Usually the human."""
    return chain(claims)[-1]


def holder(claims: dict[str, Any]) -> str:
    """Whoever is presenting the token right now."""
    return chain(claims)[0]


def depth(claims: dict[str, Any]) -> int:
    """Hops away from the root. A token issued directly to its subject is 0."""
    return len(chain(claims)) - 1


def describe(claims: dict[str, Any]) -> str:
    """The chain as a sentence, for an audit log a person has to read.

    "sql-tool-agent acting for orchestrator-agent acting for user_42"
    """
    return " acting for ".join(chain(claims))


def nest(subject_claims: dict[str, Any]) -> dict[str, Any]:
    """Build the ``act`` claim for a token derived from ``subject_claims``.

    The previous holder becomes the new innermost-but-one entry, carrying its own
    chain with it. Dropping an entry is as bad as adding one.
    """
    subject = subject_claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise MalformedChainError("subject token has no subject")

    new_act: dict[str, Any] = {"sub": subject}
    existing = subject_claims.get(ACT_CLAIM)
    if existing is not None:
        if not isinstance(existing, dict):
            raise MalformedChainError("act must be an object")
        new_act[ACT_CLAIM] = existing
    return new_act
