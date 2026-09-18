"""Reading and building a delegation chain.

Pure functions over a claims dictionary. No HTTP, no database, no key.
"""

from __future__ import annotations

import pytest

from src.services.delegation import (
    MAXIMUM_CHAIN_DEPTH,
    MalformedChainError,
    chain,
    depth,
    describe,
    holder,
    nest,
    root,
)


def _chain_of(*identities: str) -> dict:
    """Build claims for a chain given outermost first."""
    claims: dict = {"sub": identities[0]}
    node = claims
    for identity in identities[1:]:
        node["act"] = {"sub": identity}
        node = node["act"]
    return claims


def test_a_token_with_no_act_is_a_chain_of_one():
    assert chain({"sub": "reporting-agent"}) == ["reporting-agent"]
    assert depth({"sub": "reporting-agent"}) == 0


def test_the_outermost_subject_holds_the_token_and_the_innermost_is_the_root():
    claims = _chain_of("sql-tool-agent", "orchestrator-agent", "user_42")

    assert chain(claims) == ["sql-tool-agent", "orchestrator-agent", "user_42"]
    assert holder(claims) == "sql-tool-agent"
    assert root(claims) == "user_42"
    assert depth(claims) == 2


@pytest.mark.parametrize("hops", range(1, 8))
def test_the_root_is_the_original_human_at_any_depth(hops):
    """A 2-deep test passes under an implementation that keeps only one level."""
    identities = [f"agent-{n}" for n in range(hops)] + ["user_42"]

    claims = _chain_of(*identities)

    assert root(claims) == "user_42"
    assert depth(claims) == hops
    assert chain(claims) == identities


def test_describe_reads_as_a_sentence():
    claims = _chain_of("sql-tool-agent", "orchestrator-agent", "user_42")

    assert describe(claims) == ("sql-tool-agent acting for orchestrator-agent acting for user_42")


def test_nesting_puts_the_previous_holder_inside_and_keeps_its_chain():
    before = _chain_of("orchestrator-agent", "user_42")

    act = nest(before)

    after = {"sub": "sql-tool-agent", "act": act}
    assert chain(after) == ["sql-tool-agent", "orchestrator-agent", "user_42"]


def test_nesting_a_root_token_produces_a_single_entry():
    act = nest({"sub": "user_42"})

    assert act == {"sub": "user_42"}
    assert chain({"sub": "orchestrator-agent", "act": act}) == [
        "orchestrator-agent",
        "user_42",
    ]


@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"sub": ""},
        {"sub": 42},
        {"sub": "a", "act": "not-an-object"},
        {"sub": "a", "act": {"no_sub": "x"}},
        {"sub": "a", "act": {"sub": ""}},
        {"sub": "a", "act": {"sub": "b", "act": []}},
    ],
)
def test_a_malformed_chain_is_refused(claims):
    with pytest.raises(MalformedChainError):
        chain(claims)


def test_a_self_referential_chain_raises_instead_of_hanging():
    claims: dict = {"sub": "a"}
    claims["act"] = claims

    with pytest.raises(MalformedChainError, match="refers to itself"):
        chain(claims)


def test_an_absurdly_deep_chain_is_refused_before_it_is_walked():
    """Structural limit, not policy. Policy caps depth far lower."""
    identities = [f"agent-{n}" for n in range(MAXIMUM_CHAIN_DEPTH + 5)]

    with pytest.raises(MalformedChainError, match="too deep"):
        chain(_chain_of(*identities))


def test_a_chain_exactly_at_the_limit_is_still_readable():
    identities = [f"agent-{n}" for n in range(MAXIMUM_CHAIN_DEPTH)]

    assert len(chain(_chain_of(*identities))) == MAXIMUM_CHAIN_DEPTH


def test_nothing_outside_this_module_walks_an_act_structure_by_hand():
    """The traversal exists once, so reviewing it is a grep rather than a read."""
    from pathlib import Path

    offenders = []
    for path in Path("src").rglob("*.py"):
        if path.name == "delegation.py":
            continue
        text = path.read_text()
        for marker in ('["act"]', '.get("act")', "['act']"):
            if marker in text:
                offenders.append(f"{path}: {marker}")

    assert not offenders, "\n".join(offenders)
