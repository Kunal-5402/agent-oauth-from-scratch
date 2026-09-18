"""The rules that turn delegation from a way to spread authority into a reduction.

Phase 3 made delegation possible. On its own that is not an improvement. These
rules are what make it safe.
"""

from __future__ import annotations

import httpx
import jwt
import pytest

from src.services.delegation import DEPTH_CLAIM, MalformedChainError, declared_depth, depth
from tests.conftest import DOWNSTREAM_AUDIENCE, REPORTING_SECRET, TOOL_SECRET

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


def _claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


@pytest.fixture
def token_endpoint(integration_environment):
    return f"{integration_environment.authorization_server_url}/oauth/token"


@pytest.fixture
def actor_token(integration_environment):
    return integration_environment.oauth_client.client_credentials(
        client_id="tool-agent", client_secret=TOOL_SECRET, scope="reports:read"
    ).json()["access_token"]


@pytest.fixture
def root_token(integration_environment):
    return integration_environment.oauth_client.client_credentials(
        client_id="reporting-agent",
        client_secret=REPORTING_SECRET,
        scope="reports:read finance:read",
    ).json()["access_token"]


def _exchange(token_endpoint, subject, actor, **overrides):
    data = {
        "grant_type": GRANT_TYPE,
        "client_id": "tool-agent",
        "client_secret": TOOL_SECRET,
        "subject_token": subject,
        "subject_token_type": ACCESS_TOKEN_TYPE,
        "actor_token": actor,
        "actor_token_type": ACCESS_TOKEN_TYPE,
        "audience": DOWNSTREAM_AUDIENCE,
    }
    data.update(overrides)
    return httpx.post(token_endpoint, data=data)


# ------------------------------------------------- rule 1: scope intersection


def test_a_scope_the_subject_does_not_hold_is_absent_rather_than_an_error(
    token_endpoint, actor_token, integration_environment
):
    narrow = integration_environment.oauth_client.client_credentials(
        client_id="reporting-agent", client_secret=REPORTING_SECRET, scope="reports:read"
    ).json()["access_token"]

    response = _exchange(token_endpoint, narrow, actor_token, scope="reports:read finance:read")

    assert response.status_code == 200
    assert response.json()["scope"] == "reports:read"


def test_the_actors_own_ceiling_also_reduces(token_endpoint, root_token, actor_token):
    """The subject holds 2 scopes. The tool agent's registration holds 1."""
    response = _exchange(token_endpoint, root_token, actor_token, scope="finance:read")

    # finance:read is outside the actor's ceiling, so nothing survives.
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"


def test_scopes_never_grow_across_repeated_exchanges(token_endpoint, root_token, actor_token):
    token = root_token
    original = set(_claims(root_token)["scope"].split())

    for _ in range(3):
        response = _exchange(token_endpoint, token, actor_token)
        assert response.status_code == 200
        token = response.json()["access_token"]
        assert set(_claims(token)["scope"].split()) <= original


# ------------------------------------------------------- rule 2: depth capping


def test_a_root_grant_is_depth_zero(root_token):
    assert _claims(root_token)[DEPTH_CLAIM] == 0


def test_each_hop_increments_the_depth(token_endpoint, root_token, actor_token):
    token = root_token
    for expected in (1, 2, 3):
        token = _exchange(token_endpoint, token, actor_token).json()["access_token"]
        assert _claims(token)[DEPTH_CLAIM] == expected


def test_the_cap_refuses_and_signs_nothing(
    integration_environment, token_endpoint, root_token, actor_token
):
    """Checked BEFORE issuance.

    An issue-then-validate shape passes a status-code-only test while leaving a
    signed over-depth token in existence for the moment it takes to notice. The
    row count is the assertion that tells the 2 apart.
    """
    token = root_token
    for _ in range(3):
        token = _exchange(token_endpoint, token, actor_token).json()["access_token"]

    before = len(integration_environment.issued_credentials())
    response = _exchange(token_endpoint, token, actor_token)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert len(integration_environment.issued_credentials()) == before


def test_the_two_counters_must_agree(token_endpoint, root_token, actor_token):
    """delegation_depth and the chain length measure the same thing.

    If they can disagree, one is being written somewhere it should not be, and a
    cap that reads only one of them can be walked past.
    """
    token = root_token
    for _ in range(3):
        token = _exchange(token_endpoint, token, actor_token).json()["access_token"]
        claims = _claims(token)
        assert claims[DEPTH_CLAIM] == depth(claims)
        assert declared_depth(claims) == depth(claims)


@pytest.mark.parametrize("bad", [None, "2", -1, True, 99])
def test_a_missing_or_wrong_depth_is_refused_never_defaulted(bad):
    claims = {"sub": "a", "act": {"sub": "b"}}
    if bad is not None:
        claims[DEPTH_CLAIM] = bad

    with pytest.raises(MalformedChainError):
        declared_depth(claims)


def test_a_depth_sent_as_a_parameter_is_ignored(token_endpoint, root_token, actor_token):
    response = _exchange(token_endpoint, root_token, actor_token, delegation_depth="0")

    assert _claims(response.json()["access_token"])[DEPTH_CLAIM] == 1


# --------------------------------------------------- rule 4: lifetime shrinking


def test_a_lifetime_never_grows_however_many_hops(token_endpoint, root_token, actor_token):
    """The rule that gets skipped, proved by repetition rather than one hop.

    A single-hop test passes under an implementation that merely uses a short
    default. Only the loop shows the min() is doing the work. Without it,
    anybody holding a token near its end refreshes their authority forever
    without ever going back to the human.
    """
    ceiling = _claims(root_token)["exp"]

    token = root_token
    for _ in range(3):
        token = _exchange(token_endpoint, token, actor_token).json()["access_token"]
        assert _claims(token)["exp"] <= ceiling

    assert _claims(token)["exp"] <= ceiling


def test_a_derived_token_cannot_outlive_a_nearly_expired_parent(
    integration_environment, token_endpoint, actor_token, minter_factory
):
    """A subject token with seconds left yields a token with seconds left."""
    subject = minter_factory(ttl_seconds=20)

    response = _exchange(token_endpoint, subject, actor_token)

    assert response.status_code == 200
    assert response.json()["expires_in"] <= 20


@pytest.fixture
def minter_factory(integration_environment):
    from src.crypto.tokens import TokenMinter

    settings = integration_environment.settings

    def build(*, ttl_seconds: int) -> str:
        minter = TokenMinter(
            issuer=settings.issuer,
            signing_key=integration_environment.signing_key,
            default_ttl_seconds=ttl_seconds,
        )
        return minter.mint(
            {
                "sub": "agent:reporting",
                "aud": "test-resource",
                "client_id": "reporting-agent",
                "scope": "reports:read",
                DEPTH_CLAIM: 0,
            }
        ).token

    return build
