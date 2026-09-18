"""may_act, and the task a tree of work belongs to.

Both are read from a VERIFIED token and never from a request parameter. A value
carried beside the request is advisory; a value carried inside the credential is
evidence.
"""

from __future__ import annotations

import httpx
import jwt
import pytest

from src.crypto.tokens import TokenMinter
from src.services.delegation import (
    DEPTH_CLAIM,
    MAY_ACT_CLAIM,
    TASK_CLAIM,
    MalformedChainError,
    may_act_permits,
    task_of,
)
from tests.conftest import DOWNSTREAM_AUDIENCE, REPORTING_SECRET, TOOL_SECRET

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


def _claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


@pytest.fixture
def token_endpoint(integration_environment):
    return f"{integration_environment.authorization_server_url}/oauth/token"


@pytest.fixture
def minter(integration_environment):
    """Mint a subject token with claims no grant issues yet, such as may_act."""
    settings = integration_environment.settings
    return TokenMinter(
        issuer=settings.issuer,
        signing_key=integration_environment.signing_key,
        default_ttl_seconds=settings.access_token_ttl_seconds,
    )


@pytest.fixture
def actor_token(integration_environment):
    response = integration_environment.oauth_client.client_credentials(
        client_id="tool-agent", client_secret=TOOL_SECRET, scope="reports:read"
    )
    assert response.status_code == 200
    return response.json()["access_token"]


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


def _subject_with(minter, **extra):
    return minter.mint(
        {
            "sub": "agent:reporting",
            "aud": "test-resource",
            "client_id": "reporting-agent",
            "scope": "reports:read",
            # A hand-minted token must look like a real one. A missing depth
            # counter is refused, never defaulted to 0.
            DEPTH_CLAIM: 0,
            **extra,
        }
    ).token


# ---------------------------------------------------------------------- may_act


def test_an_actor_named_by_may_act_is_permitted(token_endpoint, minter, actor_token):
    subject = _subject_with(minter, **{MAY_ACT_CLAIM: {"sub": "agent:sql-tool"}})

    response = _exchange(token_endpoint, subject, actor_token)

    assert response.status_code == 200, response.text
    assert _claims(response.json()["access_token"])["sub"] == "agent:sql-tool"


def test_an_actor_not_named_by_may_act_is_refused(token_endpoint, minter, actor_token):
    subject = _subject_with(minter, **{MAY_ACT_CLAIM: {"sub": "agent:somebody-else"}})

    response = _exchange(token_endpoint, subject, actor_token)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_the_refusal_does_not_name_who_was_expected(token_endpoint, minter, actor_token):
    """Otherwise a caller who guessed a subject token learns the topology."""
    subject = _subject_with(minter, **{MAY_ACT_CLAIM: {"sub": "agent:secret-orchestrator"}})

    body = _exchange(token_endpoint, subject, actor_token).text

    assert "secret-orchestrator" not in body


def test_a_list_of_permitted_actors_is_accepted(token_endpoint, minter, actor_token):
    subject = _subject_with(
        minter,
        **{MAY_ACT_CLAIM: [{"sub": "agent:other"}, {"sub": "agent:sql-tool"}]},
    )

    assert _exchange(token_endpoint, subject, actor_token).status_code == 200


def test_a_may_act_sent_as_a_parameter_changes_nothing(token_endpoint, minter, actor_token):
    subject = _subject_with(minter, **{MAY_ACT_CLAIM: {"sub": "agent:somebody-else"}})

    response = _exchange(token_endpoint, subject, actor_token, may_act='{"sub": "agent:sql-tool"}')

    assert response.status_code == 400


def test_no_may_act_means_the_actors_own_registration_is_the_only_ceiling(
    token_endpoint, minter, actor_token
):
    assert _exchange(token_endpoint, _subject_with(minter), actor_token).status_code == 200


@pytest.mark.parametrize(
    ("claims", "actor", "permitted"),
    [
        ({}, "a", True),
        ({MAY_ACT_CLAIM: {"sub": "a"}}, "a", True),
        ({MAY_ACT_CLAIM: {"sub": "b"}}, "a", False),
        ({MAY_ACT_CLAIM: [{"sub": "b"}, {"sub": "a"}]}, "a", True),
        ({MAY_ACT_CLAIM: [{"sub": "b"}]}, "a", False),
        ({MAY_ACT_CLAIM: []}, "a", False),
    ],
)
def test_may_act_permits_unit(claims, actor, permitted):
    assert may_act_permits(claims, actor) is permitted


def test_a_malformed_may_act_raises():
    with pytest.raises(MalformedChainError):
        may_act_permits({MAY_ACT_CLAIM: "agent:sql-tool"}, "agent:sql-tool")


# ---------------------------------------------------------------------- task_id


def test_a_root_grant_starts_a_task(integration_environment):
    response = integration_environment.oauth_client.client_credentials(
        client_id="reporting-agent", client_secret=REPORTING_SECRET, scope="reports:read"
    )

    claims = _claims(response.json()["access_token"])

    assert isinstance(claims[TASK_CLAIM], str)
    assert claims[TASK_CLAIM]


def test_every_token_in_a_tree_carries_the_same_task(
    integration_environment, token_endpoint, actor_token
):
    """Copied, never generated. A new id would detach the branch from its tree."""
    root_response = integration_environment.oauth_client.client_credentials(
        client_id="reporting-agent", client_secret=REPORTING_SECRET, scope="reports:read"
    )
    root_token = root_response.json()["access_token"]
    task = _claims(root_token)[TASK_CLAIM]

    hop1 = _exchange(token_endpoint, root_token, actor_token).json()["access_token"]
    hop2 = _exchange(token_endpoint, hop1, actor_token).json()["access_token"]
    hop3 = _exchange(token_endpoint, hop2, actor_token).json()["access_token"]

    assert [_claims(t)[TASK_CLAIM] for t in (hop1, hop2, hop3)] == [task, task, task]


def test_the_task_is_recorded_on_every_row_of_the_tree(
    integration_environment, token_endpoint, actor_token
):
    root_token = integration_environment.oauth_client.client_credentials(
        client_id="reporting-agent", client_secret=REPORTING_SECRET, scope="reports:read"
    ).json()["access_token"]
    task = _claims(root_token)[TASK_CLAIM]

    _exchange(token_endpoint, root_token, actor_token)

    rows = [r for r in integration_environment.issued_credentials() if r["task_id"] == task]
    # The root token, and the token exchanged from it.
    assert len(rows) == 2


def test_a_task_sent_as_a_parameter_is_ignored(
    integration_environment, token_endpoint, actor_token
):
    root_token = integration_environment.oauth_client.client_credentials(
        client_id="reporting-agent", client_secret=REPORTING_SECRET, scope="reports:read"
    ).json()["access_token"]
    task = _claims(root_token)[TASK_CLAIM]

    response = _exchange(token_endpoint, root_token, actor_token, task_id="an-id-i-invented")

    assert _claims(response.json()["access_token"])[TASK_CLAIM] == task


def test_task_of_refuses_a_malformed_value():
    assert task_of({}) is None
    with pytest.raises(MalformedChainError):
        task_of({TASK_CLAIM: 42})
    with pytest.raises(MalformedChainError):
        task_of({TASK_CLAIM: ""})
