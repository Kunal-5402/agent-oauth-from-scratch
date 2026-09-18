"""RFC 8693 token exchange. The phase this repository exists for.

The sentence to keep in mind while reading these tests:

    The SUBJECT token carries the authority.
    The ACTOR token carries the identity of whoever is about to hold it.
"""

from __future__ import annotations

import httpx
import jwt
import pytest

from src.services.delegation import chain, describe, root
from tests.conftest import DOWNSTREAM_AUDIENCE, REPORTING_SECRET, TOOL_SECRET

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


def _claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


@pytest.fixture
def token_endpoint(integration_environment):
    return f"{integration_environment.authorization_server_url}/oauth/token"


@pytest.fixture
def tokens(integration_environment):
    """A subject token holding authority, and an actor token naming the tool."""

    def issue(client_id, secret, scope):
        response = integration_environment.oauth_client.client_credentials(
            client_id=client_id, client_secret=secret, scope=scope
        )
        assert response.status_code == 200, response.text
        return response.json()["access_token"]

    return {
        "subject": issue("reporting-agent", REPORTING_SECRET, "reports:read finance:read"),
        "actor": issue("tool-agent", TOOL_SECRET, "reports:read"),
    }


def _exchange(token_endpoint, tokens, *, client=("tool-agent", TOOL_SECRET), **overrides):
    data = {
        "grant_type": GRANT_TYPE,
        "client_id": client[0],
        "client_secret": client[1],
        "subject_token": tokens["subject"],
        "subject_token_type": ACCESS_TOKEN_TYPE,
        "actor_token": tokens["actor"],
        "actor_token_type": ACCESS_TOKEN_TYPE,
        "audience": DOWNSTREAM_AUDIENCE,
    }
    data.update({k: v for k, v in overrides.items() if v is not None})
    for key, value in overrides.items():
        if value is None:
            data.pop(key, None)
    return httpx.post(token_endpoint, data=data)


# ------------------------------------------------------------------- it works


def test_the_new_token_names_the_actor_and_records_who_authorised_it(token_endpoint, tokens):
    response = _exchange(token_endpoint, tokens)

    assert response.status_code == 200, response.text
    claims = _claims(response.json()["access_token"])

    # The OUTERMOST sub holds the token. The INNERMOST is the root.
    assert claims["sub"] == "agent:sql-tool"
    assert claims["act"] == {"sub": "agent:reporting"}
    assert chain(claims) == ["agent:sql-tool", "agent:reporting"]
    assert root(claims) == "agent:reporting"
    assert describe(claims) == "agent:sql-tool acting for agent:reporting"


def test_the_token_is_aimed_at_the_requested_service(token_endpoint, tokens):
    claims = _claims(_exchange(token_endpoint, tokens).json()["access_token"])

    assert claims["aud"] == DOWNSTREAM_AUDIENCE


def test_exchanging_twice_nests_two_deep_and_keeps_the_root(token_endpoint, tokens):
    """A 2-deep test passes under an implementation that keeps only one level."""
    first = _exchange(token_endpoint, tokens).json()["access_token"]

    second = _exchange(
        token_endpoint,
        {"subject": first, "actor": tokens["actor"]},
    )

    assert second.status_code == 200, second.text
    claims = _claims(second.json()["access_token"])
    assert chain(claims) == ["agent:sql-tool", "agent:sql-tool", "agent:reporting"]
    assert root(claims) == "agent:reporting"


def test_authority_shrinks_to_what_the_actor_may_hold(token_endpoint, tokens):
    """The subject token holds 2 scopes. The tool agent's ceiling holds 1."""
    response = _exchange(token_endpoint, tokens, scope="reports:read finance:read")

    assert response.status_code == 200
    # finance:read is absent, not an error. It is simply gone.
    assert response.json()["scope"] == "reports:read"


def test_a_derived_token_never_outlives_the_token_it_came_from(token_endpoint, tokens):
    subject_exp = _claims(tokens["subject"])["exp"]

    claims = _claims(_exchange(token_endpoint, tokens).json()["access_token"])

    assert claims["exp"] <= subject_exp


def test_the_exchange_is_recorded_like_any_other_issuance(
    integration_environment, token_endpoint, tokens
):
    claims = _claims(_exchange(token_endpoint, tokens).json()["access_token"])

    row = integration_environment.credential(claims["jti"])

    assert row is not None
    assert row["audience"] == DOWNSTREAM_AUDIENCE
    # The root is recorded so phase 6 can revoke a whole tree from it.
    assert row["root_subject"] == "agent:reporting"


# -------------------------------------------------------------------- refusals


def test_an_exchange_with_no_audience_is_refused(token_endpoint, tokens):
    """A token that works everywhere is a token whose theft costs everything."""
    response = _exchange(token_endpoint, tokens, audience=None)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_an_audience_the_caller_may_not_reach_is_refused(token_endpoint, tokens):
    response = _exchange(token_endpoint, tokens, audience="payments-api")

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_target"


def test_two_audience_values_are_refused(token_endpoint, tokens):
    response = httpx.post(
        token_endpoint,
        content=(
            f"grant_type={GRANT_TYPE}&client_id=tool-agent&client_secret={TOOL_SECRET}"
            f"&subject_token={tokens['subject']}&subject_token_type={ACCESS_TOKEN_TYPE}"
            f"&actor_token={tokens['actor']}&actor_token_type={ACCESS_TOKEN_TYPE}"
            f"&audience=sql-api&audience=payments-api"
        ),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


@pytest.mark.parametrize("which", ["subject_token", "actor_token"])
def test_a_tampered_token_issues_nothing(integration_environment, token_endpoint, tokens, which):
    """Both tokens get the full verification path, and both finish first."""
    key = "subject" if which == "subject_token" else "actor"
    broken = dict(tokens)
    broken[key] = tokens[key] + "x"

    before = len(integration_environment.issued_credentials())
    response = _exchange(token_endpoint, broken)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert len(integration_environment.issued_credentials()) == before


def test_the_two_token_failures_are_indistinguishable(token_endpoint, tokens):
    """Naming which token failed tells a caller which forgery got closest."""
    bad_subject = _exchange(token_endpoint, {**tokens, "subject": tokens["subject"] + "x"})
    bad_actor = _exchange(token_endpoint, {**tokens, "actor": tokens["actor"] + "x"})

    assert bad_subject.status_code == bad_actor.status_code
    assert bad_subject.json() == bad_actor.json()


@pytest.mark.parametrize(
    "missing", ["subject_token", "subject_token_type", "actor_token", "actor_token_type"]
)
def test_a_missing_required_parameter_is_refused(token_endpoint, tokens, missing):
    response = _exchange(token_endpoint, tokens, **{missing: None})

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


@pytest.mark.parametrize("field", ["subject_token_type", "actor_token_type"])
def test_an_unsupported_token_type_is_refused(token_endpoint, tokens, field):
    response = _exchange(
        token_endpoint, tokens, **{field: "urn:ietf:params:oauth:token-type:id_token"}
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_an_unsupported_requested_token_type_is_refused(token_endpoint, tokens):
    response = _exchange(
        token_endpoint,
        tokens,
        requested_token_type="urn:ietf:params:oauth:token-type:id_token",
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_an_act_sent_as_a_parameter_is_ignored(token_endpoint, tokens):
    """The chain counts as evidence only because the server wrote it."""
    response = _exchange(
        token_endpoint, tokens, act='{"sub": "user_root", "act": {"sub": "anybody"}}'
    )

    assert response.status_code == 200
    claims = _claims(response.json()["access_token"])
    assert claims["act"] == {"sub": "agent:reporting"}
    assert "user_root" not in chain(claims)


def test_an_unauthenticated_exchange_is_refused(token_endpoint, tokens):
    response = _exchange(token_endpoint, tokens, client=("tool-agent", "wrong-secret"))

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_the_grant_is_advertised(integration_environment):
    metadata = httpx.get(
        f"{integration_environment.authorization_server_url}/.well-known/oauth-authorization-server"
    ).json()

    assert GRANT_TYPE in metadata["grant_types_supported"]
