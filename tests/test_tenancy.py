"""A tenant is never read from a request.

A caller that could send a value saying which account it belongs to could claim
somebody else's. Reading it from the registration, and then carrying it inside
the signature, makes cross-tenant escalation structurally impossible rather than
merely forbidden.
"""

from __future__ import annotations

import httpx
import jwt
import pytest

from src.services.delegation import TENANT_CLAIM, MalformedChainError, tenant_of
from tests.conftest import (
    DOWNSTREAM_AUDIENCE,
    OTHER_TENANT_SECRET,
    REPORTING_SECRET,
    TOOL_SECRET,
)

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


def _claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


@pytest.fixture
def token_endpoint(integration_environment):
    return f"{integration_environment.authorization_server_url}/oauth/token"


def _issue(environment, client_id, secret, scope="reports:read"):
    response = environment.oauth_client.client_credentials(
        client_id=client_id, client_secret=secret, scope=scope
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _exchange(token_endpoint, subject, actor, *, client, secret, **overrides):
    data = {
        "grant_type": GRANT_TYPE,
        "client_id": client,
        "client_secret": secret,
        "subject_token": subject,
        "subject_token_type": ACCESS_TOKEN_TYPE,
        "actor_token": actor,
        "actor_token_type": ACCESS_TOKEN_TYPE,
        "audience": DOWNSTREAM_AUDIENCE,
    }
    data.update(overrides)
    return httpx.post(token_endpoint, data=data)


def test_a_token_carries_the_tenant_from_its_client_registration(
    integration_environment,
):
    default = _issue(integration_environment, "reporting-agent", REPORTING_SECRET)
    other = _issue(integration_environment, "other-tenant-agent", OTHER_TENANT_SECRET)

    assert _claims(default)[TENANT_CLAIM] == "default"
    assert _claims(other)[TENANT_CLAIM] == "acme"


def test_a_tenant_sent_as_a_parameter_is_ignored(integration_environment, token_endpoint):
    response = httpx.post(
        token_endpoint,
        data={
            "grant_type": "client_credentials",
            "client_id": "reporting-agent",
            "client_secret": REPORTING_SECRET,
            "scope": "reports:read",
            "tenant": "acme",
        },
    )

    assert response.status_code == 200
    assert _claims(response.json()["access_token"])[TENANT_CLAIM] == "default"


def test_authority_cannot_cross_a_tenant_boundary(integration_environment, token_endpoint):
    """The subject belongs to one account, the actor to another."""
    subject = _issue(integration_environment, "reporting-agent", REPORTING_SECRET)
    actor = _issue(integration_environment, "other-tenant-agent", OTHER_TENANT_SECRET)

    response = _exchange(
        token_endpoint,
        subject,
        actor,
        client="other-tenant-agent",
        secret=OTHER_TENANT_SECRET,
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_an_exchange_inside_one_tenant_keeps_it(integration_environment, token_endpoint):
    subject = _issue(integration_environment, "reporting-agent", REPORTING_SECRET)
    actor = _issue(integration_environment, "tool-agent", TOOL_SECRET)

    response = _exchange(token_endpoint, subject, actor, client="tool-agent", secret=TOOL_SECRET)

    assert response.status_code == 200
    assert _claims(response.json()["access_token"])[TENANT_CLAIM] == "default"


def test_a_cross_tenant_refusal_writes_no_credential(integration_environment, token_endpoint):
    subject = _issue(integration_environment, "reporting-agent", REPORTING_SECRET)
    actor = _issue(integration_environment, "other-tenant-agent", OTHER_TENANT_SECRET)
    before = len(integration_environment.issued_credentials())

    _exchange(
        token_endpoint,
        subject,
        actor,
        client="other-tenant-agent",
        secret=OTHER_TENANT_SECRET,
    )

    assert len(integration_environment.issued_credentials()) == before


def test_no_endpoint_accepts_a_tenant_from_the_caller():
    """Prove the absence, not just the refusal."""
    from pathlib import Path

    offenders = []
    for path in Path("src").rglob("*.py"):
        if path.name in ("delegation.py", "models.py", "repositories.py"):
            continue
        text = path.read_text()
        for marker in ('form.get("tenant")', 'form.require("tenant")', 'headers.get("tenant")'):
            if marker in text:
                offenders.append(f"{path}: {marker}")

    assert not offenders, "\n".join(offenders)


def test_tenant_of_refuses_a_malformed_value():
    assert tenant_of({}) is None
    with pytest.raises(MalformedChainError):
        tenant_of({TENANT_CLAIM: 42})
    with pytest.raises(MalformedChainError):
        tenant_of({TENANT_CLAIM: ""})


def test_the_exchange_response_declares_what_it_issued(integration_environment, token_endpoint):
    """RFC 8693 2.2.1. token_type says how to present it; this says what it is."""
    subject = _issue(integration_environment, "reporting-agent", REPORTING_SECRET)
    actor = _issue(integration_environment, "tool-agent", TOOL_SECRET)

    response = _exchange(token_endpoint, subject, actor, client="tool-agent", secret=TOOL_SECRET)

    body = response.json()
    assert body["issued_token_type"] == ACCESS_TOKEN_TYPE
    assert body["token_type"] == "Bearer"


def test_an_ordinary_token_response_has_no_issued_token_type(integration_environment):
    response = integration_environment.oauth_client.client_credentials(
        client_id="reporting-agent", client_secret=REPORTING_SECRET, scope="reports:read"
    )

    assert "issued_token_type" not in response.json()
