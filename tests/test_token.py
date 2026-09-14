from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
import httpx

def test_client_credentials_token_authorizes_an_independent_resource_server(integration_environment):
    response = integration_environment.oauth_client.client_credentials(
        client_id="reporting-agent",
        client_secret="test-only-secret",
        scope="reports:read",
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    payload = response.json()
    assert payload["token_type"] == "Bearer"
    assert payload["expires_in"] == 600
    assert payload["scope"] == "reports:read"

    resource_response = httpx.get(
        f"{integration_environment.resource_server_url}/reports",
        headers={"Authorization": f"Bearer {payload['access_token']}"},
    )
    assert resource_response.status_code == 200
    assert resource_response.json() == {
        "subject": "agent:reporting",
        "report": "access granted",
    }


def test_scope_is_attenuated_instead_of_rejected_as_a_whole(integration_environment):
    response = integration_environment.oauth_client.client_credentials(
        client_id="reporting-agent",
        client_secret="test-only-secret",
        scope="finance:read admin:*",
    )

    assert response.status_code == 200
    assert response.json()["scope"] == "finance:read"


def test_client_with_no_allowed_scopes_cannot_receive_authority(integration_environment):
    response = integration_environment.oauth_client.client_credentials(
        client_id="no-authority-agent",
        client_secret="test-only-empty-scope-secret",
        scope="finance:read",
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"


@pytest.mark.parametrize(
    ("data", "status_code", "error"),
    [
        (
            {
                "grant_type": "magic_beans",
                "client_id": "reporting-agent",
                "client_secret": "test-only-secret",
            },
            400,
            "unsupported_grant_type",
        ),
        (
            {
                "grant_type": "client_credentials",
                "client_id": "reporting-agent",
                "client_secret": "wrong-secret",
            },
            401,
            "invalid_client",
        ),
        (
            {
                "grant_type": "client_credentials",
                "client_id": "unregistered-agent",
                "client_secret": "test-only-secret",
            },
            401,
            "invalid_client",
        ),
        (
            {
                "grant_type": "client_credentials",
                "client_id": "reporting-agent",
            },
            400,
            "invalid_request",
        ),
    ],
)
def test_token_endpoint_returns_standard_errors(integration_environment, data, status_code, error):
    response = httpx.post(f"{integration_environment.authorization_server_url}/oauth/token", data=data)

    assert response.status_code == status_code
    assert response.json()["error"] == error
    assert response.headers["cache-control"] == "no-store"


def test_token_endpoint_ignores_query_parameters(integration_environment):
    response = httpx.post(
        f"{integration_environment.authorization_server_url}/oauth/token?client_id=attacker-controlled-client",
        data={
            "grant_type": "client_credentials",
            "client_id": "reporting-agent",
            "client_secret": "test-only-secret",
            "scope": "reports:read",
        },
    )

    assert response.status_code == 200
    assert response.json()["scope"] == "reports:read"


def test_token_endpoint_rejects_duplicate_security_parameters(integration_environment):
    response = httpx.post(
        f"{integration_environment.authorization_server_url}/oauth/token",
        content=(
            "grant_type=client_credentials&client_id=reporting-agent&"
            "client_id=attacker-controlled-client&client_secret=test-only-secret"
        ),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_resource_server_rejects_tampered_token(integration_environment):
    response = integration_environment.oauth_client.client_credentials(
        client_id="reporting-agent",
        client_secret="test-only-secret",
        scope="reports:read",
    )
    tampered_token = f"{response.json()['access_token']}x"

    resource_response = httpx.get(
        f"{integration_environment.resource_server_url}/reports",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert resource_response.status_code == 401
    assert resource_response.headers["www-authenticate"] == 'Bearer error="invalid_token"'


def test_resource_server_rejects_a_token_for_a_different_audience(integration_environment):
    now = datetime.now(UTC)
    wrong_audience_token = jwt.encode(
        {
            "iss": integration_environment.settings.issuer,
            "sub": "agent:reporting",
            "aud": "other-resource",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "jti": "test-jti",
        },
        integration_environment.signing_key.private_key,
        algorithm="ES256",
        headers={"kid": integration_environment.signing_key.kid, "typ": "at+jwt"},
    )

    resource_response = httpx.get(
        f"{integration_environment.resource_server_url}/reports",
        headers={"Authorization": f"Bearer {wrong_audience_token}"},
    )
    assert resource_response.status_code == 401


def test_resource_server_rejects_a_token_without_the_endpoint_scope(integration_environment):
    response = integration_environment.oauth_client.client_credentials(
        client_id="reporting-agent",
        client_secret="test-only-secret",
        scope="finance:read",
    )

    resource_response = httpx.get(
        f"{integration_environment.resource_server_url}/reports",
        headers={"Authorization": f"Bearer {response.json()['access_token']}"},
    )
    assert resource_response.status_code == 403
    assert resource_response.headers["www-authenticate"] == (
        'Bearer error="insufficient_scope", scope="reports:read"'
    )


def test_resource_server_rejects_an_expired_token(integration_environment):
    expired_at = datetime.now(UTC) - timedelta(minutes=5)
    expired_token = jwt.encode(
        {
            "iss": integration_environment.settings.issuer,
            "sub": "agent:reporting",
            "aud": integration_environment.settings.resource_audience,
            "iat": expired_at - timedelta(minutes=10),
            "exp": expired_at,
            "jti": "expired-test-jti",
            "scope": "reports:read",
        },
        integration_environment.signing_key.private_key,
        algorithm="ES256",
        headers={"kid": integration_environment.signing_key.kid, "typ": "at+jwt"},
    )

    resource_response = httpx.get(
        f"{integration_environment.resource_server_url}/reports",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert resource_response.status_code == 401
    assert resource_response.headers["www-authenticate"] == 'Bearer error="invalid_token"'


def test_resource_server_rejects_an_hmac_token_signed_with_the_published_key(
    integration_environment,
):
    """Refuse the classic algorithm-confusion attack.

    The attacker takes public key material from the JWKS and uses it as an
    HMAC secret. A verifier that trusts the header ``alg`` accepts the result.
    """
    public_jwk = integration_environment.signing_key.public_jwk()
    now = datetime.now(UTC)
    forged_token = jwt.encode(
        {
            "iss": integration_environment.settings.issuer,
            "sub": "agent:reporting",
            "aud": integration_environment.settings.resource_audience,
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "jti": "forged-test-jti",
            "scope": "reports:read",
        },
        public_jwk["x"],
        algorithm="HS256",
        headers={"kid": public_jwk["kid"], "typ": "at+jwt"},
    )

    resource_response = httpx.get(
        f"{integration_environment.resource_server_url}/reports",
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    assert resource_response.status_code == 401
    assert resource_response.headers["www-authenticate"] == 'Bearer error="invalid_token"'
