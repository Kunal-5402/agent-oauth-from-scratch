from __future__ import annotations

import httpx


def test_jwks_publishes_only_the_public_es256_key(integration_environment):
    response = httpx.get(
        f"{integration_environment.authorization_server_url}/.well-known/jwks.json"
    )

    assert response.status_code == 200
    key = response.json()["keys"][0]
    assert key["kty"] == "EC"
    assert key["crv"] == "P-256"
    assert key["alg"] == "ES256"
    assert {"x", "y", "kid", "use"}.issubset(key)
    assert "d" not in key


def test_metadata_describes_the_running_authorization_server(integration_environment):
    response = httpx.get(
        f"{integration_environment.authorization_server_url}/.well-known/oauth-authorization-server"
    )

    assert response.status_code == 200
    metadata = response.json()
    assert metadata["issuer"] == integration_environment.settings.issuer
    assert (
        metadata["token_endpoint"]
        == f"{integration_environment.authorization_server_url}/oauth/token"
    )
    assert metadata["jwks_uri"] == (
        f"{integration_environment.authorization_server_url}/.well-known/jwks.json"
    )
    assert metadata["grant_types_supported"] == ["client_credentials"]
    assert metadata["response_types_supported"] == []
    assert metadata["token_endpoint_auth_methods_supported"] == [
        "client_secret_post",
        "private_key_jwt",
    ]
