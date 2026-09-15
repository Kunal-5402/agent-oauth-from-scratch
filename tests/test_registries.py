"""The registries are the source of truth for the discovery document.

These tests are the reason the metadata is derived rather than stored in a
file. None of them can be written against a static document, because nothing
connects a file to the code that serves requests.
"""

from __future__ import annotations

import httpx
import pytest

from src.auth import ClientAuthRegistry, ClientSecretPost, default_client_auth_registry
from src.config import Settings
from src.grants import ClientCredentialsGrant, GrantRegistry, default_grant_registry


def test_every_advertised_grant_type_has_a_registered_handler(integration_environment):
    response = httpx.get(
        f"{integration_environment.authorization_server_url}/.well-known/oauth-authorization-server"
    )

    advertised = set(response.json()["grant_types_supported"])
    assert advertised == set(default_grant_registry().grant_types())


def test_every_advertised_auth_method_has_a_registered_handler(integration_environment):
    response = httpx.get(
        f"{integration_environment.authorization_server_url}/.well-known/oauth-authorization-server"
    )

    advertised = set(response.json()["token_endpoint_auth_methods_supported"])
    assert advertised == set(default_client_auth_registry().names())


def test_response_types_come_from_the_installed_grants(integration_environment):
    response = httpx.get(
        f"{integration_environment.authorization_server_url}/.well-known/oauth-authorization-server"
    )

    assert response.json()["response_types_supported"] == sorted(
        default_grant_registry().response_types()
    )


def test_a_duplicate_grant_type_cannot_be_registered():
    with pytest.raises(ValueError, match="grant types must be unique"):
        GrantRegistry([ClientCredentialsGrant(), ClientCredentialsGrant()])


def test_a_duplicate_auth_method_cannot_be_registered():
    with pytest.raises(ValueError, match="method names must be unique"):
        ClientAuthRegistry([ClientSecretPost(), ClientSecretPost()])


def test_the_metadata_overlay_may_not_declare_a_capability(tmp_path):
    with pytest.raises(ValueError, match="may not declare a capability"):
        Settings(
            issuer="http://127.0.0.1:9",
            key_directory=tmp_path,
            resource_audience="test-resource",
            metadata_overlay={"grant_types_supported": ["authorization_code"]},
        )


def test_the_metadata_overlay_carries_descriptive_values(tmp_path):
    settings = Settings(
        issuer="http://127.0.0.1:9",
        key_directory=tmp_path,
        resource_audience="test-resource",
        metadata_overlay={"service_documentation": "https://example.com/docs"},
    )

    assert settings.metadata_overlay["service_documentation"] == ("https://example.com/docs")


def test_an_unknown_grant_type_is_refused_before_client_authentication(
    integration_environment,
):
    """A bad grant must not reach the client registry.

    Dispatching first means an attacker cannot use an invented grant type to
    probe whether a client_id exists.
    """
    response = httpx.post(
        f"{integration_environment.authorization_server_url}/oauth/token",
        data={
            "grant_type": "magic_beans",
            "client_id": "reporting-agent",
            "client_secret": "deliberately-wrong-secret",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


def test_any_duplicated_form_field_is_refused_not_only_the_known_ones(
    integration_environment,
):
    """The duplicate rule covers every field, so a new grant inherits it."""
    response = httpx.post(
        f"{integration_environment.authorization_server_url}/oauth/token",
        content=(
            "grant_type=client_credentials&client_id=reporting-agent"
            "&client_secret=test-only-secret&scope=reports:read&scope=finance:read"
        ),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert "scope" in response.json()["error_description"]


def test_the_token_endpoint_documents_its_request_body(integration_environment):
    """Without this, the generated API page cannot exercise the endpoint."""
    spec = httpx.get(f"{integration_environment.authorization_server_url}/openapi.json").json()

    operation = spec["paths"]["/oauth/token"]["post"]
    schema = operation["requestBody"]["content"]["application/x-www-form-urlencoded"]["schema"]

    assert operation["requestBody"]["required"] is True
    titles = {variant["title"] for variant in schema["oneOf"]}
    assert titles == set(default_grant_registry().grant_types())
