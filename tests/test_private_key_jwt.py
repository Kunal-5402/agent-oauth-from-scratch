"""private_key_jwt: the client signs instead of sending a secret.

The refusals come first, because in an authorization server the interesting
behaviour is what it will not do.
"""

from __future__ import annotations

import httpx
import jwt
import pytest

from tests.conftest import ASSERTION_CLIENT_ID, REPORTING_SECRET, run_with_pool
from tests.oauth_client.assertions import build_assertion, generate_client_key

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


@pytest.fixture
def token_endpoint(integration_environment):
    return f"{integration_environment.authorization_server_url}/oauth/token"


@pytest.fixture
def audience(integration_environment):
    """What a correct assertion names. The issuer is also accepted."""
    return f"{integration_environment.authorization_server_url}/oauth/token"


def _post(url, assertion, *, grant_type="client_credentials", **extra):
    return httpx.post(
        url,
        data={
            "grant_type": grant_type,
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": assertion,
            **extra,
        },
    )


# ------------------------------------------------------------------ it works


def test_a_client_with_no_secret_can_obtain_a_token(
    integration_environment, token_endpoint, audience
):
    assertion = build_assertion(
        integration_environment.client_key,
        client_id=ASSERTION_CLIENT_ID,
        audience=audience,
    )

    response = _post(token_endpoint, assertion, scope="reports:read")

    assert response.status_code == 200
    payload = response.json()
    assert payload["scope"] == "reports:read"
    claims = jwt.decode(payload["access_token"], options={"verify_signature": False})
    assert claims["sub"] == "agent:assertion"
    assert claims["client_id"] == ASSERTION_CLIENT_ID


def test_the_issuer_is_also_an_acceptable_audience(integration_environment, token_endpoint):
    """RFC 7523 accepts any identifier naming this server. Both are in use."""
    assertion = build_assertion(
        integration_environment.client_key,
        client_id=ASSERTION_CLIENT_ID,
        audience=integration_environment.settings.issuer,
    )

    assert _post(token_endpoint, assertion, scope="reports:read").status_code == 200


def test_the_method_is_advertised(integration_environment):
    metadata = httpx.get(
        f"{integration_environment.authorization_server_url}/.well-known/oauth-authorization-server"
    ).json()

    assert "private_key_jwt" in metadata["token_endpoint_auth_methods_supported"]


def test_it_works_for_a_second_grant_without_touching_any_grant_module(
    integration_environment, token_endpoint, audience
):
    """The payoff of keeping authentication and grant type in separate registries.

    Adding one file under src/auth/ made the method available to every grant. If
    this ever needs a change inside a grant module, the separation has been lost.
    """
    from src.grants import default_grant_registry

    registered = default_grant_registry().grant_types()
    assert "client_credentials" in registered

    for grant_type in registered:
        assertion = build_assertion(
            integration_environment.client_key,
            client_id=ASSERTION_CLIENT_ID,
            audience=audience,
        )
        response = _post(token_endpoint, assertion, grant_type=grant_type, scope="reports:read")
        # Reaching the grant at all is the assertion. A grant with other
        # required parameters answers invalid_request, never invalid_client.
        assert response.status_code == 200 or response.json()["error"] != "invalid_client", (
            f"{grant_type} refused the authentication itself"
        )


# ------------------------------------------------------------------- refusals


def test_an_assertion_signed_by_an_unregistered_key_is_refused(token_endpoint, audience):
    stranger = generate_client_key(kid="client-key-1")  # same kid, wrong key

    assertion = build_assertion(stranger, client_id=ASSERTION_CLIENT_ID, audience=audience)

    response = _post(token_endpoint, assertion)
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_an_assertion_aimed_at_the_resource_server_is_refused(
    integration_environment, token_endpoint
):
    """The anti-replay property.

    If the resource audience were acceptable, a malicious resource server could
    replay an assertion it received and authenticate as the client.
    """
    assertion = build_assertion(
        integration_environment.client_key,
        client_id=ASSERTION_CLIENT_ID,
        audience=integration_environment.settings.resource_audience,
    )

    assert _post(token_endpoint, assertion).status_code == 401


def test_an_assertion_issued_by_a_different_client_is_refused(
    integration_environment, token_endpoint, audience
):
    assertion = build_assertion(
        integration_environment.client_key,
        client_id=ASSERTION_CLIENT_ID,
        audience=audience,
        issuer="reporting-agent",
    )

    assert _post(token_endpoint, assertion).status_code == 401


def test_the_same_assertion_cannot_be_used_twice(integration_environment, token_endpoint, audience):
    """Single use. Without it the assertion is a bearer credential until exp."""
    assertion = build_assertion(
        integration_environment.client_key,
        client_id=ASSERTION_CLIENT_ID,
        audience=audience,
    )

    first = _post(token_endpoint, assertion, scope="reports:read")
    second = _post(token_endpoint, assertion, scope="reports:read")

    assert first.status_code == 200
    assert second.status_code == 401
    assert second.json()["error"] == "invalid_client"


def test_a_long_lived_assertion_is_refused(integration_environment, token_endpoint, audience):
    assertion = build_assertion(
        integration_environment.client_key,
        client_id=ASSERTION_CLIENT_ID,
        audience=audience,
        lifetime_seconds=3600,
    )

    assert _post(token_endpoint, assertion).status_code == 401


def test_an_expired_assertion_is_refused(integration_environment, token_endpoint, audience):
    assertion = build_assertion(
        integration_environment.client_key,
        client_id=ASSERTION_CLIENT_ID,
        audience=audience,
        lifetime_seconds=-30,
    )

    assert _post(token_endpoint, assertion).status_code == 401


def test_an_hmac_assertion_forged_from_the_public_key_is_refused(
    integration_environment, token_endpoint, audience
):
    """Algorithm confusion, aimed at the client key this time."""
    key = integration_environment.client_key
    assertion = build_assertion(
        key,
        client_id=ASSERTION_CLIENT_ID,
        audience=audience,
        algorithm="HS256",
        signing_key=key.public_jwk["x"],
    )

    assert _post(token_endpoint, assertion).status_code == 401


def test_an_assertion_naming_an_unknown_kid_is_refused(
    integration_environment, token_endpoint, audience
):
    assertion = build_assertion(
        integration_environment.client_key,
        client_id=ASSERTION_CLIENT_ID,
        audience=audience,
        kid="a-kid-that-was-never-registered",
    )

    assert _post(token_endpoint, assertion).status_code == 401


def test_another_clients_key_cannot_authenticate_as_this_client(
    integration_environment, token_endpoint, audience
):
    """Keys are selected on (client_id, kid), never on kid alone.

    Two clients may legitimately register the same kid. Selecting on kid alone
    would let one client's assertion be verified with another's key.
    """
    from src.models import ClientKey
    from src.storage.repositories import ClientKeyRepository

    stranger = generate_client_key(kid=integration_environment.client_key.kid)

    async def _register(pool):
        await ClientKeyRepository(pool).add(
            ClientKey(
                client_id="reporting-agent",
                kid=stranger.kid,
                public_jwk=stranger.public_jwk,
            )
        )

    run_with_pool(_register)

    assertion = build_assertion(stranger, client_id=ASSERTION_CLIENT_ID, audience=audience)

    assert _post(token_endpoint, assertion).status_code == 401


def test_a_client_id_that_disagrees_with_the_assertion_is_refused(
    integration_environment, token_endpoint, audience
):
    """Never prefer an unsigned value over the signed one."""
    assertion = build_assertion(
        integration_environment.client_key,
        client_id=ASSERTION_CLIENT_ID,
        audience=audience,
    )

    response = _post(token_endpoint, assertion, client_id="reporting-agent")

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_an_assertion_and_a_client_secret_together_are_refused(
    integration_environment, token_endpoint, audience
):
    """Do not merge credential sources."""
    assertion = build_assertion(
        integration_environment.client_key,
        client_id=ASSERTION_CLIENT_ID,
        audience=audience,
    )

    response = httpx.post(
        token_endpoint,
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": assertion,
            "client_id": "reporting-agent",
            "client_secret": REPORTING_SECRET,
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_an_unsupported_assertion_type_is_refused(
    integration_environment, token_endpoint, audience
):
    assertion = build_assertion(
        integration_environment.client_key,
        client_id=ASSERTION_CLIENT_ID,
        audience=audience,
    )

    response = httpx.post(
        token_endpoint,
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:example:something-else",
            "client_assertion": assertion,
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_a_malformed_assertion_is_refused(token_endpoint):
    response = _post(token_endpoint, "this-is-not-a-jwt")

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_no_refusal_writes_a_credential(integration_environment, token_endpoint, audience):
    stranger = generate_client_key()

    _post(
        token_endpoint, build_assertion(stranger, client_id=ASSERTION_CLIENT_ID, audience=audience)
    )
    _post(token_endpoint, "not-a-jwt")
    _post(
        token_endpoint,
        build_assertion(
            integration_environment.client_key,
            client_id=ASSERTION_CLIENT_ID,
            audience="the-wrong-audience",
        ),
    )

    assert integration_environment.issued_credentials() == []
