"""What the database has to guarantee.

The interesting property is not that a row appears. It is the ORDER: a token
that could not be recorded must never reach anybody, because phase 6 cannot
revoke what it cannot find.
"""

from __future__ import annotations

import httpx
import jwt
import pytest

from src.auth import ClientSecretPost
from src.auth.base import PresentedCredential
from src.models import RegisteredClient
from src.services.clients import ClientRegistry
from src.storage.repositories import ClientRepository, IssuedCredentialRepository
from tests.conftest import REPORTING_SECRET, SUSPENDED_SECRET, run_with_pool


def _claims(access_token: str) -> dict:
    return jwt.decode(access_token, options={"verify_signature": False})


def test_the_issuance_record_matches_the_token_that_was_handed_out(
    integration_environment,
):
    response = integration_environment.oauth_client.client_credentials(
        client_id="reporting-agent",
        client_secret=REPORTING_SECRET,
        scope="reports:read",
    )
    assert response.status_code == 200
    claims = _claims(response.json()["access_token"])

    row = integration_environment.credential(claims["jti"])

    assert row is not None
    assert row["client_id"] == claims["client_id"]
    assert row["subject"] == claims["sub"]
    assert row["audience"] == claims["aud"]
    assert row["scope"] == claims["scope"]
    assert int(row["issued_at"].timestamp()) == claims["iat"]
    assert int(row["expires_at"].timestamp()) == claims["exp"]
    # Recorded from the first issuance because it cannot be added later.
    assert row["root_subject"] == claims["sub"]
    assert row["delegation_depth"] == 0
    assert row["revoked_at"] is None


def test_a_token_that_cannot_be_recorded_is_never_handed_out(integration_environment, monkeypatch):
    """The ordering test.

    Asserting only that a row appears passes under BOTH orderings, because by
    the time the assertion runs the record-after-respond path has caught up.
    Forcing the write to fail is the only way to observe the crash window.
    """

    async def _explode(self, issuance):
        raise RuntimeError("the database is unreachable")

    monkeypatch.setattr(IssuedCredentialRepository, "record", _explode)

    before = len(integration_environment.issued_credentials())
    response = httpx.post(
        f"{integration_environment.authorization_server_url}/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "reporting-agent",
            "client_secret": REPORTING_SECRET,
            "scope": "reports:read",
        },
    )

    assert response.status_code >= 500
    assert "access_token" not in response.text
    assert len(integration_environment.issued_credentials()) == before


def test_every_issuance_gets_its_own_row(integration_environment):
    for _ in range(5):
        integration_environment.oauth_client.client_credentials(
            client_id="reporting-agent",
            client_secret=REPORTING_SECRET,
            scope="reports:read",
        )

    rows = integration_environment.issued_credentials()

    assert len(rows) == 5
    assert len({row["jti"] for row in rows}) == 5


def test_a_suspended_client_authenticates_and_is_then_refused(integration_environment):
    """Authenticating and being allowed to act are 2 different questions.

    The registry accepts the secret, because it is correct. The pipeline refuses
    at step 3. Folding the 2 together would mean a future grant could satisfy
    one by satisfying the other.
    """

    async def _authenticate(pool):
        registry = ClientRegistry(ClientRepository(pool))
        method = ClientSecretPost()
        presented = PresentedCredential(
            client_id="suspended-agent", secret=SUSPENDED_SECRET, method=method.name
        )
        return await registry.authenticate(presented, method)

    authenticated = run_with_pool(_authenticate)
    assert authenticated.client_id == "suspended-agent"
    assert authenticated.status == "suspended"

    response = httpx.post(
        f"{integration_environment.authorization_server_url}/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "suspended-agent",
            "client_secret": SUSPENDED_SECRET,
            "scope": "reports:read",
        },
    )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"
    assert integration_environment.issued_credentials() == []


def test_no_client_secret_is_stored_in_plain_text(integration_environment):
    async def _read(pool):
        async with pool.connection() as connection:
            result = await connection.execute("SELECT client_id, secret_hash FROM clients")
            return await result.fetchall()

    rows = run_with_pool(_read)

    assert rows
    for client_id, secret_hash in rows:
        if secret_hash is None:
            # A private_key_jwt client holds no secret at all, which is the
            # strongest version of this property: nothing to leak.
            continue
        assert secret_hash.startswith("$argon2"), client_id
        assert REPORTING_SECRET not in secret_hash
        assert SUSPENDED_SECRET not in secret_hash

    assert any(secret_hash is None for _, secret_hash in rows), (
        "expected at least one secretless client, or this test proves less than it looks"
    )


def test_a_suspended_client_is_refused_before_anything_is_signed(
    integration_environment,
):
    response = httpx.post(
        f"{integration_environment.authorization_server_url}/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "suspended-agent",
            "client_secret": SUSPENDED_SECRET,
        },
    )

    assert response.status_code == 401
    assert integration_environment.issued_credentials() == []


@pytest.mark.parametrize(
    ("client_id", "secret"),
    [
        ("reporting-agent", "wrong-secret"),
        ("no-such-client", REPORTING_SECRET),
    ],
)
def test_a_failed_authentication_records_nothing(integration_environment, client_id, secret):
    response = httpx.post(
        f"{integration_environment.authorization_server_url}/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
        },
    )

    assert response.status_code == 401
    assert integration_environment.issued_credentials() == []


def test_a_client_row_survives_a_restart_of_the_registry(integration_environment):
    async def _add(pool):
        await ClientRepository(pool).upsert(
            RegisteredClient(
                client_id="late-arrival",
                subject="agent:late",
                secret_hash="$argon2id$v=19$m=65536,t=3,p=4$placeholder",
                allowed_scopes=frozenset({"reports:read"}),
            )
        )

    async def _read_back(pool):
        return await ClientRepository(pool).get("late-arrival")

    run_with_pool(_add)
    found = run_with_pool(_read_back)

    assert found is not None
    assert found.subject == "agent:late"
    assert found.allowed_scopes == frozenset({"reports:read"})
