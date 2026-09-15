"""The 2 verifiers must agree on every token.

The authorization server verifies locally, because it holds the key. A resource
server verifies from the published JWKS, over HTTP. They are deliberately
separate code, so the resource server stays a genuinely independent consumer
rather than a caller of server internals.

Separate code can drift. This file is what stops that: both verifiers see the
same tokens and must reach the same verdict. It fails the moment one of them
learns a rule the other does not.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from src.crypto.keys import KeyStore
from src.crypto.tokens import ACCESS_TOKEN_TYPE, TokenError, TokenMinter, TokenVerifier
from tests.resource_server.verifier import (
    AuthorizationServerVerifier,
    TokenValidationError,
)


def _forge(key, claims, *, headers=None, secret=None, algorithm="ES256"):
    return jwt.encode(
        claims,
        secret if secret is not None else key.private_key,
        algorithm=algorithm,
        headers={"kid": key.kid, "typ": ACCESS_TOKEN_TYPE, **(headers or {})},
    )


def _cases(environment, tmp_path):
    """Return (name, token, should_be_accepted) for each token worth checking."""
    settings = environment.settings
    key = environment.signing_key
    minter = TokenMinter(
        issuer=settings.issuer,
        signing_key=key,
        default_ttl_seconds=settings.access_token_ttl_seconds,
    )

    def claims(**overrides):
        now = datetime.now(UTC)
        base = {
            "iss": settings.issuer,
            "sub": "agent:reporting",
            "aud": settings.resource_audience,
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "jti": "parity-jti",
        }
        base.update(overrides)
        return base

    stranger = KeyStore(tmp_path / "stranger").load_or_create()

    return [
        (
            "a minted token",
            minter.mint({"sub": "agent:reporting", "aud": settings.resource_audience}).token,
            True,
        ),
        ("a hand-built valid token", _forge(key, claims()), True),
        ("a tampered signature", _forge(key, claims()) + "x", False),
        ("another audience", _forge(key, claims(aud="other-api")), False),
        ("another issuer", _forge(key, claims(iss="https://evil.test")), False),
        ("expired", _forge(key, claims(exp=datetime.now(UTC) - timedelta(seconds=1))), False),
        ("not an access token", _forge(key, claims(), headers={"typ": "JWT"}), False),
        ("signed by an unknown key", _forge(stranger, claims()), False),
        (
            "HS256 forged from the published key",
            _forge(
                key,
                claims(),
                secret=key.public_jwk()["x"],
                algorithm="HS256",
                headers={"alg": "HS256"},
            ),
            False,
        ),
        ("missing jti", _forge(key, {k: v for k, v in claims().items() if k != "jti"}), False),
        ("missing sub", _forge(key, {k: v for k, v in claims().items() if k != "sub"}), False),
        ("not a JWT at all", "not-a-jwt", False),
    ]


def test_both_verifiers_reach_the_same_verdict(integration_environment, tmp_path):
    settings = integration_environment.settings
    local = TokenVerifier(issuer=settings.issuer, signing_key=integration_environment.signing_key)
    remote = AuthorizationServerVerifier(settings.issuer, audience=settings.resource_audience)

    try:
        disagreements = []
        for name, token, should_accept in _cases(integration_environment, tmp_path):
            local_ok = _accepts(local.verify, token, settings.resource_audience, TokenError)
            remote_ok = _accepts(remote.validate, token, None, TokenValidationError)

            if local_ok != remote_ok:
                disagreements.append(
                    f"{name}: authorization server={local_ok}, resource server={remote_ok}"
                )
            elif local_ok is not should_accept:
                disagreements.append(f"{name}: both said {local_ok}, expected {should_accept}")
    finally:
        remote.close()

    assert not disagreements, "\n".join(disagreements)


def _accepts(verify, token, audience, error_type) -> bool:
    try:
        verify(token, audience=audience) if audience else verify(token)
    except error_type:
        return False
    except Exception as exc:  # any other error type is itself a defect
        pytest.fail(f"verifier raised {type(exc).__name__} instead of {error_type.__name__}: {exc}")
    return True
