"""A client-side signer for private_key_jwt.

This lives with the OAuth client rather than the server, because it is what a
real client does: hold a private key the server never sees, and sign a fresh
assertion per request.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from cryptography.hazmat.primitives.asymmetric import ec


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class ClientKeyPair:
    """A client's key. Only ``public_jwk`` is ever given to the server."""

    private_key: ec.EllipticCurvePrivateKey
    kid: str

    @property
    def public_jwk(self) -> dict[str, str]:
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _base64url(numbers.x.to_bytes(32, "big")),
            "y": _base64url(numbers.y.to_bytes(32, "big")),
            "kid": self.kid,
            "use": "sig",
            "alg": "ES256",
        }


def generate_client_key(kid: str = "client-key-1") -> ClientKeyPair:
    return ClientKeyPair(private_key=ec.generate_private_key(ec.SECP256R1()), kid=kid)


def build_assertion(
    key: ClientKeyPair,
    *,
    client_id: str,
    audience: str,
    lifetime_seconds: int = 60,
    jti: str | None = None,
    issuer: str | None = None,
    subject: str | None = None,
    algorithm: str = "ES256",
    signing_key: object | None = None,
    kid: str | None = None,
) -> str:
    """Sign one assertion. Every argument can be wrong on purpose, for tests."""
    now = datetime.now(UTC)
    claims = {
        "iss": issuer if issuer is not None else client_id,
        "sub": subject if subject is not None else client_id,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(seconds=lifetime_seconds),
        "jti": jti or secrets.token_urlsafe(16),
    }
    return jwt.encode(
        claims,
        signing_key if signing_key is not None else key.private_key,
        algorithm=algorithm,
        headers={"kid": kid if kid is not None else key.kid},
    )
