"""The server's own JWT boundary: one place that mints, one place that verifies.

Every grant reaches the signer through ``TokenMinter``. Every token the server
reads back, such as the ``subject_token`` of an exchange or a ``client_assertion``
from a client, goes through ``TokenVerifier``.

Two rules are held here rather than at each call site, because a call site can
forget and a chokepoint cannot:

* The caller never decides ``iss``, ``iat``, ``exp`` or ``jti``.
* The algorithm is never read from the token. It is an allow-list of one.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from src.crypto.keys import SigningKey

ALGORITHM = "ES256"
ACCESS_TOKEN_TYPE = "at+jwt"  # noqa: S105 - the RFC 9068 media type, not a credential

# Claims the server owns. A caller that supplies one is a bug, not a request.
MINTER_OWNED_CLAIMS = frozenset({"iss", "iat", "exp", "jti"})

# Claims every access token this server issues must carry.
REQUIRED_CLAIMS = ("iss", "sub", "aud", "iat", "exp", "jti")


class TokenError(Exception):
    """A token could not be minted, or could not be trusted."""


@dataclass(frozen=True)
class MintedToken:
    token: str
    claims: dict[str, Any]
    expires_in: int


class TokenMinter:
    """The only path to a signature. Grants supply claims; it supplies the rest."""

    def __init__(
        self,
        *,
        issuer: str,
        signing_key: SigningKey,
        default_ttl_seconds: int,
    ) -> None:
        self._issuer = issuer
        self._signing_key = signing_key
        self._default_ttl_seconds = default_ttl_seconds

    def mint(
        self,
        claims: dict[str, Any],
        *,
        ttl_seconds: int | None = None,
        not_after: datetime | None = None,
    ) -> MintedToken:
        """Sign an access token.

        ``not_after`` is shrink rule 4 expressed as a parameter: a derived token
        must never outlive the token it came from. Putting the ``min()`` here
        means a grant cannot skip it by forgetting to apply it.
        """
        supplied = MINTER_OWNED_CLAIMS & set(claims)
        if supplied:
            raise TokenError("the caller may not set " + ", ".join(sorted(supplied)))

        now = datetime.now(UTC)
        expires_at = now + timedelta(
            seconds=ttl_seconds if ttl_seconds is not None else self._default_ttl_seconds
        )
        if not_after is not None:
            expires_at = min(expires_at, not_after)

        remaining = int((expires_at - now).total_seconds())
        if remaining <= 0:
            raise TokenError("the requested lifetime has already elapsed")

        full_claims: dict[str, Any] = {
            "iss": self._issuer,
            "iat": now,
            "exp": expires_at,
            "jti": secrets.token_urlsafe(24),
            **claims,
        }
        token = jwt.encode(
            full_claims,
            self._signing_key.private_key,
            algorithm=ALGORITHM,
            headers={"kid": self._signing_key.kid, "typ": ACCESS_TOKEN_TYPE},
        )
        return MintedToken(token=token, claims=full_claims, expires_in=remaining)


class TokenVerifier:
    """Verify a token this server issued.

    A resource server does the same job from the published JWKS, over HTTP. This
    one is local: the authorization server already holds the key. The 2 are kept
    as separate code on purpose, so the resource server stays a genuinely
    independent consumer rather than a caller of server internals. A parity test
    keeps them from drifting.
    """

    def __init__(self, *, issuer: str, signing_key: SigningKey) -> None:
        self._issuer = issuer
        self._signing_key = signing_key

    def verify_any_audience(self, token: str) -> dict[str, Any]:
        """Verify everything except which audience the token names.

        A token being exchanged was issued for where it is now, not for where it
        is going, so the exchange cannot predict its ``aud``. Issuer, algorithm,
        key, type, expiry and the required claims are all still checked, and
        ``aud`` must still be present.
        """
        return self._verify(token, audience=None)

    def verify(self, token: str, *, audience: str) -> dict[str, Any]:
        """Return the claims, or raise. Never returns an unverified value."""
        return self._verify(token, audience=audience)

    def _verify(self, token: str, *, audience: str | None) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise TokenError("token header is malformed") from exc

        # Read the header only to REJECT, never to choose how to verify.
        if header.get("alg") != ALGORITHM:
            raise TokenError("unsupported token algorithm")
        if header.get("typ") != ACCESS_TOKEN_TYPE:
            raise TokenError("token is not an access token")
        if header.get("kid") != self._signing_key.kid:
            raise TokenError("token was not signed by the active key")

        try:
            return jwt.decode(
                token,
                self._signing_key.public_key,
                algorithms=[ALGORITHM],
                issuer=self._issuer,
                audience=audience,
                options={
                    "require": list(REQUIRED_CLAIMS),
                    "verify_aud": audience is not None,
                },
            )
        except jwt.InvalidTokenError as exc:
            # One message for every failure. A caller probing with forged tokens
            # learns nothing about which field it got closest on.
            raise TokenError("token validation failed") from exc
