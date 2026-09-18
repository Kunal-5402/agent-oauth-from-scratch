"""RFC 7523 section 2.2: the client signs an assertion instead of sending a secret.

A shared secret has to exist in 2 places, so it can leak from either. This method
removes the shared secret entirely: the server stores only a public key, and a
database dump grants nothing.

The client sends::

    client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    client_assertion=<a JWT signed with the client's private key>
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import jwt

from src.api.forms import TokenForm
from src.auth.base import PresentedCredential
from src.crypto.keys import SigningKey
from src.errors import OAuthError
from src.models import RegisteredClient
from src.storage.repositories import AssertionReplayRepository, ClientKeyRepository

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
ALGORITHM = "ES256"

# An assertion is a proof of possession made moments before it is sent. A long
# window turns it into a credential worth stealing.
MAXIMUM_LIFETIME = timedelta(minutes=5)


class PrivateKeyJwt:
    name = "private_key_jwt"

    def __init__(
        self,
        *,
        issuer: str,
        token_endpoint: str,
        keys: ClientKeyRepository,
        replays: AssertionReplayRepository,
        server_key: SigningKey,
    ) -> None:
        self._issuer = issuer
        self._token_endpoint = token_endpoint
        self._keys = keys
        self._replays = replays
        # Used only to burn comparable time when a client does not exist.
        self._server_key = server_key

    # ------------------------------------------------------------------ extract

    def extract(self, headers: Mapping[str, str], form: TokenForm) -> PresentedCredential | None:
        if not form.present("client_assertion") and not form.present("client_assertion_type"):
            return None

        assertion_type = form.require("client_assertion_type")
        if assertion_type != ASSERTION_TYPE:
            raise OAuthError("invalid_request", "unsupported client assertion type", 400)
        assertion = form.require("client_assertion")

        # The client_id lives inside the signed assertion. A form client_id is
        # allowed, and must agree: reading an unsigned value in preference to a
        # signed one is how a caller ends up authenticated as somebody else.
        claimed = self._unverified_subject(assertion)
        if form.present("client_id") and form.get("client_id") != claimed:
            raise OAuthError(
                "invalid_request", "client_id does not match the client assertion", 400
            )

        return PresentedCredential(client_id=claimed, assertion=assertion, method=self.name)

    @staticmethod
    def _unverified_subject(assertion: str) -> str:
        """Read ``sub`` without trusting it, only to know which key to fetch.

        Nothing is decided on this value. It selects a candidate key, and the
        signature check that follows is what makes it true.
        """
        try:
            claims = jwt.decode(assertion, options={"verify_signature": False})
        except jwt.InvalidTokenError as exc:
            raise OAuthError("invalid_request", "client assertion is malformed", 400) from exc
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise OAuthError("invalid_request", "client assertion has no subject", 400)
        return subject

    # ------------------------------------------------------------------- verify

    async def verify(self, presented: PresentedCredential, client: RegisteredClient | None) -> bool:
        assertion = presented.assertion or ""

        try:
            header = jwt.get_unverified_header(assertion)
        except jwt.InvalidTokenError:
            return False

        # Read the header only to reject. Never to choose how to verify.
        if header.get("alg") != ALGORITHM:
            return False
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            return False

        if client is None:
            # Verify against the server's own public key so an unknown client
            # costs roughly what a real signature check costs. It is an
            # approximation of constant time, not a guarantee, because only the
            # signature step is matched. It is still far better than returning
            # immediately, which would make client IDs enumerable by timing.
            self._burn_a_signature_check(assertion)
            return False

        key = await self._keys.get(client.client_id, kid)
        if key is None:
            self._burn_a_signature_check(assertion)
            return False

        try:
            claims = jwt.decode(
                assertion,
                jwt.PyJWK.from_dict(key.public_jwk).key,
                algorithms=[ALGORITHM],
                # aud is checked below, against 2 acceptable values.
                options={"require": ["iss", "sub", "aud", "exp", "jti"], "verify_aud": False},
            )
        except (jwt.InvalidTokenError, jwt.PyJWKError):
            return False

        return self._claims_are_acceptable(claims, client) and await self._is_first_use(claims)

    def _claims_are_acceptable(self, claims: dict, client: RegisteredClient) -> bool:
        if claims.get("iss") != client.client_id or claims.get("sub") != client.client_id:
            return False

        # The audience must name THIS server. If it named the resource server, a
        # malicious resource server could replay an assertion it received and
        # authenticate as the client. RFC 7523 allows either the issuer
        # identifier or the endpoint URL; both identify this server.
        audience = claims.get("aud")
        accepted = {self._issuer, self._token_endpoint}
        values = set(audience) if isinstance(audience, list) else {audience}
        if not values & accepted:
            return False

        expires_at = datetime.fromtimestamp(claims["exp"], tz=UTC)
        return expires_at - datetime.now(UTC) <= MAXIMUM_LIFETIME

    async def _is_first_use(self, claims: dict) -> bool:
        """Single use, decided by the database rather than by this process."""
        return await self._replays.claim(
            client_id=claims["sub"],
            jti=str(claims["jti"]),
            expires_at=datetime.fromtimestamp(claims["exp"], tz=UTC),
        )

    def _burn_a_signature_check(self, assertion: str) -> None:
        # The result is discarded on purpose. Only the elapsed time matters.
        with contextlib.suppress(Exception):
            jwt.decode(assertion, self._server_key.public_key, algorithms=[ALGORITHM])

    # ------------------------------------------------------------------ openapi

    def openapi_properties(self) -> dict[str, dict[str, object]]:
        return {
            "client_assertion_type": {"type": "string", "enum": [ASSERTION_TYPE]},
            "client_assertion": {"type": "string"},
        }

    def required_openapi_fields(self) -> tuple[str, ...]:
        return ("client_assertion_type", "client_assertion")
