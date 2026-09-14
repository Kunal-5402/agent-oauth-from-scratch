"""Client-credentials authentication, scope attenuation, and JWT issuance."""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

from src.config import Settings
from src.crypto.keys import SigningKey


class OAuthError(Exception):
    """An OAuth error that can be safely converted to a protocol response."""

    def __init__(self, error: str, description: str, status_code: int) -> None:
        self.error = error
        self.description = description
        self.status_code = status_code
        super().__init__(description)


@dataclass(frozen=True)
class RegisteredClient:
    """A bootstrap client record; replace this with a database repository later."""

    client_id: str
    client_secret: str
    subject: str
    allowed_scopes: frozenset[str]

    def __post_init__(self) -> None:
        if not self.client_id or not self.client_secret or not self.subject:
            raise ValueError("client_id, client_secret, and subject must not be empty")


class ClientRegistry:
    """Immutable client lookup used by the first, database-free server slice."""

    # Compared against when the client ID is unknown, so both failure paths run
    # the same constant-time comparison. The value itself is never a secret.
    _ABSENT_CLIENT_SECRET = "absent-client-placeholder-secret"  # noqa: S105 - a public placeholder

    def __init__(self, clients: Iterable[RegisteredClient]) -> None:
        registered_clients = tuple(clients)
        self._clients = {client.client_id: client for client in registered_clients}
        if len(self._clients) != len(registered_clients):
            raise ValueError("client IDs must be unique")

    def authenticate(self, client_id: str, client_secret: str) -> RegisteredClient:
        client = self._clients.get(client_id)

        # Always compare a secret, even for an unknown client ID. An early
        # return there would make the response time enumerate valid client IDs.
        # Compare bytes, because compare_digest rejects non-ASCII text.
        expected_secret = client.client_secret if client is not None else self._ABSENT_CLIENT_SECRET
        secret_matches = secrets.compare_digest(
            client_secret.encode("utf-8"),
            expected_secret.encode("utf-8"),
        )

        if client is None or not secret_matches:
            # Do not distinguish an unknown ID from an incorrect secret.
            raise OAuthError("invalid_client", "client authentication failed", 401)
        return client

    def all(self) -> tuple[RegisteredClient, ...]:
        """Return registered clients for public metadata construction."""
        return tuple(self._clients.values())


@dataclass(frozen=True)
class IssuedToken:
    access_token: str
    expires_in: int
    scope: str


class TokenIssuer:
    """The single token-issuance chokepoint for currently supported grants."""

    def __init__(
        self,
        settings: Settings,
        signing_key: SigningKey,
        clients: ClientRegistry,
    ) -> None:
        self._settings = settings
        self._signing_key = signing_key
        self._clients = clients

    def issue_client_credentials(
        self,
        *,
        client_id: str,
        client_secret: str,
        requested_scope: str | None,
    ) -> IssuedToken:
        client = self._clients.authenticate(client_id, client_secret)
        requested_scopes = _parse_scope(requested_scope)
        granted_scopes = tuple(
            scope for scope in requested_scopes if scope in client.allowed_scopes
        )

        # Unknown scopes are dropped when at least one requested scope is valid,
        # as documented in the roadmap. A wholly unauthorized request is refused.
        if requested_scopes and not granted_scopes:
            raise OAuthError("invalid_scope", "none of the requested scopes are allowed", 400)

        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=self._settings.access_token_ttl_seconds)
        scope = " ".join(granted_scopes)
        claims = {
            "iss": self._settings.issuer,
            "sub": client.subject,
            "aud": self._settings.resource_audience,
            "iat": now,
            "exp": expires_at,
            "jti": secrets.token_urlsafe(24),
            "client_id": client.client_id,
        }
        if scope:
            claims["scope"] = scope

        token = jwt.encode(
            claims,
            self._signing_key.private_key,
            algorithm="ES256",
            headers={"kid": self._signing_key.kid, "typ": "at+jwt"},
        )
        return IssuedToken(
            access_token=token,
            expires_in=self._settings.access_token_ttl_seconds,
            scope=scope,
        )


def _parse_scope(value: str | None) -> tuple[str, ...]:
    """Parse OAuth's space-delimited scope string, retaining stable order."""
    if value is None or not value.strip():
        return ()

    scopes: list[str] = []
    for scope in value.split():
        if scope not in scopes:
            scopes.append(scope)
    return tuple(scopes)
