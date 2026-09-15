"""The client record and the lookup used by the database-free first slice."""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from dataclasses import dataclass

from src.errors import OAuthError


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
