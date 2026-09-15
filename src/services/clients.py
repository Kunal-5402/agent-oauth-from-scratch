"""Authentication against the stored client registry."""

from __future__ import annotations

from src.errors import OAuthError
from src.models import ACTIVE, SUSPENDED, RegisteredClient
from src.storage.repositories import ClientRepository
from src.storage.secrets import verify_secret

__all__ = ["ACTIVE", "SUSPENDED", "ClientRegistry", "RegisteredClient"]


class ClientRegistry:
    """Authentication only. Whether a client may still act is step 3, not here."""

    def __init__(self, repository: ClientRepository) -> None:
        self._repository = repository

    async def authenticate(self, client_id: str, client_secret: str) -> RegisteredClient:
        client = await self._repository.get(client_id)

        # verify_secret runs a full argon2 verification even when the client is
        # unknown, so an unknown ID and a wrong secret cost the same. An early
        # return here would let the response time enumerate valid client IDs.
        if not verify_secret(client_secret, client.secret_hash if client else None):
            # Never distinguish an unknown ID from an incorrect secret.
            raise OAuthError("invalid_client", "client authentication failed", 401)

        assert client is not None  # noqa: S101 - verify_secret returns False when absent
        return client

    async def all(self) -> tuple[RegisteredClient, ...]:
        """Every client, for building the public metadata document."""
        return await self._repository.all()
