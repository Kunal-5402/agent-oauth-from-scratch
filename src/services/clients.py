"""Authentication against the stored client registry."""

from __future__ import annotations

from src.auth.base import ClientAuthMethod, PresentedCredential
from src.errors import OAuthError
from src.models import ACTIVE, SUSPENDED, RegisteredClient
from src.storage.repositories import ClientRepository

__all__ = ["ACTIVE", "SUSPENDED", "ClientRegistry", "RegisteredClient"]


class ClientRegistry:
    """Authentication only. Whether a client may still act is step 3, not here."""

    def __init__(self, repository: ClientRepository) -> None:
        self._repository = repository

    async def authenticate(
        self, presented: PresentedCredential, method: ClientAuthMethod
    ) -> RegisteredClient:
        """Look the client up, let the method judge the proof, refuse uniformly.

        Only the method knows what a valid proof looks like. Only this function
        decides what to say when it is not, and it says the same thing whether
        the client was unknown, the secret wrong, or the assertion replayed.
        """
        client = await self._repository.get(presented.client_id)

        # Every method does comparable work for a missing client, so an unknown
        # client ID costs what a wrong proof costs and cannot be found by timing.
        if not await method.verify(presented, client):
            raise OAuthError("invalid_client", "client authentication failed", 401)

        assert client is not None  # noqa: S101 - verify returns False when absent
        return client

    async def all(self) -> tuple[RegisteredClient, ...]:
        """Every client, for building the public metadata document."""
        return await self._repository.all()
