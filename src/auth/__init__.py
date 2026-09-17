"""The registry of supported client authentication methods."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from src.api.forms import TokenForm
from src.auth.base import ClientAuthMethod, PresentedCredential
from src.auth.client_secret_post import ClientSecretPost
from src.auth.private_key_jwt import PrivateKeyJwt
from src.crypto.keys import SigningKey
from src.errors import OAuthError
from src.storage.repositories import AssertionReplayRepository, ClientKeyRepository

__all__ = [
    "ClientAuthMethod",
    "ClientAuthRegistry",
    "ClientSecretPost",
    "PresentedCredential",
    "PrivateKeyJwt",
    "default_client_auth_registry",
]


class ClientAuthRegistry:
    """Hold the installed authentication methods and pick the one in use."""

    def __init__(self, methods: Iterable[ClientAuthMethod]) -> None:
        installed = tuple(methods)
        self._methods = {method.name: method for method in installed}
        if len(self._methods) != len(installed):
            raise ValueError("client authentication method names must be unique")

    def names(self) -> frozenset[str]:
        """The value advertised as token_endpoint_auth_methods_supported."""
        return frozenset(self._methods)

    def all(self) -> tuple[ClientAuthMethod, ...]:
        return tuple(self._methods.values())

    def extract(
        self, headers: Mapping[str, str], form: TokenForm
    ) -> tuple[PresentedCredential, ClientAuthMethod]:
        """Return what the caller presented, and the method that will verify it."""
        found = [
            (presented, method)
            for method in self._methods.values()
            if (presented := method.extract(headers, form)) is not None
        ]

        # Do not merge credential sources. A caller presenting 2 is either
        # confused or probing for which one the server reads.
        if len(found) > 1:
            raise OAuthError(
                "invalid_request",
                "client credentials must be presented exactly once",
                400,
            )
        if not found:
            raise OAuthError("invalid_request", "missing required parameter: client_id", 400)
        return found[0]


def default_client_auth_registry(
    *,
    issuer: str,
    token_endpoint: str,
    keys: ClientKeyRepository,
    replays: AssertionReplayRepository,
    server_key: SigningKey,
) -> ClientAuthRegistry:
    """Every method this server supports today.

    Adding a method here is the only change needed: the discovery document reads
    the registry, and every grant that needs a client gets the new method at once.
    """
    return ClientAuthRegistry(
        [
            ClientSecretPost(),
            PrivateKeyJwt(
                issuer=issuer,
                token_endpoint=token_endpoint,
                keys=keys,
                replays=replays,
                server_key=server_key,
            ),
        ]
    )
