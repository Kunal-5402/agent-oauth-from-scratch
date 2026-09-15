"""The registry of supported client authentication methods."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from src.api.forms import TokenForm
from src.auth.base import ClientAuthMethod, ClientCredentials
from src.auth.client_secret_post import ClientSecretPost
from src.errors import OAuthError

__all__ = [
    "ClientAuthMethod",
    "ClientAuthRegistry",
    "ClientCredentials",
    "ClientSecretPost",
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

    def extract(self, headers: Mapping[str, str], form: TokenForm) -> ClientCredentials:
        """Return the single set of credentials the caller presented."""
        found = [
            credentials
            for method in self._methods.values()
            if (credentials := method.extract(headers, form)) is not None
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


def default_client_auth_registry() -> ClientAuthRegistry:
    return ClientAuthRegistry([ClientSecretPost()])
