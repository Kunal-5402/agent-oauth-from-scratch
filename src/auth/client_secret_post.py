"""RFC 6749 section 2.3.1 credentials in the request body.

This method is OPTIONAL in the specification, and NOT RECOMMENDED, because a
form body reaches application logs far more often than an Authorization header
does. ``client_secret_basic`` is the method a server must support; it is
tracked separately.
"""

from __future__ import annotations

from collections.abc import Mapping

from src.api.forms import TokenForm
from src.auth.base import PresentedCredential
from src.models import RegisteredClient
from src.storage.secrets import verify_secret


class ClientSecretPost:
    name = "client_secret_post"

    def extract(self, headers: Mapping[str, str], form: TokenForm) -> PresentedCredential | None:
        if not form.present("client_id") and not form.present("client_secret"):
            return None

        # A partial attempt is an error, not an absence. Reporting the missing
        # field keeps the existing contract for a caller that forgot one half.
        return PresentedCredential(
            client_id=form.require("client_id"),
            secret=form.require("client_secret"),
            method=self.name,
        )

    async def verify(self, presented: PresentedCredential, client: RegisteredClient | None) -> bool:
        # verify_secret runs a full argon2 verification against a placeholder
        # when there is no client, so an unknown ID costs what a wrong secret
        # costs. An early return here would restore the timing side channel.
        return verify_secret(presented.secret or "", client.secret_hash if client else None)

    def openapi_properties(self) -> dict[str, dict[str, str]]:
        return {
            "client_id": {"type": "string"},
            "client_secret": {"type": "string", "format": "password"},
        }

    def required_openapi_fields(self) -> tuple[str, ...]:
        return ("client_id", "client_secret")
