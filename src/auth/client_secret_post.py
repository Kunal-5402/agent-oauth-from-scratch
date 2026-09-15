"""RFC 6749 section 2.3.1 credentials in the request body.

This method is OPTIONAL in the specification, and NOT RECOMMENDED, because a
form body reaches application logs far more often than an Authorization header
does. ``client_secret_basic`` is the method a server must support; it is
tracked separately.
"""

from __future__ import annotations

from collections.abc import Mapping

from src.api.forms import TokenForm
from src.auth.base import ClientCredentials


class ClientSecretPost:
    name = "client_secret_post"

    def extract(self, headers: Mapping[str, str], form: TokenForm) -> ClientCredentials | None:
        if not form.present("client_id") and not form.present("client_secret"):
            return None

        # A partial attempt is an error, not an absence. Reporting the missing
        # field keeps the existing contract for a caller that forgot one half.
        client_id = form.require("client_id")
        client_secret = form.require("client_secret")
        return ClientCredentials(client_id=client_id, client_secret=client_secret, method=self.name)

    def openapi_properties(self) -> dict[str, dict[str, str]]:
        return {
            "client_id": {"type": "string"},
            "client_secret": {"type": "string", "format": "password"},
        }

    def required_openapi_fields(self) -> tuple[str, ...]:
        return ("client_id", "client_secret")
