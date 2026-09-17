"""RFC 6749 section 4.4. The client acts for itself; there is no human."""

from __future__ import annotations

import secrets

from src.api.forms import TokenForm
from src.grants.base import GrantResult
from src.models import RegisteredClient
from src.services.scopes import parse_scope


class ClientCredentialsGrant:
    grant_type = "client_credentials"
    requires_client_auth = True
    response_types = frozenset()

    async def resolve(self, form: TokenForm, client: RegisteredClient | None) -> GrantResult:
        assert client is not None  # noqa: S101 - requires_client_auth guarantees it
        return GrantResult(
            subject=client.subject,
            client_id=client.client_id,
            requested_scopes=parse_scope(form.get("scope")),
            principal_status=client.status,
            # A root grant starts a tree of work. Every token derived from
            # this one copies the task unchanged, so phase 6 can stop the
            # whole task or one branch of it.
            task_id=secrets.token_urlsafe(12),
            # The client registration is the ONLY ceiling here. There is no
            # human and no delegation chain underneath it, which is why an
            # empty allow-list has to mean zero rather than "unrestricted".
            ceilings=(client.allowed_scopes,),
        )

    def metadata(self, settings: object) -> dict[str, object]:
        return {}

    def openapi_schema(self) -> dict[str, object]:
        return {
            "title": self.grant_type,
            "type": "object",
            "required": ["grant_type", "client_id", "client_secret"],
            "properties": {
                "grant_type": {"type": "string", "enum": [self.grant_type]},
                "client_id": {"type": "string"},
                "client_secret": {"type": "string", "format": "password"},
                "scope": {
                    "type": "string",
                    "description": "Space delimited. Intersected with the client ceiling.",
                },
            },
        }
