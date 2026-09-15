"""Strict reading of the token endpoint's request body.

One form body is read. Query parameters never reach a grant, and no field may
appear twice. Both rules exist so a caller cannot send 2 values for one
security-relevant parameter and hope the server reads the wrong one.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from fastapi import Request

from src.errors import OAuthError

FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"


@dataclass(frozen=True)
class TokenForm:
    """The validated fields of one token request."""

    fields: Mapping[str, str]

    @property
    def grant_type(self) -> str:
        return self.fields["grant_type"]

    def get(self, name: str) -> str | None:
        return self.fields.get(name)

    def require(self, name: str) -> str:
        value = self.fields.get(name)
        if not value:
            raise OAuthError("invalid_request", f"missing required parameter: {name}", 400)
        return value

    def present(self, name: str) -> bool:
        return name in self.fields


async def read_token_form(request: Request) -> TokenForm:
    """Read one form body only; query parameters never affect token issuance."""
    content_type = request.headers.get("content-type", "")
    if not content_type.lower().startswith(FORM_CONTENT_TYPE):
        raise OAuthError(
            "invalid_request",
            f"content type must be {FORM_CONTENT_TYPE}",
            400,
        )

    form = await request.form()

    # Every field is checked for duplicates, not only the fields this server
    # happens to know about today. A grant added later then inherits the rule
    # instead of having to remember it.
    fields: dict[str, str] = {}
    for name in set(form.keys()):
        values = form.getlist(name)
        if len(values) > 1:
            raise OAuthError("invalid_request", f"{name} must appear at most once", 400)
        value = values[0]
        if not isinstance(value, str):
            raise OAuthError("invalid_request", f"{name} must be text", 400)
        fields[name] = value

    if not fields.get("grant_type"):
        raise OAuthError("invalid_request", "missing required parameter: grant_type", 400)
    return TokenForm(fields=fields)
