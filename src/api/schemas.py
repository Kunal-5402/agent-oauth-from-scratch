"""Response schemas exposed by the authorization-server HTTP API."""

from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"  # noqa: S105 - an OAuth token type, not a credential
    expires_in: int
    scope: str | None = None


class OAuthErrorResponse(BaseModel):
    error: str
    error_description: str
