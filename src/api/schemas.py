"""Response schemas exposed by the authorization-server HTTP API."""

from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str | None = None


class OAuthErrorResponse(BaseModel):
    error: str
    error_description: str
