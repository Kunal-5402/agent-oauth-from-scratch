"""Response schemas exposed by the authorization-server HTTP API."""

from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"  # noqa: S105 - an OAuth token type, not a credential
    expires_in: int
    scope: str | None = None


class TokenExchangeResponse(TokenResponse):
    """RFC 8693 section 2.2.1 requires issued_token_type.

    It is easy to forget, because the response otherwise looks exactly like an
    ordinary token response. ``token_type`` says how to PRESENT the credential.
    ``issued_token_type`` says what the credential IS. They answer different
    questions and a client needs both.
    """

    issued_token_type: str


class OAuthErrorResponse(BaseModel):
    error: str
    error_description: str
