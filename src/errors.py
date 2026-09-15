"""The one OAuth error type, shared by every layer that can refuse a request."""

from __future__ import annotations


class OAuthError(Exception):
    """An OAuth error that can be safely converted to a protocol response."""

    def __init__(self, error: str, description: str, status_code: int) -> None:
        self.error = error
        self.description = description
        self.status_code = status_code
        super().__init__(description)
