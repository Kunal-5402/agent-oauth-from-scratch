"""Uvicorn entry point: ``uv run uvicorn src.main:app --reload``."""

from __future__ import annotations

import os

from src.api.routes import create_app
from src.config import settings_from_environment
from src.crypto.keys import KeyStore
from src.services.clients import ClientRegistry, RegisteredClient


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} must be configured before starting the authorization server")
    return value


def application_from_environment():
    """Build the deployed app from environment-injected bootstrap credentials."""
    settings = settings_from_environment()
    client = RegisteredClient(
        client_id=_required_environment("OAUTH_CLIENT_ID"),
        client_secret=_required_environment("OAUTH_CLIENT_SECRET"),
        subject=_required_environment("OAUTH_CLIENT_SUBJECT"),
        allowed_scopes=frozenset(os.environ.get("OAUTH_CLIENT_SCOPES", "").split()),
    )
    return create_app(
        settings=settings,
        signing_key=KeyStore(settings.key_directory).load_or_create(),
        clients=ClientRegistry([client]),
    )


app = application_from_environment()
