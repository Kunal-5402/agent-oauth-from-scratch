"""Uvicorn entry point: ``make run``, or ``uv run uvicorn src.main:app``."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.api.routes import create_app
from src.config import Settings, settings_from_environment
from src.crypto.keys import KeyStore
from src.services.clients import ClientRegistry, RegisteredClient
from src.storage.database import create_pool, migrate
from src.storage.repositories import (
    AssertionReplayRepository,
    ClientKeyRepository,
    ClientRepository,
    IssuedCredentialRepository,
)
from src.storage.secrets import hash_secret


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} must be configured before starting the authorization server")
    return value


def _bootstrap_client() -> RegisteredClient:
    """The first-run seed client. This is a convenience, not a client registry.

    The stored row is the source of truth. These variables only decide what to
    write the first time, so a fresh checkout has something to authenticate as.
    """
    return RegisteredClient(
        client_id=_required_environment("OAUTH_CLIENT_ID"),
        subject=_required_environment("OAUTH_CLIENT_SUBJECT"),
        secret_hash=hash_secret(_required_environment("OAUTH_CLIENT_SECRET")),
        allowed_scopes=frozenset(os.environ.get("OAUTH_CLIENT_SCOPES", "").split()),
        allowed_audiences=frozenset(os.environ.get("OAUTH_CLIENT_AUDIENCES", "").split()),
    )


def build_application(settings: Settings) -> FastAPI:
    pool = create_pool(settings.database_url)
    clients = ClientRepository(pool)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await pool.open()
        async with pool.connection() as connection:
            await migrate(connection)
        await clients.upsert(_bootstrap_client())
        yield
        await pool.close()

    application = create_app(
        settings=settings,
        signing_key=KeyStore(settings.key_directory).load_or_create(),
        clients=ClientRegistry(clients),
        credentials=IssuedCredentialRepository(pool),
        client_keys=ClientKeyRepository(pool),
        replays=AssertionReplayRepository(pool),
        lifespan=lifespan,
    )
    return application


app = build_application(settings_from_environment())
