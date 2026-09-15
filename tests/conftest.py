from __future__ import annotations

import asyncio
import os
import socket
import threading
import time
from collections.abc import Awaitable, Callable, Generator
from dataclasses import dataclass
from typing import Any, TypeVar

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from psycopg_pool import AsyncConnectionPool

from src.api.routes import create_app
from src.config import Settings
from src.crypto.keys import KeyStore, SigningKey
from src.services.clients import ClientRegistry, RegisteredClient
from src.storage.database import create_pool, migrate, reset
from src.storage.repositories import ClientRepository, IssuedCredentialRepository
from src.storage.secrets import hash_secret
from tests.oauth_client.client import OAuthClient
from tests.resource_server.app import create_resource_server

# Never falls back to the development database, and never skips when absent.
# A skipped database test is a green build that proved nothing.
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql://oauth:oauth@127.0.0.1:5433/oauth_test"
)

REPORTING_SECRET = "test-only-secret"
NO_AUTHORITY_SECRET = "test-only-empty-scope-secret"
SUSPENDED_SECRET = "test-only-suspended-secret"

T = TypeVar("T")


def run_with_pool(work: Callable[[AsyncConnectionPool], Awaitable[T]]) -> T:
    """Run one piece of database work on its own pool and loop.

    The server's pool belongs to uvicorn's event loop, in another thread. A pool
    cannot be shared across loops, so the tests open their own. That is also
    what a real deployment looks like: 2 processes, one database.
    """

    async def _run() -> T:
        pool = create_pool(TEST_DATABASE_URL)
        await pool.open()
        try:
            return await work(pool)
        finally:
            await pool.close()

    return asyncio.run(_run())


@dataclass(frozen=True)
class IntegrationEnvironment:
    authorization_server_url: str
    resource_server_url: str
    settings: Settings
    signing_key: SigningKey
    oauth_client: OAuthClient

    def issued_credentials(self) -> list[dict[str, Any]]:
        """Every row the server has recorded, newest last."""

        async def _read(pool: AsyncConnectionPool) -> list[dict[str, Any]]:
            from psycopg.rows import dict_row

            async with pool.connection() as connection:
                connection.row_factory = dict_row
                result = await connection.execute(
                    "SELECT * FROM issued_credentials ORDER BY issued_at, jti"
                )
                return list(await result.fetchall())

        return run_with_pool(_read)

    def credential(self, jti: str) -> dict[str, Any] | None:
        return next((r for r in self.issued_credentials() if r["jti"] == jti), None)


class LiveServer:
    """Run a FastAPI app on a real loopback TCP socket for integration tests."""

    def __init__(
        self,
        app: FastAPI,
        *,
        readiness_path: str,
        listener: socket.socket | None = None,
    ) -> None:
        self._socket = listener or socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if listener is None:
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind(("127.0.0.1", 0))
            self._socket.listen()
        host, port = self._socket.getsockname()
        self.base_url = f"http://{host}:{port}"
        self._readiness_path = readiness_path
        self._server = uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False))
        self._thread = threading.Thread(
            target=self._server.run,
            kwargs={"sockets": [self._socket]},
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                response = httpx.get(f"{self.base_url}{self._readiness_path}", timeout=0.5)
                if response.is_success:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
        self.stop()
        raise RuntimeError(f"server at {self.base_url} did not become ready")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)
        self._socket.close()


def _seed_clients() -> tuple[RegisteredClient, ...]:
    return (
        RegisteredClient(
            client_id="reporting-agent",
            subject="agent:reporting",
            secret_hash=hash_secret(REPORTING_SECRET),
            allowed_scopes=frozenset({"finance:read", "reports:read"}),
            allowed_audiences=frozenset({"test-resource"}),
        ),
        RegisteredClient(
            client_id="no-authority-agent",
            subject="agent:no-authority",
            secret_hash=hash_secret(NO_AUTHORITY_SECRET),
            allowed_scopes=frozenset(),
        ),
        RegisteredClient(
            client_id="suspended-agent",
            subject="agent:suspended",
            secret_hash=hash_secret(SUSPENDED_SECRET),
            status="suspended",
            allowed_scopes=frozenset({"reports:read"}),
        ),
    )


@pytest.fixture
def clean_database() -> str:
    """A freshly migrated, freshly seeded database for one test."""

    async def _prepare(pool: AsyncConnectionPool) -> None:
        async with pool.connection() as connection:
            await reset(connection)
            await migrate(connection)
        repository = ClientRepository(pool)
        for client in _seed_clients():
            await repository.upsert(client)

    try:
        run_with_pool(_prepare)
    except Exception as exc:  # the message matters more than the traceback here
        raise RuntimeError(
            f"cannot reach the test database at {TEST_DATABASE_URL}.\n"
            "Start it with `make db-up`, or set TEST_DATABASE_URL."
        ) from exc
    return TEST_DATABASE_URL


@pytest.fixture
def integration_environment(
    tmp_path, clean_database
) -> Generator[IntegrationEnvironment, None, None]:
    authorization_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    authorization_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    authorization_socket.bind(("127.0.0.1", 0))
    authorization_socket.listen()
    host, port = authorization_socket.getsockname()
    authorization_server_url = f"http://{host}:{port}"

    settings = Settings(
        issuer=authorization_server_url,
        key_directory=tmp_path / "keys",
        resource_audience="test-resource",
        access_token_ttl_seconds=600,
        database_url=clean_database,
    )
    signing_key = KeyStore(settings.key_directory).load_or_create()

    # The application opens its own pool inside uvicorn's event loop.
    pool = create_pool(settings.database_url)

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await pool.open()
        yield
        await pool.close()

    authorization_app = create_app(
        settings=settings,
        signing_key=signing_key,
        clients=ClientRegistry(ClientRepository(pool)),
        credentials=IssuedCredentialRepository(pool),
        lifespan=lifespan,
    )
    authorization_server = LiveServer(
        authorization_app,
        readiness_path="/.well-known/oauth-authorization-server",
        listener=authorization_socket,
    )
    authorization_server.start()

    resource_server = LiveServer(
        create_resource_server(
            authorization_server_issuer=authorization_server_url,
            audience=settings.resource_audience,
        ),
        readiness_path="/health",
    )
    resource_server.start()
    oauth_client = OAuthClient(authorization_server_url)
    try:
        yield IntegrationEnvironment(
            authorization_server_url=authorization_server_url,
            resource_server_url=resource_server.base_url,
            settings=settings,
            signing_key=signing_key,
            oauth_client=oauth_client,
        )
    finally:
        oauth_client.close()
        resource_server.stop()
        authorization_server.stop()
