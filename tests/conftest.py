from __future__ import annotations

import socket
import threading
import time
from collections.abc import Generator
from dataclasses import dataclass

import httpx
import pytest
import uvicorn
from fastapi import FastAPI

from src.api.routes import create_app
from src.config import Settings
from src.crypto.keys import KeyStore, SigningKey
from src.services.token_issuer import ClientRegistry, RegisteredClient
from tests.oauth_client.client import OAuthClient
from tests.resource_server.app import create_resource_server


@dataclass(frozen=True)
class IntegrationEnvironment:
    authorization_server_url: str
    resource_server_url: str
    settings: Settings
    signing_key: SigningKey
    oauth_client: OAuthClient


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
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                response = httpx.get(f"{self.base_url}{self._readiness_path}", timeout=0.2)
                if response.is_success:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.02)
        self.stop()
        raise RuntimeError(f"server at {self.base_url} did not become ready")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)
        self._socket.close()


@pytest.fixture
def integration_environment(tmp_path) -> Generator[IntegrationEnvironment, None, None]:
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
    )
    signing_key = KeyStore(settings.key_directory).load_or_create()
    clients = ClientRegistry(
        [
            RegisteredClient(
                client_id="reporting-agent",
                client_secret="test-only-secret",
                subject="agent:reporting",
                allowed_scopes=frozenset({"finance:read", "reports:read"}),
            ),
            RegisteredClient(
                client_id="no-authority-agent",
                client_secret="test-only-empty-scope-secret",
                subject="agent:no-authority",
                allowed_scopes=frozenset(),
            ),
        ]
    )
    authorization_app = create_app(
        settings=settings,
        signing_key=signing_key,
        clients=clients,
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
