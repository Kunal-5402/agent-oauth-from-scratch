"""Reading and writing the 3 tables. No business rules live here."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from src.models import RegisteredClient


@dataclass(frozen=True)
class IssuanceRecord:
    """What the server writes down before it hands a token to anybody."""

    jti: str
    client_id: str
    subject: str
    audience: str
    scope: str
    issued_at: datetime
    expires_at: datetime
    root_subject: str
    task_id: str | None = None
    delegation_depth: int = 0


class ClientRepository:
    def __init__(self, pool: AsyncConnectionPool) -> None:
        self._pool = pool

    async def get(self, client_id: str) -> RegisteredClient | None:
        async with self._pool.connection() as connection:
            connection.row_factory = dict_row
            result = await connection.execute(
                """
                SELECT client_id, subject, status, secret_hash, auth_method,
                       allowed_scopes, allowed_audiences
                  FROM clients
                 WHERE client_id = %s
                """,
                (client_id,),
            )
            row = await result.fetchone()
        return _to_client(row) if row else None

    async def all(self) -> tuple[RegisteredClient, ...]:
        async with self._pool.connection() as connection:
            connection.row_factory = dict_row
            result = await connection.execute(
                """
                SELECT client_id, subject, status, secret_hash, auth_method,
                       allowed_scopes, allowed_audiences
                  FROM clients
                 ORDER BY client_id
                """
            )
            rows = await result.fetchall()
        return tuple(_to_client(row) for row in rows)

    async def upsert(self, client: RegisteredClient) -> None:
        async with self._pool.connection() as connection:
            await connection.execute(
                """
                INSERT INTO clients (client_id, subject, status, secret_hash,
                                     auth_method, allowed_scopes, allowed_audiences)
                     VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (client_id) DO UPDATE
                        SET subject = EXCLUDED.subject,
                            status = EXCLUDED.status,
                            secret_hash = EXCLUDED.secret_hash,
                            auth_method = EXCLUDED.auth_method,
                            allowed_scopes = EXCLUDED.allowed_scopes,
                            allowed_audiences = EXCLUDED.allowed_audiences
                """,
                (
                    client.client_id,
                    client.subject,
                    client.status,
                    client.secret_hash,
                    client.auth_method,
                    sorted(client.allowed_scopes),
                    sorted(client.allowed_audiences),
                ),
            )
            await connection.commit()


class IssuedCredentialRepository:
    def __init__(self, pool: AsyncConnectionPool) -> None:
        self._pool = pool

    async def record(self, issuance: IssuanceRecord) -> None:
        """Write the issuance. A failure here must stop the token reaching anybody."""
        async with self._pool.connection() as connection:
            await connection.execute(
                """
                INSERT INTO issued_credentials
                       (jti, client_id, subject, audience, scope, issued_at,
                        expires_at, root_subject, task_id, delegation_depth)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    issuance.jti,
                    issuance.client_id,
                    issuance.subject,
                    issuance.audience,
                    issuance.scope,
                    issuance.issued_at,
                    issuance.expires_at,
                    issuance.root_subject,
                    issuance.task_id,
                    issuance.delegation_depth,
                ),
            )
            await connection.commit()

    async def get(self, jti: str) -> dict[str, Any] | None:
        async with self._pool.connection() as connection:
            connection.row_factory = dict_row
            result = await connection.execute(
                "SELECT * FROM issued_credentials WHERE jti = %s", (jti,)
            )
            return await result.fetchone()

    async def count(self) -> int:
        async with self._pool.connection() as connection:
            result = await connection.execute("SELECT count(*) FROM issued_credentials")
            row = await result.fetchone()
        return row[0]


def _to_client(row: dict[str, Any]) -> RegisteredClient:
    return RegisteredClient(
        client_id=row["client_id"],
        subject=row["subject"],
        status=row["status"],
        secret_hash=row["secret_hash"],
        auth_method=row["auth_method"],
        allowed_scopes=frozenset(row["allowed_scopes"]),
        allowed_audiences=frozenset(row["allowed_audiences"]),
    )
