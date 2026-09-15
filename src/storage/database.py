"""The Postgres connection pool and a migration runner.

The runner is 30 lines and deliberately not a framework. Migrations are ordered
``.sql`` files; applying one records its name. A file is never applied twice and
is never edited after it has been applied.
"""

from __future__ import annotations

from pathlib import Path

from psycopg import AsyncConnection
from psycopg_pool import AsyncConnectionPool

MIGRATIONS_DIRECTORY = Path(__file__).parent / "migrations"

_SCHEMA_VERSION_TABLE = """
CREATE TABLE IF NOT EXISTS schema_version (
    name       TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


def create_pool(database_url: str, *, open_now: bool = False) -> AsyncConnectionPool:
    """Build the pool. Opening is the caller's decision, so tests can control it."""
    return AsyncConnectionPool(database_url, open=open_now, min_size=1, max_size=10)


async def migrate(connection: AsyncConnection) -> list[str]:
    """Apply every unapplied migration, in filename order. Return what ran."""
    await connection.execute(_SCHEMA_VERSION_TABLE)

    result = await connection.execute("SELECT name FROM schema_version")
    applied = {row[0] for row in await result.fetchall()}

    ran: list[str] = []
    for path in sorted(MIGRATIONS_DIRECTORY.glob("*.sql")):
        if path.name in applied:
            continue
        await connection.execute(path.read_text())
        await connection.execute("INSERT INTO schema_version (name) VALUES (%s)", (path.name,))
        ran.append(path.name)

    await connection.commit()
    return ran


async def reset(connection: AsyncConnection) -> None:
    """Drop everything. For tests only; never called by the running server."""
    await connection.execute("DROP SCHEMA public CASCADE")
    await connection.execute("CREATE SCHEMA public")
    await connection.commit()
