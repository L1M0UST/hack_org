"""Small PostgreSQL connectivity helpers."""

from __future__ import annotations

import psycopg
from psycopg import Connection

from .db_config import DatabaseConfig


def ping_database(config: DatabaseConfig) -> dict[str, str]:
    """Open a PostgreSQL connection and return server identity metadata."""

    conninfo = (
        f"host={config.host} port={config.port} dbname={config.database} "
        f"user={config.user} password={config.password} sslmode={config.sslmode}"
    )
    with psycopg.connect(conninfo, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version(), current_database(), current_user")
            version, database, user = cur.fetchone()
    return {"version": version, "database": database, "user": user}


def connect_database(config: DatabaseConfig) -> Connection:
    """Open a PostgreSQL connection using the configured runtime settings."""

    conninfo = (
        f"host={config.host} port={config.port} dbname={config.database} "
        f"user={config.user} password={config.password} sslmode={config.sslmode}"
    )
    return psycopg.connect(conninfo, autocommit=True, connect_timeout=10)
