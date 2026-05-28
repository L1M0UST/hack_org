"""PostgreSQL configuration helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from .env_utils import load_env_file


@dataclass
class DatabaseConfig:
    """Runtime PostgreSQL connection settings."""

    driver: str
    host: str
    port: int
    database: str
    user: str
    password: str
    sslmode: str


def load_database_config(path: Path, env_path: Path | None = None) -> DatabaseConfig:
    """Load database config from YAML indirection plus environment variables."""

    if env_path:
        load_env_file(env_path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))["database"]
    return DatabaseConfig(
        driver=str(data["driver"]),
        host=_required_env(data["host_env"]),
        port=int(os.environ.get(data["port_env"], "5432")),
        database=_required_env(data["database_env"]),
        user=_required_env(data["user_env"]),
        password=_required_env(data["password_env"]),
        sslmode=os.environ.get(data["sslmode_env"], "prefer"),
    )


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing database env var: {name}")
    return value
