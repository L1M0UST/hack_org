"""Artifact storage backends for collected raw materials."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import yaml
from .env_utils import load_env_file


class ArtifactStore(Protocol):
    """Common upload interface for raw collection artifacts."""

    def upload_file(self, local_path: Path, object_key: str) -> str | None:
        """Upload one file and return its remote object key when applicable."""


class LocalArtifactStore:
    """No-op backend used when only local files are desired."""

    def upload_file(self, local_path: Path, object_key: str) -> str | None:
        """Keep files local and report no remote object key."""

        return None


@dataclass
class MinioSettings:
    """Resolved MinIO connection settings."""

    endpoint: str
    access_key: str
    secret_key: str
    bucket: str
    secure: bool


class MinioArtifactStore:
    """S3-compatible object storage backend backed by MinIO."""

    def __init__(self, settings: MinioSettings) -> None:
        from minio import Minio

        self.bucket = settings.bucket
        self.client = Minio(
            settings.endpoint,
            access_key=settings.access_key,
            secret_key=settings.secret_key,
            secure=settings.secure,
        )
        if not self.client.bucket_exists(self.bucket):
            self.client.make_bucket(self.bucket)

    def upload_file(self, local_path: Path, object_key: str) -> str | None:
        """Upload one file and return its MinIO object key."""

        self.client.fput_object(self.bucket, object_key, str(local_path))
        return object_key


def load_artifact_store(config_path: Path, env_path: Path | None = None) -> ArtifactStore:
    """Load the configured artifact storage backend."""

    if env_path:
        load_env_file(env_path)
    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))["storage"]
    backend = str(data.get("backend", "local")).casefold()
    if backend == "local":
        return LocalArtifactStore()
    if backend != "minio":
        raise ValueError(f"Unsupported artifact storage backend: {backend}")
    minio_cfg = data["minio"]
    secure_raw = os.environ.get(minio_cfg["secure_env"], "true").casefold()
    return MinioArtifactStore(
        MinioSettings(
            endpoint=_required_env(minio_cfg["endpoint_env"]),
            access_key=_required_env(minio_cfg["access_key_env"]),
            secret_key=_required_env(minio_cfg["secret_key_env"]),
            bucket=_required_env(minio_cfg["bucket_env"]),
            secure=secure_raw in {"1", "true", "yes", "on"},
        )
    )


def artifact_object_key(source_id: str, digest: str, filename: str) -> str:
    """Build one stable object key."""

    return f"raw/{source_id}/{digest}/{filename}"


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required env var for MinIO storage: {name}")
    return value
