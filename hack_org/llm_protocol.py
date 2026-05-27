"""Helpers for loading LLM schemas and validating structured model output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


def load_schema(path: Path) -> dict[str, Any]:
    """Load one JSON Schema file."""

    return json.loads(path.read_text(encoding="utf-8"))


def validate_payload(schema_path: Path, payload: dict[str, Any]) -> None:
    """Validate one model payload against a local JSON Schema."""

    schema = load_schema(schema_path)
    Draft202012Validator(schema).validate(payload)
