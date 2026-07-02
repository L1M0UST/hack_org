"""Unified daily file logging for collection, processing, and storage workflows."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from .utils import repair_mojibake, utcnow, write_json


LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LogChannel = Literal["collection", "processing", "storage", "error"]


@dataclass
class DailySummary:
    """Counters used to build one daily summary.json file."""

    date: str
    counters: dict[str, int] = field(default_factory=dict)

    def increment(self, key: str, amount: int = 1) -> None:
        """Increment a named summary counter."""

        self.counters[key] = self.counters.get(key, 0) + amount

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable daily summary."""

        return {"date": self.date, **self.counters}


class DailyLogger:
    """Write human-readable and JSONL logs into one directory per calendar day."""

    def __init__(self, base_dir: Path, console: bool = True) -> None:
        self.base_dir = base_dir
        self.console = console
        if self.console and hasattr(sys.stdout, "reconfigure"):
            try:
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
        self.now = utcnow()
        self.date = self.now.astimezone().date().isoformat()
        self.day_dir = base_dir / self.date
        self.day_dir.mkdir(parents=True, exist_ok=True)
        self.summary = DailySummary(self.date)

    def log(
        self,
        channel: LogChannel,
        level: LogLevel,
        event: str,
        message: str,
        **fields: Any,
    ) -> None:
        """Write one event to .log and .jsonl files, plus error.log when needed."""

        timestamp = utcnow().isoformat()
        payload = {
            "timestamp": timestamp,
            "level": level,
            "channel": channel,
            "event": event,
            "message": message,
            **fields,
        }
        payload = _repair_payload(payload)
        self._append_jsonl(self.day_dir / f"{channel}.jsonl", payload)
        line = self._format_line(payload)
        self._append_text(self.day_dir / f"{channel}.log", line)
        if self.console:
            self._print_console(line)
        if level in {"ERROR", "CRITICAL"}:
            self._append_text(self.day_dir / "error.log", line)
            self.summary.increment("errors")
        elif level == "WARNING":
            self.summary.increment("warnings")

    def count(self, key: str, amount: int = 1) -> None:
        """Increment a summary counter."""

        self.summary.increment(key, amount)

    def write_summary(self, extra: dict[str, Any] | None = None) -> Path:
        """Persist summary.json for the current day."""

        data = self.summary.to_dict()
        if extra:
            data.update(extra)
        path = self.day_dir / "summary.json"
        write_json(path, data)
        return path

    @staticmethod
    def _format_line(payload: dict[str, Any]) -> str:
        local_time = datetime.fromisoformat(payload["timestamp"]).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        details = " ".join(
            f'{key}={json.dumps(value, ensure_ascii=False)}'
            for key, value in payload.items()
            if key not in {"timestamp", "level", "channel", "event", "message"} and value is not None
        )
        suffix = f" {details}" if details else ""
        return f'[{local_time}] {payload["level"]} [{payload["channel"]}] {payload["event"]}: {payload["message"]}{suffix}'

    @staticmethod
    def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    @staticmethod
    def _append_text(path: Path, line: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    @staticmethod
    def _print_console(line: str) -> None:
        try:
            print(line, flush=True)
        except UnicodeEncodeError:
            encoding = sys.stdout.encoding or "utf-8"
            safe = line.encode(encoding, errors="replace").decode(encoding, errors="replace")
            print(safe, flush=True)


def _repair_payload(value: Any) -> Any:
    """Repair mojibake in log messages and structured fields before writing."""

    if isinstance(value, str):
        return repair_mojibake(value)
    if isinstance(value, list):
        return [_repair_payload(item) for item in value]
    if isinstance(value, tuple):
        return [_repair_payload(item) for item in value]
    if isinstance(value, dict):
        return {str(_repair_payload(key)): _repair_payload(item) for key, item in value.items()}
    return value
