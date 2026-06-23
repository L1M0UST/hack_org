#!/usr/bin/env python3
"""Pull apt_group change-log JSONL from FTP and replay into ClickHouse."""

from __future__ import annotations

import argparse
import ftplib
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from fnmatch import fnmatch
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent

DEFAULT_APT_COLUMNS = [
    "apt_organization",
    "organization_code",
    "team_name",
    "attack_type",
    "technical_skills",
    "suspected_source",
    "affected_industry",
    "alias",
    "attack_pattern",
    "attack_frequency",
    "target_country",
    "earliest_active_time",
    "active_time",
    "common_language",
    "team_description",
    "tactics",
    "associated_domain",
    "associative_hash",
    "associative_ip",
    "associative_url",
    "related_certificates",
]


def load_env_file(path: Path) -> None:
    """Load KEY=VALUE pairs from a local .env file without overriding env vars."""

    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def main() -> None:
    load_env_file(SCRIPT_DIR / ".env")
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote-name", default=None)
    parser.add_argument("--pattern", default="apt_group_changes_*.jsonl")
    parser.add_argument("--local-dir", default="incoming")
    parser.add_argument("--state-file", default=os.environ.get("SYNC_STATE_FILE", ".sync_state.json"))
    parser.add_argument("--keep-remote", action="store_true")
    parser.add_argument("--keep-local", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    local_dir = Path(args.local_dir)
    local_dir.mkdir(parents=True, exist_ok=True)
    remote_names = [args.remote_name] if args.remote_name else list_remote_files(args.pattern)
    if not remote_names:
        print(json.dumps({"files": 0, "applied": 0, "last_seq": load_last_seq(Path(args.state_file))}, ensure_ascii=False))
        return
    total_applied = 0
    last_seq = load_last_seq(Path(args.state_file))
    for remote_name in remote_names:
        local_path = local_dir / Path(remote_name).name
        pull_ftp(remote_name, local_path)
        if not args.keep_remote and not args.dry_run:
            delete_remote(remote_name)
        changes = [row for row in read_jsonl(local_path) if int(row["change_seq"]) > last_seq]
        if changes:
            file_last_seq = max(int(row["change_seq"]) for row in changes)
            if not args.dry_run:
                apply_changes(changes)
                save_last_seq(Path(args.state_file), file_last_seq)
                cleanup_local(local_path, keep_local=args.keep_local)
            last_seq = file_last_seq
            total_applied += len(changes)
        elif not args.dry_run:
            cleanup_local(local_path, keep_local=args.keep_local)
    print(json.dumps({"files": len(remote_names), "applied": total_applied, "last_seq": last_seq}, ensure_ascii=False))


def connect_ftp():
    use_tls = os.environ.get("FTP_TLS", "false").casefold() in {"1", "true", "yes"}
    ftp_cls = ftplib.FTP_TLS if use_tls else ftplib.FTP
    ftp = ftp_cls()
    ftp.connect(os.environ["FTP_HOST"], int(os.environ.get("FTP_PORT", "21")), timeout=30)
    ftp.login(os.environ["FTP_USER"], os.environ["FTP_PASSWORD"])
    if use_tls:
        ftp.prot_p()
    remote_dir = os.environ.get("FTP_DIR", "")
    if remote_dir:
        ensure_ftp_dir(ftp, remote_dir)
    return ftp


def ensure_ftp_dir(ftp: ftplib.FTP, remote_dir: str) -> None:
    """Create an FTP directory tree if it does not exist, then cwd into it."""

    normalized = remote_dir.replace("\\", "/").strip()
    if not normalized or normalized == ".":
        return
    is_absolute = normalized.startswith("/")
    parts = [part for part in normalized.split("/") if part]
    if is_absolute:
        ftp.cwd("/")
    for part in parts:
        try:
            ftp.cwd(part)
        except ftplib.error_perm:
            ftp.mkd(part)
            ftp.cwd(part)


def list_remote_files(pattern: str) -> list[str]:
    """List remote change files matching a shell-style pattern."""

    with connect_ftp() as ftp:
        names = ftp.nlst()
    return sorted(name for name in names if fnmatch(Path(name).name, pattern))


def pull_ftp(remote_name: str, local_path: Path) -> None:
    with connect_ftp() as ftp:
        with local_path.open("wb") as handle:
            ftp.retrbinary(f"RETR {remote_name}", handle.write)


def delete_remote(remote_name: str) -> None:
    """Delete one remote FTP file."""

    with connect_ftp() as ftp:
        ftp.delete(remote_name)


def cleanup_local(local_path: Path, *, keep_local: bool) -> None:
    """Delete one local file unless retention was requested."""

    if not keep_local and local_path.exists():
        local_path.unlink()


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def apply_changes(changes: list[dict]) -> None:
    rows = []
    for change in changes:
        row = change.get("new_row")
        if not row or change.get("operation") == "delete":
            continue
        rows.append(row)
    if not rows:
        return
    columns = apt_columns(rows)
    rows = [{column: normalize_value(row.get(column)) for column in columns} for row in rows]
    payload = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    interface = os.environ.get("CLICKHOUSE_INTERFACE", "http").casefold()
    if interface == "native":
        apply_changes_native(columns, payload)
    elif interface == "http":
        apply_changes_http(columns, payload)
    else:
        raise ValueError(f"unsupported CLICKHOUSE_INTERFACE: {interface}")


def apply_changes_native(columns: list[str], payload: str) -> None:
    """Insert rows through clickhouse-client native TCP protocol."""

    command = [
        "clickhouse-client",
        "--host", os.environ.get("CLICKHOUSE_HOST", "127.0.0.1"),
        "--port", os.environ.get("CLICKHOUSE_PORT", "9000"),
        "--user", os.environ.get("CLICKHOUSE_USER", "default"),
        "--query", insert_query(columns),
    ]
    password = os.environ.get("CLICKHOUSE_PASSWORD")
    if password:
        command.extend(["--password", password])
    subprocess.run(command, input=payload, text=True, check=True)


def apply_changes_http(columns: list[str], payload: str) -> None:
    """Insert rows through ClickHouse HTTP interface, usually port 8123."""

    timeout = int(os.environ.get("CLICKHOUSE_TIMEOUT", "60"))
    clickhouse_http_request(insert_query(columns), data=payload.encode("utf-8"), timeout=timeout).read()


def clickhouse_http_request(query: str, data: bytes | None = None, timeout: int | None = None):
    """Run one ClickHouse HTTP query and return the response object."""

    protocol = os.environ.get("CLICKHOUSE_PROTOCOL", "http")
    host = os.environ.get("CLICKHOUSE_HOST", "127.0.0.1")
    port = os.environ.get("CLICKHOUSE_PORT", "8123")
    timeout = timeout or int(os.environ.get("CLICKHOUSE_TIMEOUT", "60"))
    url = f"{protocol}://{host}:{port}/?{urllib.parse.urlencode({'query': query})}"
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            "X-ClickHouse-User": os.environ.get("CLICKHOUSE_USER", "default"),
        },
        method="POST",
    )
    password = os.environ.get("CLICKHOUSE_PASSWORD")
    if password:
        request.add_header("X-ClickHouse-Key", password)
    try:
        return urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"ClickHouse HTTP query failed: {exc.code} {body}") from exc


def insert_query(columns: list[str]) -> str:
    """Build a ClickHouse JSONEachRow insert statement."""

    column_sql = ", ".join(quote_identifier(column) for column in columns)
    return f"INSERT INTO {clickhouse_table_name()} ({column_sql}) FORMAT JSONEachRow"


def clickhouse_table_name() -> str:
    """Return a safely quoted ClickHouse table name."""

    table = os.environ.get("CLICKHOUSE_TABLE", "apt_group_distributed")
    database = os.environ.get("CLICKHOUSE_DATABASE", "default")
    if database:
        return f"{quote_identifier(database)}.{quote_identifier(table)}"
    return quote_identifier(table)


def quote_identifier(value: str) -> str:
    """Quote simple ClickHouse identifiers and reject unsafe names."""

    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise ValueError(f"unsafe ClickHouse identifier: {value!r}")
    return f"`{value}`"


def normalize_value(value):
    if value is None:
        return ""
    return str(value)


def apt_columns(rows: list[dict] | None = None) -> list[str]:
    raw = os.environ.get("APT_GROUP_COLUMNS")
    if not raw:
        columns = DEFAULT_APT_COLUMNS
    else:
        columns = [item.strip() for item in raw.split(",") if item.strip()]
    columns = [column for column in columns if column not in excluded_columns()]
    if os.environ.get("CLICKHOUSE_AUTO_COLUMNS", "true").casefold() not in {"1", "true", "yes"}:
        return columns
    table_columns = clickhouse_table_columns()
    if not table_columns:
        return columns
    available = [column for column in columns if column in table_columns]
    if rows:
        for column in DEFAULT_APT_COLUMNS:
            if column in table_columns and column not in available and any(column in row for row in rows):
                available.append(column)
    if not available:
        raise RuntimeError("No matching ClickHouse columns found for apt_group export rows")
    return available


def excluded_columns() -> set[str]:
    """Return columns that must not be inserted because ClickHouse generates them."""

    raw = os.environ.get("CLICKHOUSE_EXCLUDE_COLUMNS", "storage_time")
    return {item.strip() for item in raw.split(",") if item.strip()}


def clickhouse_table_columns() -> set[str]:
    """Fetch target table columns through HTTP when enabled."""

    if os.environ.get("CLICKHOUSE_INTERFACE", "http").casefold() != "http":
        return set()
    try:
        with clickhouse_http_request(f"DESCRIBE TABLE {clickhouse_table_name()} FORMAT JSON") as response:
            payload = json.loads(response.read().decode("utf-8"))
        return {str(item["name"]) for item in payload.get("data", [])}
    except Exception:
        return set()


def load_last_seq(path: Path) -> int:
    if not path.exists():
        return 0
    return int(json.loads(path.read_text(encoding="utf-8")).get("last_seq", 0))


def save_last_seq(path: Path, last_seq: int) -> None:
    path.write_text(json.dumps({"last_seq": last_seq}, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
