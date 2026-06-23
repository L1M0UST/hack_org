#!/usr/bin/env python3
"""Pull apt_group change-log JSONL from FTP and replay into ClickHouse."""

from __future__ import annotations

import argparse
import ftplib
import json
import os
import subprocess
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
    "storage_time",
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
    table = os.environ.get("CLICKHOUSE_TABLE", "apt_group_distributed")
    database = os.environ.get("CLICKHOUSE_DATABASE", "default")
    full_table = f"{database}.{table}" if database else table
    columns = apt_columns()
    rows = []
    for change in changes:
        row = change.get("new_row")
        if not row or change.get("operation") == "delete":
            continue
        rows.append({column: normalize_value(row.get(column)) for column in columns})
    if not rows:
        return
    payload = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    command = [
        "clickhouse-client",
        "--host", os.environ.get("CLICKHOUSE_HOST", "127.0.0.1"),
        "--port", os.environ.get("CLICKHOUSE_PORT", "9000"),
        "--user", os.environ.get("CLICKHOUSE_USER", "default"),
        "--query", f"INSERT INTO {full_table} ({', '.join(columns)}) FORMAT JSONEachRow",
    ]
    password = os.environ.get("CLICKHOUSE_PASSWORD")
    if password:
        command.extend(["--password", password])
    subprocess.run(command, input=payload, text=True, check=True)


def normalize_value(value):
    if value is None:
        return ""
    return str(value)


def apt_columns() -> list[str]:
    raw = os.environ.get("APT_GROUP_COLUMNS")
    if not raw:
        return DEFAULT_APT_COLUMNS
    return [item.strip() for item in raw.split(",") if item.strip()]


def load_last_seq(path: Path) -> int:
    if not path.exists():
        return 0
    return int(json.loads(path.read_text(encoding="utf-8")).get("last_seq", 0))


def save_last_seq(path: Path, last_seq: int) -> None:
    path.write_text(json.dumps({"last_seq": last_seq}, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
