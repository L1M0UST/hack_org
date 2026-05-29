#!/usr/bin/env python3
"""Pull apt_group change-log JSONL from FTP and replay into ClickHouse."""

from __future__ import annotations

import argparse
import ftplib
import json
import os
import subprocess
from pathlib import Path

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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote-name", required=True)
    parser.add_argument("--local-dir", default="incoming")
    parser.add_argument("--state-file", default=os.environ.get("SYNC_STATE_FILE", ".sync_state.json"))
    parser.add_argument("--keep-remote", action="store_true")
    parser.add_argument("--keep-local", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    local_dir = Path(args.local_dir)
    local_dir.mkdir(parents=True, exist_ok=True)
    local_path = local_dir / args.remote_name
    pull_ftp(args.remote_name, local_path)
    last_seq = load_last_seq(Path(args.state_file))
    changes = [row for row in read_jsonl(local_path) if int(row["change_seq"]) > last_seq]
    if not changes:
        if not args.dry_run:
            cleanup(args.remote_name, local_path, keep_remote=args.keep_remote, keep_local=args.keep_local)
        print(json.dumps({"applied": 0, "last_seq": last_seq}, ensure_ascii=False))
        return
    if not args.dry_run:
        apply_changes(changes)
        save_last_seq(Path(args.state_file), max(int(row["change_seq"]) for row in changes))
        cleanup(args.remote_name, local_path, keep_remote=args.keep_remote, keep_local=args.keep_local)
    print(json.dumps({"applied": len(changes), "last_seq": max(int(row["change_seq"]) for row in changes)}, ensure_ascii=False))


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
        ftp.cwd(remote_dir)
    return ftp


def pull_ftp(remote_name: str, local_path: Path) -> None:
    with connect_ftp() as ftp:
        with local_path.open("wb") as handle:
            ftp.retrbinary(f"RETR {remote_name}", handle.write)


def cleanup(remote_name: str, local_path: Path, *, keep_remote: bool, keep_local: bool) -> None:
    if not keep_remote:
        with connect_ftp() as ftp:
            ftp.delete(remote_name)
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
