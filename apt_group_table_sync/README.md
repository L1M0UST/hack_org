# apt_group_table_sync

Offline-side tools for replaying `apt_group_change_log` JSONL packages into ClickHouse table `apt_group_distributed`.

The crawler machine uploads change files through SFTP. The offline machine pulls those files through FTP, then writes them into ClickHouse.

## Install

```bash
python3 -m venv .venv
```

## Environment

```env
FTP_HOST=1.2.3.4
FTP_PORT=21
FTP_USER=user
FTP_PASSWORD=password
FTP_DIR=/apt_group
FTP_TLS=false
CLICKHOUSE_HOST=127.0.0.1
CLICKHOUSE_PORT=9000
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=
CLICKHOUSE_DATABASE=default
CLICKHOUSE_TABLE=apt_group_distributed
SYNC_STATE_FILE=.sync_state.json
# Optional: set this if your ClickHouse table has extra columns such as source_evidence.
# APT_GROUP_COLUMNS=apt_organization,organization_code,team_name,...,source_evidence,storage_time
```

## Run

```bash
.venv/bin/python sync_apt_group_from_ftp.py --remote-name apt_group_changes.jsonl
```

The script records `last_seq` locally, skips already applied changes, then deletes the remote FTP file and local downloaded file only after ClickHouse insert succeeds. Use `--keep-remote` or `--keep-local` if you want to retain files.

For update replay, `apt_group_distributed` should write into a `ReplacingMergeTree` local table keyed by `organization_code, apt_organization` with a version column such as `storage_time`; ordinary MergeTree tables will keep historical duplicates.
