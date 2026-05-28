# apt_group_table_sync

Offline-side tools for replaying `apt_group_change_log` JSONL packages into ClickHouse table `apt_group_distributed`.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install paramiko
```

## Environment

```env
SFTP_HOST=1.2.3.4
SFTP_PORT=22
SFTP_USER=user
SFTP_PASSWORD=password
SFTP_DIR=/apt_group
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
.venv/bin/python sync_apt_group_from_sftp.py --remote-name apt_group_changes.jsonl
```

The script records `last_seq` locally and skips already applied changes.

For update replay, `apt_group_distributed` should write into a `ReplacingMergeTree` local table keyed by `apt_organization` with a version column such as `storage_time` or `change_seq`; ordinary MergeTree tables will keep historical duplicates.
