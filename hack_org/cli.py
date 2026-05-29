"""Command line interface for the threat intelligence archive system."""

from __future__ import annotations

import argparse
import csv
import json
import ftplib
import os
from pathlib import Path

from .aliasing import import_alias_seed
from .artifact_store import load_artifact_store
from .archive import ArchiveBuilder
from .config import load_sources
from .discovery import discover_unknown_groups
from .harvesting import HarvestManager
from .importer import import_groups_to_store
from .db_config import load_database_config
from .daily_report import DailyReportBuilder
from .llm_protocol import validate_payload
from .model_ingestor import ModelOutputIngestor
from .pg_client import connect_database, ping_database
from .pg_repository import PostgresRepository
from .llm_client import OpenAICompatibleClient, load_llm_config
from .llm_inputs import build_article_extract_variables
from .pipeline import DailyPipeline
from .pg_archive import PostgresArchiveExporter
from .notification import load_notifier, render_report_message
from .errors import classify_error
from .env_utils import load_env_file
from .scoring import score_article
from .storage import StateStore
from .utils import utcnow, write_json


def main() -> None:
    """Run the CLI."""

    parser = argparse.ArgumentParser(prog="hack-org")
    parser.add_argument("--csv", default="hacker_organizations.csv")
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--state-dir", default=".state")
    parser.add_argument("--sources", default="config/sources.yaml")
    parser.add_argument("--alias-seed", default="config/alias_seed.yaml")
    parser.add_argument("--db", default=".state/hack_org.sqlite")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init_db")
    sub.add_parser("import_csv")
    sub.add_parser("import_alias_seed")
    sub.add_parser("check_llm")
    sub.add_parser("check_db_config")
    sub.add_parser("check_pg")
    sub.add_parser("check_storage_config")
    sub.add_parser("sync_sources_to_pg")
    sub.add_parser("sync_groups_to_pg")
    sub.add_parser("sync_articles_to_pg")
    llm_task = sub.add_parser("run_llm_task")
    llm_task.add_argument("task_type", choices=["article_extract", "group_profile_synthesis", "group_structure_synthesis", "apt_group_export_synthesis"])
    llm_task.add_argument("input_json")
    llm_task.add_argument("--output", default=None)
    ingest_output = sub.add_parser("ingest_model_output")
    ingest_output.add_argument("task_type", choices=["article_extract", "group_profile_synthesis", "group_structure_synthesis", "apt_group_export_synthesis"])
    ingest_output.add_argument("output_json")
    build_article_input = sub.add_parser("build_article_extract_input")
    build_article_input.add_argument("article_id", type=int)
    build_article_input.add_argument("--output", default=None)
    build_profile_input = sub.add_parser("build_group_profile_input")
    build_profile_input.add_argument("organization_code")
    build_profile_input.add_argument("--output", default=None)
    build_structure_input = sub.add_parser("build_group_structure_input")
    build_structure_input.add_argument("organization_code")
    build_structure_input.add_argument("--output", default=None)
    build_export_input = sub.add_parser("build_apt_group_export_input")
    build_export_input.add_argument("organization_code")
    build_export_input.add_argument("--output", default=None)
    collect = sub.add_parser("collect_sources")
    collect.add_argument("--limit", type=int, default=25)
    collect.add_argument("--workers", type=int, default=4)
    collect.add_argument("--timeout", type=float, default=20.0)
    collect.add_argument("--proxy", default="http://127.0.0.1:7890")
    discover_groups = sub.add_parser("discover_unknown_groups")
    discover_groups.add_argument("--article-limit", type=int, default=None)
    discover_groups.add_argument("--min-confidence", type=float, default=0.45)
    discover_groups.add_argument("--output", default=".state/discovered_groups.json")
    list_discovered = sub.add_parser("list_discovered_groups")
    list_discovered.add_argument("--limit", type=int, default=50)
    list_discovered.add_argument("--status", default=None)
    promote_discovered = sub.add_parser("promote_discovered_group")
    promote_discovered.add_argument("candidate_id", type=int)
    promote_discovered.add_argument("--canonical-name", default=None)
    promote_discovered.add_argument("--min-evidence", type=int, default=2)
    promote_discovered.add_argument("--min-confidence", type=float, default=0.65)
    promote_discovered.add_argument("--force", action="store_true")
    promote_batch = sub.add_parser("promote_discovered_groups")
    promote_batch.add_argument("--min-evidence", type=int, default=2)
    promote_batch.add_argument("--min-confidence", type=float, default=0.65)
    promote_batch.add_argument("--limit", type=int, default=20)
    sub.add_parser("process_articles")
    sub.add_parser("build_group_files")
    sub.add_parser("generate_summary")
    run_pipeline = sub.add_parser("run_daily_pipeline")
    run_pipeline.add_argument("--article-limit", type=int, default=None)
    run_pipeline.add_argument("--collect", action="store_true")
    run_pipeline.add_argument("--collect-limit", type=int, default=25)
    run_pipeline.add_argument("--workers", type=int, default=4)
    run_pipeline.add_argument("--timeout", type=float, default=20.0)
    run_pipeline.add_argument("--proxy", default="http://127.0.0.1:7890")
    run_pipeline.add_argument("--no-export", action="store_true")
    run_pipeline.add_argument("--article-order", choices=["newest", "oldest"], default="newest")
    run_pipeline.add_argument("--model-workers", type=int, default=1)
    run_pipeline.add_argument("--auto-promote-discovered", action="store_true")
    run_pipeline.add_argument("--promote-min-evidence", type=int, default=2)
    run_pipeline.add_argument("--promote-min-confidence", type=float, default=0.65)
    run_pipeline.add_argument("--promote-limit", type=int, default=20)
    run_pipeline.add_argument("--apt-group-only", action="store_true")
    sub.add_parser("rebuild_apt_group_projection")
    export_table = sub.add_parser("export_apt_table")
    export_table.add_argument("--output", default=".state/apt_group_export.tsv")
    export_table.add_argument("--format", choices=["tsv", "csv", "jsonl"], default="tsv")
    export_table.add_argument("--english-headers", action="store_true")
    export_table.add_argument("--since", default=None)
    send_apt_ftp = sub.add_parser("send_apt_table_ftp")
    send_apt_ftp.add_argument("--output", default=".state/ftp/apt_group_export.jsonl")
    send_apt_ftp.add_argument("--format", choices=["jsonl", "csv", "tsv"], default="jsonl")
    send_apt_ftp.add_argument("--since", default=None)
    send_apt_ftp.add_argument("--remote-name", default=None)
    send_apt_ftp.add_argument("--english-headers", action="store_true")
    export_changes = sub.add_parser("export_apt_group_changes")
    export_changes.add_argument("--after-seq", type=int, default=0)
    export_changes.add_argument("--limit", type=int, default=None)
    export_changes.add_argument("--output", default=".state/apt_group_changes.jsonl")
    send_changes = sub.add_parser("send_apt_group_changes_sftp")
    send_changes.add_argument("--after-seq", type=int, default=0)
    send_changes.add_argument("--limit", type=int, default=None)
    send_changes.add_argument("--output", default=".state/sftp/apt_group_changes.jsonl")
    send_changes.add_argument("--remote-name", default=None)
    sub.add_parser("export_group_archives")
    sub.add_parser("drop_legacy_pg_tables")
    sub.add_parser("ledger_counts")
    show_ledger = sub.add_parser("show_ledger")
    show_ledger.add_argument("ledger", choices=["facts", "structure", "activity"])
    show_ledger.add_argument("--limit", type=int, default=20)
    sub.add_parser("show_backlog")
    daily_report = sub.add_parser("build_daily_report")
    daily_report.add_argument("--date", default=None)
    daily_report.add_argument("--send", action="store_true")
    args = parser.parse_args()

    root = Path.cwd()
    csv_path = root / args.csv
    data_dir = root / args.data_dir
    state_dir = root / args.state_dir
    state_dir.mkdir(parents=True, exist_ok=True)
    store = StateStore(root / args.db)

    if args.command == "init_db":
        print(json.dumps(store.stats(), ensure_ascii=False, indent=2))
    elif args.command == "import_csv":
        stats = import_groups_to_store(csv_path, store)
        _sync_groups_json(state_dir, store)
        _sync_archive_dirs(data_dir, store)
        print(json.dumps(stats, ensure_ascii=False, indent=2))
    elif args.command == "import_alias_seed":
        stats = import_alias_seed(root / args.alias_seed, store)
        _sync_groups_json(state_dir, store)
        _sync_archive_dirs(data_dir, store)
        print(json.dumps(stats, ensure_ascii=False, indent=2))
    elif args.command == "check_llm":
        config = load_llm_config(root / "config" / "llm.yaml")
        OpenAICompatibleClient(config, env_path=root / ".env")
        print(
            json.dumps(
                {
                    "provider": "openai_compatible",
                    "base_url": config.base_url,
                    "model": config.model,
                    "api_key_env": config.api_key_env,
                    "tasks": sorted(config.prompts.keys()),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    elif args.command == "check_db_config":
        config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        print(
            json.dumps(
                {
                    "driver": config.driver,
                    "host": config.host,
                    "port": config.port,
                    "database": config.database,
                    "user": config.user,
                    "sslmode": config.sslmode,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    elif args.command == "check_storage_config":
        artifact_store = load_artifact_store(root / "config" / "storage.yaml", env_path=root / ".env")
        print(json.dumps({"backend": artifact_store.__class__.__name__}, ensure_ascii=False, indent=2))
    elif args.command == "check_pg":
        config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        print(json.dumps(ping_database(config), ensure_ascii=False, indent=2))
    elif args.command == "sync_sources_to_pg":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        sources = load_sources(root / args.sources)
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            synced = repository.sync_sources(sources)
        print(json.dumps({"synced_sources": synced}, ensure_ascii=False, indent=2))
    elif args.command == "sync_groups_to_pg":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            mapping = repository.sync_group_profiles(store.group_profiles())
        print(json.dumps({"synced_groups": len(mapping)}, ensure_ascii=False, indent=2))
    elif args.command == "sync_articles_to_pg":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        rows = store.article_records(order="oldest")
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            synced = 0
            for row in rows:
                repository.upsert_collected_document(row)
                synced += 1
        print(json.dumps({"synced_articles": synced}, ensure_ascii=False, indent=2))
    elif args.command == "run_llm_task":
        llm_config = load_llm_config(root / "config" / "llm.yaml")
        client = OpenAICompatibleClient(llm_config, env_path=root / ".env")
        variables = _read_json(root / args.input_json)
        output = json.dumps(client.run_task(args.task_type, variables, root), ensure_ascii=False, indent=2)
        if args.output:
            (root / args.output).write_text(output, encoding="utf-8")
        else:
            print(output)
    elif args.command == "ingest_model_output":
        llm_config = load_llm_config(root / "config" / "llm.yaml")
        payload = _read_json(root / args.output_json)
        validate_payload(root / llm_config.prompts[args.task_type].schema, payload)
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            with conn.transaction():
                counters = ModelOutputIngestor(repository).ingest(payload)
        print(json.dumps(counters, ensure_ascii=False, indent=2))
    elif args.command == "build_article_extract_input":
        article = store.article_model_by_id(args.article_id)
        article_row = store.article_record_by_id(args.article_id)
        if not article:
            raise SystemExit(f"article not found: {args.article_id}")
        if not article_row:
            raise SystemExit(f"article row not found: {args.article_id}")
        groups = store.group_profiles()
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            repository.sync_sources(load_sources(root / args.sources))
            pg_group_ids = repository.sync_group_profiles(groups)
            pg_document_id = repository.upsert_collected_document(article_row)
            candidates = build_article_extract_variables(
                pg_document_id,
                article,
                groups,
                pg_group_ids=pg_group_ids,
            )["candidate_groups_json"]
            group_context = repository.group_context_by_organization_codes(
                [item["organization_code"] for item in candidates]
            )
        variables = build_article_extract_variables(
            pg_document_id,
            article,
            groups,
            pg_group_ids=pg_group_ids,
            group_context=group_context,
        )
        output = json.dumps(variables, ensure_ascii=False, indent=2)
        if args.output:
            (root / args.output).write_text(output, encoding="utf-8")
        else:
            print(output)
    elif args.command in {"build_group_profile_input", "build_group_structure_input", "build_apt_group_export_input"}:
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            if args.command == "build_group_profile_input":
                variables = repository.profile_synthesis_input(args.organization_code)
            elif args.command == "build_group_structure_input":
                variables = repository.structure_synthesis_input(args.organization_code)
            else:
                variables = repository.export_synthesis_input(args.organization_code)
        output = json.dumps(variables, ensure_ascii=False, indent=2)
        if args.output:
            (root / args.output).write_text(output, encoding="utf-8")
        else:
            print(output)
    elif args.command == "collect_sources":
        sources = [source for source in load_sources(root / args.sources) if source.enabled]
        proxy = args.proxy or None
        artifact_store = load_artifact_store(root / "config" / "storage.yaml", env_path=root / ".env")
        manager = HarvestManager(
            store=store,
            state_dir=state_dir,
            timeout=args.timeout,
            proxy=proxy,
            workers=args.workers,
            artifact_store=artifact_store,
        )
        summary = manager.collect_sources(sources, limit=args.limit)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    elif args.command == "discover_unknown_groups":
        result = discover_unknown_groups(store, article_limit=args.article_limit, min_confidence=args.min_confidence)
        candidates = store.discovered_group_candidates(limit=200)
        output_path = root / args.output
        write_json(output_path, {"summary": result.__dict__, "candidates": candidates})
        print(json.dumps({"summary": result.__dict__, "output": str(output_path)}, ensure_ascii=False, indent=2))
    elif args.command == "list_discovered_groups":
        print(json.dumps(store.discovered_group_candidates(limit=args.limit, status=args.status), ensure_ascii=False, indent=2))
    elif args.command == "promote_discovered_group":
        result = store.promote_discovered_group_candidate(
            args.candidate_id,
            canonical_name=args.canonical_name,
            min_evidence=args.min_evidence,
            min_confidence=args.min_confidence,
            force=args.force,
        )
        _sync_groups_json(state_dir, store)
        _sync_archive_dirs(data_dir, store)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.command == "promote_discovered_groups":
        results = store.promote_discovered_group_candidates(
            min_evidence=args.min_evidence,
            min_confidence=args.min_confidence,
            limit=args.limit,
        )
        _sync_groups_json(state_dir, store)
        _sync_archive_dirs(data_dir, store)
        print(json.dumps({"promoted": results}, ensure_ascii=False, indent=2))
    elif args.command == "process_articles":
        groups = store.group_profiles()
        _sync_groups_json(state_dir, store)
        articles = store.article_models()
        weights = {source.id: source.weight for source in load_sources(root / args.sources)}
        matches = []
        for group in groups:
            for article in articles:
                match = score_article(group, article, source_weight=weights.get(article.source_id, 1.0))
                if match:
                    matches.append(match)
        write_json(state_dir / "matches.json", [match.model_dump(mode="json") for match in matches])
        print(f"processed {len(matches)} matches")
    elif args.command == "build_group_files":
        groups = {group.canonical_name: group for group in store.group_profiles()}
        builder = ArchiveBuilder(data_dir)
        for item in _load_json(state_dir / "matches.json", []):
            from .models import MatchResult

            match = MatchResult.model_validate(item)
            group = groups.get(match.group_name)
            if group:
                builder.archive_match(group, match)
        print("archive updated")
    elif args.command == "generate_summary":
        groups = store.group_profiles()
        _sync_archive_dirs(data_dir, store)
        write_json(data_dir / "_summary.json", {"updated_at": utcnow().isoformat(), "group_count": len(groups), "groups": [g.canonical_name for g in groups]})
        print(f"summarized {len(groups)} groups")
    elif args.command == "run_daily_pipeline":
        try:
            summary = DailyPipeline(root, store).run(
                article_limit=args.article_limit,
                collect=args.collect,
                collect_limit=args.collect_limit,
                workers=args.workers,
                timeout=args.timeout,
                proxy=args.proxy or None,
                export_outputs=not args.no_export,
                article_order=args.article_order,
                model_workers=args.model_workers,
                auto_promote_discovered=args.auto_promote_discovered,
                promote_min_evidence=args.promote_min_evidence,
                promote_min_confidence=args.promote_min_confidence,
                promote_limit=args.promote_limit,
                apt_group_only=args.apt_group_only,
            )
            print(json.dumps(summary.as_dict(), ensure_ascii=False, indent=2))
        except Exception as exc:
            report_path = _write_failure_report(root, state_dir, store, exc)
            print(json.dumps({"fatal_error": str(exc), "report": str(report_path)}, ensure_ascii=False, indent=2))
            raise SystemExit(1) from exc
    elif args.command == "rebuild_apt_group_projection":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            with conn.transaction():
                rows = repository.rebuild_apt_group_projection()
        print(json.dumps({"projected_rows": rows}, ensure_ascii=False, indent=2))
    elif args.command == "export_apt_table":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            rows = repository.apt_group_export_rows(chinese_headers=not args.english_headers, since=args.since)
        output_path = root / args.output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if args.format == "jsonl":
            with output_path.open("w", encoding="utf-8") as handle:
                for row in rows:
                    handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        else:
            delimiter = "\t" if args.format == "tsv" else ","
            columns = list(rows[0].keys()) if rows else [
                "APT组织",
                "组织编码",
                "组织名称",
                "攻击类型",
                "技术能力",
                "疑似来源",
                "受影响行业",
                "别名",
                "攻击模式",
                "攻击频率",
                "目标国家或地区",
                "最早活跃时间",
                "活跃时间",
                "常用语言",
                "组织描述",
                "战术技术",
                "关联域名",
                "关联哈希",
                "关联IP",
                "关联URL",
                "关联证书",
                "入库时间",
            ]
            with output_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=columns, delimiter=delimiter)
                writer.writeheader()
                writer.writerows(rows)
        print(json.dumps({"rows": len(rows), "output": str(output_path)}, ensure_ascii=False, indent=2))
    elif args.command == "export_apt_group_changes":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            rows = repository.apt_group_change_rows(after_seq=args.after_seq, limit=args.limit)
            latest_seq = repository.max_apt_group_change_seq()
            last_exported_seq = max((int(row["change_seq"]) for row in rows), default=args.after_seq)
        output_path = root / args.output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        _write_jsonl(output_path, rows)
        print(json.dumps({"rows": len(rows), "output": str(output_path), "last_exported_seq": last_exported_seq, "latest_seq": latest_seq}, ensure_ascii=False, indent=2))
    elif args.command == "send_apt_group_changes_sftp":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            rows = repository.apt_group_change_rows(after_seq=args.after_seq, limit=args.limit)
            latest_seq = repository.max_apt_group_change_seq()
            last_exported_seq = max((int(row["change_seq"]) for row in rows), default=args.after_seq)
        output_path = root / args.output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        _write_jsonl(output_path, rows)
        remote_name = args.remote_name or output_path.name
        _send_file_sftp(output_path, remote_name, root / ".env")
        print(json.dumps({"rows": len(rows), "local_file": str(output_path), "remote_name": remote_name, "last_exported_seq": last_exported_seq, "latest_seq": latest_seq}, ensure_ascii=False, indent=2))
    elif args.command == "send_apt_table_ftp":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            rows = repository.apt_group_export_rows(chinese_headers=not args.english_headers, since=args.since)
        output_path = root / args.output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        _write_rows(output_path, rows, args.format)
        remote_name = args.remote_name or output_path.name
        _send_file_ftp(output_path, remote_name, root / ".env")
        print(json.dumps({"rows": len(rows), "local_file": str(output_path), "remote_name": remote_name}, ensure_ascii=False, indent=2))
    elif args.command == "export_group_archives":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            snapshots = PostgresRepository(conn).group_archive_snapshots()
        exported = PostgresArchiveExporter(data_dir).export(snapshots)
        print(json.dumps({"exported_groups": exported, "data_dir": str(data_dir)}, ensure_ascii=False, indent=2))
    elif args.command == "drop_legacy_pg_tables":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            with conn.transaction():
                dropped = repository.drop_legacy_projection_tables()
        print(json.dumps({"dropped_tables": dropped}, ensure_ascii=False, indent=2))
    elif args.command == "ledger_counts":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            counts = repository.ledger_counts()
        print(json.dumps(counts, ensure_ascii=False, indent=2, default=str))
    elif args.command == "show_ledger":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            repository = PostgresRepository(conn)
            repository.ensure_runtime_schema()
            rows = repository.recent_ledger_rows(args.ledger, args.limit)
        print(json.dumps(rows, ensure_ascii=False, indent=2, default=str))
    elif args.command == "show_backlog":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        with connect_database(db_config) as conn:
            summary = PostgresRepository(conn).document_backlog_summary()
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    elif args.command == "build_daily_report":
        db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        try:
            with connect_database(db_config) as conn:
                builder = DailyReportBuilder(state_dir, store, PostgresRepository(conn))
                path = builder.write(args.date)
        except Exception:
            builder = DailyReportBuilder(state_dir, store, None)
            path = builder.write(args.date)
        if args.send:
            report = _read_json(path)
            notifier = load_notifier(root / "config" / "notifications.yaml", root, env_path=root / ".env")
            title, body = render_report_message(report)
            notifier.send(title, body, report)
        print(json.dumps({"output": str(path)}, ensure_ascii=False, indent=2))
    store.close()




def _write_jsonl(output_path: Path, rows: list[dict]) -> None:
    """Write dictionaries as UTF-8 JSONL."""

    with output_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _send_file_sftp(local_path: Path, remote_name: str, env_path: Path) -> None:
    """Upload one file through password SFTP using SFTP_* environment variables."""

    load_env_file(env_path)
    import paramiko

    host = os.environ["SFTP_HOST"]
    port = int(os.environ.get("SFTP_PORT", "22"))
    user = os.environ["SFTP_USER"]
    password = os.environ["SFTP_PASSWORD"]
    remote_dir = os.environ.get("SFTP_DIR", ".")
    transport = paramiko.Transport((host, port))
    try:
        transport.connect(username=user, password=password)
        with paramiko.SFTPClient.from_transport(transport) as sftp:
            if remote_dir:
                sftp.chdir(remote_dir)
            sftp.put(str(local_path), remote_name)
    finally:
        transport.close()


def _write_rows(output_path: Path, rows: list[dict], fmt: str) -> None:
    """Write rows as jsonl/csv/tsv."""

    if fmt == "jsonl":
        with output_path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        return
    delimiter = "\t" if fmt == "tsv" else ","
    columns = list(rows[0].keys()) if rows else []
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, delimiter=delimiter)
        if columns:
            writer.writeheader()
            writer.writerows(rows)


def _send_file_ftp(local_path: Path, remote_name: str, env_path: Path) -> None:
    """Upload one file through FTP/FTPS using FTP_* environment variables."""

    load_env_file(env_path)
    host = os.environ["FTP_HOST"]
    port = int(os.environ.get("FTP_PORT", "21"))
    user = os.environ["FTP_USER"]
    password = os.environ["FTP_PASSWORD"]
    remote_dir = os.environ.get("FTP_DIR", "")
    use_tls = os.environ.get("FTP_TLS", "false").casefold() in {"1", "true", "yes"}
    ftp_cls = ftplib.FTP_TLS if use_tls else ftplib.FTP
    with ftp_cls() as ftp:
        ftp.connect(host, port, timeout=30)
        ftp.login(user, password)
        if use_tls:
            ftp.prot_p()
        if remote_dir:
            ftp.cwd(remote_dir)
        with local_path.open("rb") as handle:
            ftp.storbinary(f"STOR {remote_name}", handle)

def _sync_groups_json(state_dir: Path, store: StateStore) -> None:
    write_json(state_dir / "groups.json", [group.model_dump() for group in store.group_profiles()])


def _sync_archive_dirs(data_dir: Path, store: StateStore) -> None:
    builder = ArchiveBuilder(data_dir)
    for group in store.group_profiles():
        builder.ensure_group(group)


def _load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _read_json(path: Path) -> dict:
    """Read JSON files produced by either Python or PowerShell redirects."""

    data = path.read_bytes()
    for encoding in ("utf-8", "utf-8-sig", "utf-16"):
        try:
            return json.loads(data.decode(encoding))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    raise ValueError(f"unable to decode JSON file: {path}")


def _write_failure_report(root: Path, state_dir: Path, store: StateStore, exc: Exception) -> Path:
    """Write and send a best-effort report when the main pipeline aborts."""

    builder = DailyReportBuilder(state_dir, store, None)
    path = builder.write()
    report = _read_json(path)
    error_info = classify_error(exc)
    report["health"] = {
        "status": "critical" if error_info["severity"] == "fatal" else "warning",
        "alerts": [
            {
                "level": "critical" if error_info["severity"] == "fatal" else "warning",
                "code": error_info["category"],
                "message": str(exc),
            }
        ],
    }
    report["alerts"] = report["health"]["alerts"]
    report["problem_summary"] = [
        f"[{report['health']['alerts'][0]['level']}] {error_info['category']}: {exc}"
    ]
    write_json(path, report)
    try:
        notifier = load_notifier(root / "config" / "notifications.yaml", root, env_path=root / ".env")
        title, body = render_report_message(report)
        notifier.send(title, body, report)
    except Exception:
        pass
    return path


if __name__ == "__main__":
    main()
