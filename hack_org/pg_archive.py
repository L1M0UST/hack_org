"""Filesystem exports derived from PostgreSQL synthesis tables."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import TOPIC_DIRS, slugify, utcnow, write_json


EVENT_TYPE_CN = {
    "campaign": "活动",
    "intrusion": "入侵",
    "disclosure": "披露",
    "attribution": "归因",
    "arrest": "逮捕",
    "tooling": "工具变化",
    "vulnerability_exploitation": "漏洞利用",
    "other": "其他",
}


class PostgresArchiveExporter:
    """Write human-readable per-group files from PostgreSQL snapshots."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir

    def export(self, snapshots: list[dict[str, Any]]) -> int:
        """Write one archive tree per group and return count."""

        for snapshot in snapshots:
            self._export_group(snapshot)
        return len(snapshots)

    def _export_group(self, snapshot: dict[str, Any]) -> None:
        root = self.data_dir / slugify(snapshot["canonical_name"])
        basic = root / TOPIC_DIRS["basic"]
        org = root / TOPIC_DIRS["org"]
        timeline = root / TOPIC_DIRS["timeline"]
        meta = root / "_meta"
        for path in (basic, org, timeline, meta):
            path.mkdir(parents=True, exist_ok=True)

        overview = snapshot["latest_overview"] or f"# {snapshot['canonical_name']}\n"
        (basic / "overview.md").write_text(overview.rstrip() + "\n", encoding="utf-8")
        write_json(
            basic / "aliases.json",
            {
                "organization_code": snapshot["organization_code"],
                "aliases": snapshot["aliases"],
            },
        )
        write_json(basic / "facts.json", {"facts": snapshot["facts"]})

        structure_text = snapshot["latest_structure_overview"] or ""
        (org / "overview.md").write_text(structure_text.rstrip() + "\n", encoding="utf-8")
        write_json(org / "relations.json", {"relations": snapshot["relations"]})
        write_json(org / "members.json", {"members": snapshot["members"]})

        write_json(timeline / "events.json", {"events": snapshot["events"]})
        timeline_lines = [f"# {snapshot['canonical_name']} 活动时间线"]
        for event in snapshot["events"]:
            date = event["event_date"] or "unknown"
            event_type = EVENT_TYPE_CN.get(event["event_type"], event["event_type"])
            timeline_lines.append(
                f"- {date} | {event_type} | {event['title']} | {event['summary']}"
            )
        (timeline / "timeline.md").write_text("\n".join(timeline_lines).rstrip() + "\n", encoding="utf-8")

        write_json(
            meta / "snapshot.json",
            {
                "exported_at": utcnow().isoformat(),
                "group_id": snapshot["group_id"],
                "organization_code": snapshot["organization_code"],
                "canonical_name": snapshot["canonical_name"],
            },
        )
