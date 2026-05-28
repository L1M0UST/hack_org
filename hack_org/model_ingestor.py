"""Dispatch validated model outputs into PostgreSQL tables."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from .pg_repository import PostgresRepository


class ModelOutputIngestor:
    """Route one validated model payload to the matching repository writes."""

    def __init__(self, repository: PostgresRepository) -> None:
        self.repository = repository

    def ingest(self, payload: dict[str, Any]) -> dict[str, int]:
        """Ingest one validated model payload and return write counters."""

        task_type = payload["task_type"]
        if task_type == "article_extract":
            return self._ingest_article_extract(payload)
        if task_type == "group_profile_synthesis":
            self.repository.apply_profile_synthesis(payload)
            return {"profile_syntheses": 1}
        if task_type == "group_structure_synthesis":
            self.repository.apply_structure_synthesis(payload)
            return {"structure_syntheses": 1}
        if task_type == "apt_group_export_synthesis":
            self.repository.upsert_apt_group_export(payload)
            return {"apt_group_exports": 1}
        raise ValueError(f"Unsupported task_type: {task_type}")

    def _ingest_article_extract(self, payload: dict[str, Any]) -> dict[str, int]:
        document_id = payload["document_id"]
        counters = {
            "matches": 0,
            "facts": 0,
            "relations": 0,
            "members": 0,
            "events": 0,
            "discarded_invalid_group_refs": 0,
        }
        valid_group_ids = self._valid_group_ids_from_payload(payload)
        for item in payload["matched_groups"]:
            if not _item_has_valid_group(item, valid_group_ids):
                counters["discarded_invalid_group_refs"] += 1
                continue
            self.repository.upsert_article_match(document_id, item)
            counters["matches"] += 1
        for item in payload["basic_profile_updates"]:
            if not _item_has_valid_group(item, valid_group_ids):
                counters["discarded_invalid_group_refs"] += 1
                continue
            if not _fact_passes_guardrails(item):
                continue
            item = _localize_fact_value(item)
            self.repository.append_fact_event(item, document_id)
            counters["facts"] += 1
        for item in payload["organization_structure_updates"]["relations"]:
            if not _item_has_valid_group(item, valid_group_ids):
                counters["discarded_invalid_group_refs"] += 1
                continue
            self.repository.append_structure_event(item, document_id, structure_type="relation")
            counters["relations"] += 1
        for item in payload["organization_structure_updates"]["members"]:
            if not _item_has_valid_group(item, valid_group_ids):
                counters["discarded_invalid_group_refs"] += 1
                continue
            self.repository.append_structure_event(item, document_id, structure_type="member")
            counters["members"] += 1
        for item in payload["activity_events"]:
            if not _item_has_valid_group(item, valid_group_ids):
                counters["discarded_invalid_group_refs"] += 1
                continue
            self.repository.append_activity_timeline_event(item, document_id)
            counters["events"] += 1
        return counters

    def _valid_group_ids_from_payload(self, payload: dict[str, Any]) -> set[str]:
        """Find official threat_group UUIDs referenced by model output; reject names and document ids."""

        candidates: set[str] = set()
        containers = [
            payload.get("matched_groups", []),
            payload.get("basic_profile_updates", []),
            payload.get("organization_structure_updates", {}).get("relations", []),
            payload.get("organization_structure_updates", {}).get("members", []),
            payload.get("activity_events", []),
        ]
        for items in containers:
            for item in items:
                group_id = str(item.get("group_id", ""))
                if _looks_like_uuid(group_id):
                    candidates.add(group_id)
        return self.repository.existing_group_ids(sorted(candidates))



def _looks_like_uuid(value: str) -> bool:
    try:
        UUID(str(value))
        return True
    except (TypeError, ValueError):
        return False


def _item_has_valid_group(item: dict[str, Any], valid_group_ids: set[str]) -> bool:
    group_id = str(item.get("group_id", ""))
    return group_id in valid_group_ids

def _fact_passes_guardrails(item: dict[str, Any]) -> bool:
    """Reject the highest-risk unsupported fact shapes before storage."""

    if item["fact_type"] == "suspected_source":
        return item["fact_value"].casefold() in item["evidence_text"].casefold()
    return True


def _localize_fact_value(item: dict[str, Any]) -> dict[str, Any]:
    """Prefer Chinese normalized values for human-readable fact categories."""

    chinese_display_types = {
        "target_country",
        "target_sector",
        "target_department",
        "attack_type",
        "attack_pattern",
        "tactic",
        "common_language",
        "victim_org",
    }
    normalized = item.get("normalized_value") or ""
    if item.get("fact_type") in chinese_display_types and _contains_cjk(normalized):
        item = dict(item)
        item["fact_value"] = normalized
    return item


def _contains_cjk(value: str) -> bool:
    return any("\u4e00" <= char <= "\u9fff" for char in value)
