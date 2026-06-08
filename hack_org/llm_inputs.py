"""Builders for normalized LLM input payloads."""

from __future__ import annotations

import re
from typing import Any

from .models import Article, GroupProfile


AMBIGUOUS_TERMS = {
    "stop",
    "maze",
    "snake",
    "sandworm",
    "energy",
    "ghost",
}

AMBIGUOUS_REQUIRED_CONTEXT = {
    "stop": ("ransomware", "djvu"),
    "maze": ("ransomware",),
    "snake": ("malware", "ransomware", "keylogger"),
    "sandworm": ("apt", "threat actor", "group"),
    "energy": ("apt", "threat actor", "group"),
    "ghost": ("apt", "threat actor", "group"),
}

THREAT_CONTEXT_TERMS = (
    "apt",
    "threat actor",
    "ransomware",
    "malware",
    "campaign",
    "group",
    "actor",
    "intrusion",
)


def build_article_extract_variables(
    article_id: str,
    article: Article,
    groups: list[GroupProfile],
    *,
    pg_group_ids: dict[str, str] | None = None,
    group_context: dict[str, dict[str, Any]] | None = None,
    max_candidate_groups: int = 12,
    max_document_chars: int = 40000,
) -> dict[str, Any]:
    """Build prompt variables for article_extract from one normalized article."""

    candidate_groups = candidate_groups_for_article(article, groups, limit=max_candidate_groups)
    pg_group_ids = pg_group_ids or {}
    group_context = group_context or {}
    for group in candidate_groups:
        local_group_id = group["group_id"]
        group["organization_code"] = local_group_id
        group["group_id"] = pg_group_ids.get(local_group_id, local_group_id)
    context_groups = []
    for group in candidate_groups:
        organization_code = group["organization_code"]
        context = group_context.get(organization_code)
        context_groups.append(
            context
            or {
                "group_id": group["group_id"],
                "organization_code": organization_code,
                "canonical_name": group["canonical_name"],
                "known_aliases": group["aliases"],
                "known_facts": [],
                "known_relations": [],
                "latest_overview": None,
                "latest_structure_overview": None,
            }
        )
    text = article.text or ""
    truncated_text, text_truncated = truncate_text_middle(text, max_document_chars)
    metadata = dict(article.metadata)
    metadata["original_text_chars"] = len(text)
    metadata["text_truncated_for_model"] = text_truncated
    metadata["model_text_chars"] = len(truncated_text)
    return {
        "document_json": {
            "document_id": article_id,
            "source_id": article.source_id,
            "source_type": article.metadata.get("collector_type"),
            "source_tier": article.metadata.get("source_tier"),
            "source_category": article.metadata.get("source_category"),
            "source_title": article.source_title,
            "source_url": article.source_url,
            "source_domain": article.source_domain,
            "published_at": article.published_at.isoformat() if article.published_at else None,
            "collected_at": article.collected_at.isoformat(),
            "title": article.title,
            "author": article.author,
            "language": article.metadata.get("language"),
            "content_type": article.metadata.get("collector_type", "article"),
            "text": truncated_text,
            "metadata": metadata,
        },
        "candidate_groups_json": candidate_groups,
        "existing_database_context_json": {"groups": context_groups},
    }


def candidate_groups_for_article(article: Article, groups: list[GroupProfile], limit: int = 12) -> list[dict[str, Any]]:
    """Find exact canonical/alias mentions for one article."""

    haystack = f"{article.title}\n{article.text}"
    candidates: list[dict[str, Any]] = []
    for group in groups:
        matched_terms = sorted(
            {
                term
                for term in [group.canonical_name, *group.aliases]
                if term_matches(term, haystack)
            }
        )
        if matched_terms:
            candidates.append(
                {
                    "group_id": group.group_id,
                    "canonical_name": group.canonical_name,
                    "aliases": group.aliases,
                    "matched_terms": matched_terms[:10],
                }
            )
    candidates.sort(key=lambda item: len(item["matched_terms"]), reverse=True)
    return candidates[:limit]


def term_matches(term: str, text: str) -> bool:
    """Match organization terms conservatively for prompt context."""

    term = term.strip()
    if not term:
        return False
    ascii_term = term.isascii()
    if ascii_term and len(term) < 4 and not any(char.isdigit() for char in term):
        return False
    if ascii_term:
        pattern = rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])"
        match = re.search(pattern, text, flags=re.I)
        if not match:
            return False
        if term.casefold() in AMBIGUOUS_TERMS:
            window = text[max(0, match.start() - 120) : match.end() + 120].casefold()
            required = AMBIGUOUS_REQUIRED_CONTEXT.get(term.casefold(), THREAT_CONTEXT_TERMS)
            return any(context in window for context in required)
        return True
    return term.casefold() in text.casefold()


def truncate_text_middle(text: str, max_chars: int) -> tuple[str, bool]:
    """Keep the beginning and end of long source text for model extraction."""

    if max_chars <= 0 or len(text) <= max_chars:
        return text, False
    marker = "\n\n[MODEL_INPUT_TRUNCATED: middle content omitted]\n\n"
    keep = max(0, max_chars - len(marker))
    head = keep // 2
    tail = keep - head
    return f"{text[:head]}{marker}{text[-tail:]}", True
