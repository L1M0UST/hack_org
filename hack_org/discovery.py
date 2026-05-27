"""Discovery of organization names that are not yet in the local catalog."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .models import Article, GroupProfile
from .normalization import normalize_name
from .storage import StateStore

_CONTEXT_TERMS = (
    "threat actor", "actor", "group", "apt", "ransomware", "gang", "operation",
    "campaign", "intrusion set", "cluster", "tracked as", "known as", "dubbed",
    "named", "attributed", "espionage", "ecrime", "hacktivist", "malware"
)

_PATTERNS = [
    re.compile(r"(?:tracked as|known as|dubbed|named|called|referred to as)\s+(?:the\s+)?(?:threat actor\s+)?[\"'????]?([A-Z][A-Za-z0-9._\-]*(?:\s+[A-Z][A-Za-z0-9._\-]*){0,3})"),
    re.compile(r"\b((?:APT|TA|UNC|DEV|FIN)[-_ ]?\d{1,5})\b"),
    re.compile(r"\b(Storm[- ]\d{3,5}|Earth\s+[A-Z][A-Za-z0-9]+|Void\s+[A-Z][A-Za-z0-9]+)\b"),
    re.compile(r"\b([A-Z][A-Za-z0-9]+(?:\s+(?:Bear|Panda|Spider|Kitten|Tiger|Jackal|Hyena|Wolf|Lynx|Elephant|Chollima|Blizzard|Typhoon|Tempest|Sleet|Ghoul|Wombat|Mantis|Scarab|Cobra|Fly|Falcon|Eagle|Taurus|Lotus|Dragon|Crew|Team|Group|Gang|Collective|Ransomware))\b)"),
]

_STOPWORDS = {
    "Microsoft", "Google", "Cisco", "CrowdStrike", "Kaspersky", "Mandiant", "Palo Alto",
    "SentinelOne", "Proofpoint", "Trend Micro", "Check Point", "CISA", "NCSC", "GitHub",
    "Windows", "Linux", "Android", "Chrome", "Firefox", "WordPress", "Exchange", "SharePoint",
    "Threat Intelligence", "Security Blog", "Unit 42", "Securelist", "The Record",
}


@dataclass(frozen=True)
class DiscoveryResult:
    """Counters for one discovery pass."""

    articles_scanned: int
    candidates_found: int
    evidence_written: int


def discover_unknown_groups(store: StateStore, *, article_limit: int | None = None, min_confidence: float = 0.45) -> DiscoveryResult:
    """Scan collected documents for actor names absent from the known group/alias catalog."""

    groups = store.group_profiles()
    known = _known_names(groups)
    rows = store.article_records(limit=article_limit, order="newest")
    candidates_found = 0
    evidence_written = 0
    for row in rows:
        article = store.article_model_by_id(row["id"])
        if not article:
            continue
        for candidate in _extract_candidates(article):
            normalized = normalize_name(candidate["name"])
            if normalized in known or _is_bad_name(candidate["name"]):
                continue
            if candidate["confidence"] < min_confidence:
                continue
            candidates_found += 1
            store.upsert_discovered_group_candidate(
                candidate["name"],
                candidate["evidence_text"],
                article_id=row["id"],
                source_id=article.source_id,
                source_url=article.source_url,
                source_title=article.title,
                confidence=candidate["confidence"],
            )
            evidence_written += 1
    return DiscoveryResult(len(rows), candidates_found, evidence_written)


def _known_names(groups: list[GroupProfile]) -> set[str]:
    names: set[str] = set()
    for group in groups:
        for value in (group.canonical_name, *group.aliases, *group.search_terms):
            if value:
                names.add(normalize_name(value))
    return names


def _extract_candidates(article: Article) -> list[dict[str, Any]]:
    text = f"{article.title}\n{article.text or ''}"
    found: dict[str, dict[str, Any]] = {}
    for pattern in _PATTERNS:
        for match in pattern.finditer(text):
            name = _clean_name(match.group(1))
            if not name:
                continue
            window = text[max(0, match.start() - 180): match.end() + 220]
            confidence = _confidence(name, window, article)
            normalized = normalize_name(name)
            current = found.get(normalized)
            item = {"name": name, "confidence": confidence, "evidence_text": _compact(window)}
            if not current or confidence > current["confidence"]:
                found[normalized] = item
    return list(found.values())


def _confidence(name: str, window: str, article: Article) -> float:
    lowered = window.casefold()
    score = 0.35
    if any(term in lowered for term in _CONTEXT_TERMS):
        score += 0.25
    if re.search(r"\b(APT|TA|UNC|DEV|FIN)\s*[-_ ]?\d+\b", name, flags=re.I):
        score += 0.2
    if name.casefold() in (article.title or "").casefold():
        score += 0.15
    if any(term in lowered for term in ("target", "malware", "ransomware", "campaign", "espionage")):
        score += 0.1
    return min(score, 0.95)


def _clean_name(value: str) -> str:
    value = re.sub(r"\s+", " ", value.strip(" '\"????.,:;()[]{}<>"))
    value = re.sub(r"\s+(?:and|or|that|which|with|using|targeting|against)\b.*$", "", value, flags=re.I)
    return value[:80].strip()


def _compact(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()[:700]


def _is_bad_name(name: str) -> bool:
    if len(name) < 3 or len(name) > 80:
        return True
    if name in _STOPWORDS:
        return True
    if name.casefold() in {item.casefold() for item in _STOPWORDS}:
        return True
    if re.fullmatch(r"CVE[- ]?\d{4}[- ]?\d+", name, flags=re.I):
        return True
    lowered = name.casefold()
    noisy_phrases = (
        " into ", " behind ", " reduce ", " listed ", " maintains ", " repurposed ",
        " is an ", " is a ", " platform", " samples", " source code", " queue risk",
    )
    if any(phrase in f" {lowered} " for phrase in noisy_phrases):
        return True
    if sum(ch.isalpha() for ch in name) < 3:
        return True
    return False
