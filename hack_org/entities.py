"""Lightweight entity extraction for public threat intelligence text."""

from __future__ import annotations

import re


PATTERNS = {
    "cve": r"\bCVE-\d{4}-\d{4,7}\b",
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
    "url": r"https?://[^\s<>\"]+",
    "malware": r"\b(?:ransomware|backdoor|trojan|loader|stealer|wiper|rat|botnet|spyware)\b",
    "sector": r"\b(?:government|finance|financial|energy|healthcare|defense|telecom|education|technology)\b",
    "country": r"\b(?:China|Russia|North Korea|Iran|United States|Ukraine|South Korea|Japan|India|Vietnam)\b",
}


def extract_entities(text: str, aliases: list[str]) -> dict[str, list[str]]:
    """Extract common IOCs and contextual entities from article text."""

    entities: dict[str, set[str]] = {key: set() for key in [*PATTERNS, "alias", "threat_actor", "member_name", "org_name", "victim_org"]}
    for key, pattern in PATTERNS.items():
        for match in re.findall(pattern, text, flags=re.I):
            entities[key].add(match if isinstance(match, str) else match[0])
    lowered = text.lower()
    for alias in aliases:
        if alias and alias.lower() in lowered:
            entities["alias"].add(alias)
    for org in re.findall(r"\b[A-Z][A-Za-z0-9&.-]+(?:\s+[A-Z][A-Za-z0-9&.-]+){0,3}\b", text):
        if any(token in org.lower() for token in ("security", "ministry", "army", "bureau", "agency", "group")):
            entities["org_name"].add(org)
    return {key: sorted(values) for key, values in entities.items() if values}
