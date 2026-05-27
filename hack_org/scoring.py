"""Relevance scoring and topic classification."""

from __future__ import annotations

from rapidfuzz import fuzz

from .entities import extract_entities
from .models import Article, GroupProfile, MatchResult


def score_article(group: GroupProfile, article: Article, source_weight: float = 1.0) -> MatchResult | None:
    """Score whether an article is relevant enough to archive for a group."""

    title = article.title or article.source_title
    text = article.text or ""
    haystack = f"{title}\n{text}".lower()
    terms = [group.canonical_name, *group.aliases, *group.search_terms]
    title_hits = [term for term in terms if term and term.lower() in title.lower()]
    body_hits = [term for term in terms if term and haystack.count(term.lower()) >= 2]
    fuzzy = max((fuzz.partial_ratio(term.lower(), haystack) for term in terms if term), default=0)
    entities = extract_entities(text, group.aliases)
    reasons: list[str] = []
    score = 0.0
    if title_hits:
        score += 0.45
        reasons.append(f"title matched: {', '.join(sorted(set(title_hits))[:5])}")
    if body_hits:
        score += 0.3
        reasons.append(f"body repeated matches: {', '.join(sorted(set(body_hits))[:5])}")
    if fuzzy >= 92 and (title_hits or body_hits):
        score += 0.15
        reasons.append(f"high fuzzy match: {fuzzy:.0f}")
    if any(entities.get(key) for key in ("cve", "malware", "sector", "country", "alias")):
        score += 0.15
        reasons.append("supporting entities found")
    confidence = min(score * source_weight, 1.0)
    if confidence < 0.35:
        return None
    return MatchResult(
        group_name=group.canonical_name,
        article=article,
        confidence=round(confidence, 3),
        reasons=reasons or ["low-context source match"],
        entities=entities,
        topic=classify_topic(text),
    )


def classify_topic(text: str) -> str:
    """Classify article content into one of the three archival topics."""

    lowered = text.lower()
    if any(word in lowered for word in ("member", "subgroup", "ministry", "bureau", "attributed", "linked to")):
        return "org"
    if any(word in lowered for word in ("campaign", "observed", "targeted", "incident", "since", "timeline")):
        return "timeline"
    return "basic"
