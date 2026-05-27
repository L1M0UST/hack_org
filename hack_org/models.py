"""Shared data models for collection, processing, and archiving."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl


class GroupProfile(BaseModel):
    """Normalized group record imported from the input CSV."""

    group_id: str | None = None
    canonical_name: str
    description: str = ""
    aliases: list[str] = Field(default_factory=list)
    search_terms: list[str] = Field(default_factory=list)


class SourceConfig(BaseModel):
    """One configurable public intelligence source."""

    id: str
    name: str
    type: Literal["rss", "webpage", "api_json"]
    url: HttpUrl
    enabled: bool = True
    weight: float = 1.0
    headers: dict[str, str] = Field(default_factory=dict)
    method: str = "GET"
    category: str = "public_intel"
    tier: Literal["A", "B"] = "A"
    max_items: int | None = None
    fetch_full_article: bool = True
    keywords: list[str] = Field(default_factory=list)
    user_agent: str | None = None
    api_key_env: str | None = None
    auth_header: str | None = None
    auth_prefix: str = ""


class Article(BaseModel):
    """Collected public article or report before group-specific processing."""

    source_id: str
    source_title: str
    source_url: str
    source_domain: str
    published_at: datetime | None = None
    collected_at: datetime
    author: str | None = None
    html_path: str | None = None
    text_path: str | None = None
    title: str
    text: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class MatchResult(BaseModel):
    """Article relevance score and extracted entities for a group."""

    group_name: str
    article: Article
    confidence: float
    reasons: list[str]
    entities: dict[str, list[str]]
    topic: Literal["basic", "org", "timeline"]
