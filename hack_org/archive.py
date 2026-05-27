"""Filesystem archive builder for group profiles and matched articles."""

from __future__ import annotations

from pathlib import Path

from .models import GroupProfile, MatchResult
from .utils import TOPIC_DIRS, append_jsonl, sha256_text, slugify, utcnow, write_json


class ArchiveBuilder:
    """Create and maintain the requested local archive directory structure."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir

    def ensure_group(self, group: GroupProfile) -> Path:
        """Create the required topic and metadata directories for a group."""

        root = self.data_dir / slugify(group.canonical_name)
        for dirname in [*TOPIC_DIRS.values(), "_meta"]:
            (root / dirname).mkdir(parents=True, exist_ok=True)
        self._write_seed_files(root, group)
        return root

    def archive_match(self, group: GroupProfile, match: MatchResult) -> None:
        """Archive one matched article into metadata and a topic file."""

        root = self.ensure_group(group)
        fingerprints_path = root / "_meta" / "fingerprints.json"
        fingerprints = _read_json(fingerprints_path, {"urls": {}, "titles": {}, "texts": {}})
        url_hash = sha256_text(match.article.source_url)
        title_hash = sha256_text(match.article.title.lower())
        text_hash = sha256_text(match.article.text[:5000].lower())
        if url_hash in fingerprints.get("urls", {}):
            self._log(root, "duplicate_skipped", match)
            return
        fingerprints["urls"][url_hash] = match.article.source_url
        fingerprints["titles"][title_hash] = match.article.title
        fingerprints["texts"][text_hash] = match.article.text_path
        write_json(fingerprints_path, fingerprints)
        if match.topic == "timeline":
            self._write_timeline(root, match)
        elif match.topic == "org":
            self._append_org_link(root, match)
        else:
            self._append_ttp(root, match)
        self._update_sources(root, match)
        self._update_index(root)
        self._log(root, "archived", match)

    def _write_seed_files(self, root: Path, group: GroupProfile) -> None:
        basic = root / TOPIC_DIRS["basic"]
        org = root / TOPIC_DIRS["org"]
        meta = root / "_meta"
        overview = basic / "overview.md"
        if not overview.exists():
            overview.write_text(f"# {group.canonical_name}\n\n{group.description}\n", encoding="utf-8")
        write_json(basic / "aliases.json", {"aliases": group.aliases, "search_terms": group.search_terms})
        for path, seed in [
            (basic / "targets.json", {"countries": [], "sectors": [], "departments": []}),
            (org / "members.json", {"members": []}),
            (org / "subgroups.json", {"subgroups": [], "naming_map": []}),
            (meta / "fingerprints.json", {"urls": {}, "titles": {}, "texts": {}}),
            (meta / "sources.json", {"sources": []}),
        ]:
            if not path.exists():
                write_json(path, seed)
        for md in (basic / "ttps.md", org / "org_links.md"):
            if not md.exists():
                md.write_text(f"# {md.stem}\n", encoding="utf-8")

    def _write_timeline(self, root: Path, match: MatchResult) -> None:
        date = (match.article.published_at or match.article.collected_at).date().isoformat()
        path = root / TOPIC_DIRS["timeline"] / f"{date}_{slugify(match.article.title)}.md"
        entities = "\n".join(f"- {k}: {', '.join(v)}" for k, v in match.entities.items())
        reasons = "\n".join(f"- {reason}" for reason in match.reasons)
        path.write_text(
            f"# {match.article.title}\n\n"
            f"时间: {date}\n\n"
            f"摘要: {match.article.text[:600]}\n\n"
            f"来源: {match.article.source_title}\n\n"
            f"URL: {match.article.source_url}\n\n"
            f"关联实体:\n{entities or '- 无'}\n\n"
            f"置信度: {match.confidence}\n\n"
            f"reasons:\n{reasons}\n",
            encoding="utf-8",
        )

    def _append_org_link(self, root: Path, match: MatchResult) -> None:
        path = root / TOPIC_DIRS["org"] / "org_links.md"
        path.write_text(path.read_text(encoding="utf-8") + f"\n## {match.article.title}\n\n- URL: {match.article.source_url}\n- confidence: {match.confidence}\n", encoding="utf-8")

    def _append_ttp(self, root: Path, match: MatchResult) -> None:
        path = root / TOPIC_DIRS["basic"] / "ttps.md"
        entities = ", ".join([*match.entities.get("malware", []), *match.entities.get("cve", [])])
        path.write_text(path.read_text(encoding="utf-8") + f"\n## {match.article.title}\n\n- URL: {match.article.source_url}\n- entities: {entities or 'n/a'}\n- confidence: {match.confidence}\n", encoding="utf-8")

    def _update_sources(self, root: Path, match: MatchResult) -> None:
        path = root / "_meta" / "sources.json"
        data = _read_json(path, {"sources": []})
        item = {
            "source_title": match.article.source_title,
            "source_url": match.article.source_url,
            "source_domain": match.article.source_domain,
            "published_at": match.article.published_at.isoformat() if match.article.published_at else None,
            "collected_at": match.article.collected_at.isoformat(),
            "confidence": match.confidence,
            "reasons": match.reasons,
        }
        if item["source_url"] not in {source.get("source_url") for source in data["sources"]}:
            data["sources"].append(item)
        write_json(path, data)

    def _update_index(self, root: Path) -> None:
        files = [str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()]
        write_json(root / "_meta" / "index.json", {"updated_at": utcnow().isoformat(), "files": sorted(files)})

    def _log(self, root: Path, event: str, match: MatchResult) -> None:
        append_jsonl(root / "_meta" / "run_log.jsonl", {"event": event, "at": utcnow().isoformat(), "url": match.article.source_url})


def _read_json(path: Path, default):
    if not path.exists():
        return default
    import json

    return json.loads(path.read_text(encoding="utf-8"))
