"""Notification backends for daily operational reports."""

from __future__ import annotations

import os
import json
import subprocess
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx
import requests
import yaml
from .env_utils import load_env_file


class Notifier(Protocol):
    """Notification sender interface."""

    def send(self, title: str, body: str, report: dict[str, Any]) -> None:
        """Send one notification."""


class NullNotifier:
    """Disabled notification backend."""

    def send(self, title: str, body: str, report: dict[str, Any]) -> None:
        """Do nothing."""


@dataclass
class FileNotifier:
    """Write notification text to a local file."""

    output: Path

    def send(self, title: str, body: str, report: dict[str, Any]) -> None:
        """Persist the latest notification text."""

        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text(f"{title}\n\n{body}\n", encoding="utf-8")


@dataclass
class WebhookNotifier:
    """Generic JSON webhook notifier."""

    url: str

    def send(self, title: str, body: str, report: dict[str, Any]) -> None:
        """Post a generic JSON notification."""

        response = httpx.post(self.url, json={"title": title, "body": body, "report": report}, timeout=15)
        response.raise_for_status()


@dataclass
class WeComNotifier:
    """Enterprise WeChat group robot webhook notifier."""

    webhook_url: str

    def send(self, title: str, body: str, report: dict[str, Any]) -> None:
        """Send a markdown message to a WeCom group robot."""

        response = httpx.post(
            self.webhook_url,
            json={"msgtype": "markdown", "markdown": {"content": f"**{title}**\n\n{body}"}},
            timeout=15,
        )
        response.raise_for_status()


@dataclass
class TelegramNotifier:
    """Telegram bot notifier with optional proxy support."""

    bot_token: str
    chat_id: str
    proxy: str | None = None
    curl_wrapper: str | None = None

    def send(self, title: str, body: str, report: dict[str, Any]) -> None:
        """Send one text message through Telegram Bot API."""

        text = f"{title}\n\n{body}"
        proxies = None
        if self.proxy:
            proxies = {"http": self.proxy, "https": self.proxy}
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        chunks = _split_telegram_text(text)
        for index, chunk in enumerate(chunks, start=1):
            payload = {
                "chat_id": self.chat_id,
                "text": f"({index}/{len(chunks)})\n{chunk}" if len(chunks) > 1 else chunk,
                "disable_web_page_preview": True,
            }
            try:
                response = requests.post(url, json=payload, proxies=proxies, timeout=20)
                response.raise_for_status()
            except requests.RequestException as exc:
                try:
                    self._send_with_curl(url, payload)
                except RuntimeError as curl_exc:
                    raise RuntimeError(
                        f"Telegram send failed: {self._redact(str(exc))}; curl fallback: {self._redact(str(curl_exc))}"
                    ) from None

    def _send_with_curl(self, url: str, payload: dict[str, Any]) -> None:
        """Fallback to system curl for local proxy/TLS combinations."""

        curl_bin = shutil.which("curl") or shutil.which("curl.exe")
        if not curl_bin:
            raise RuntimeError("curl executable not found")
        command = [
            curl_bin,
            "-sS",
            "--fail",
            "--max-time",
            "30",
            "--http1.1",
            *(["--ssl-no-revoke"] if curl_bin.endswith("curl.exe") else []),
            "-H",
            "Content-Type: application/json",
            "-d",
            json.dumps(payload, ensure_ascii=False),
        ]
        if self.proxy:
            command.extend(["-x", self.proxy])
        command.append(url)
        if self.curl_wrapper:
            command = [self.curl_wrapper, *command]
        last_error = None
        for attempt in range(1, 4):
            result = subprocess.run(command, check=False, capture_output=True, text=True)
            if result.returncode == 0:
                return
            last_error = result.stderr.strip() or result.stdout.strip() or f"curl exit {result.returncode}"
            time.sleep(attempt)
        raise RuntimeError(f"Telegram curl fallback failed after retries: {self._redact(last_error or '')}")

    def _redact(self, value: str) -> str:
        """Remove bot token from network errors before surfacing them."""

        return value.replace(self.bot_token, "<telegram_bot_token>")


def load_notifier(config_path: Path, root: Path, env_path: Path | None = None) -> Notifier:
    """Load notifier from config."""

    if env_path:
        load_env_file(env_path)
    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))["notifications"]
    if not data.get("enabled", False):
        return NullNotifier()
    backend = str(data.get("backend", "file")).casefold()
    if backend == "file":
        return FileNotifier(root / data["file"]["output"])
    if backend == "webhook":
        return WebhookNotifier(_required_env(data["webhook"]["url_env"]))
    if backend == "wecom":
        return WeComNotifier(_required_env(data["wecom"]["webhook_url_env"]))
    if backend == "telegram":
        telegram_cfg = data["telegram"]
        proxy_env = telegram_cfg.get("proxy_env")
        proxy = os.environ.get(proxy_env) if proxy_env else None
        return TelegramNotifier(
            bot_token=_required_env(telegram_cfg["bot_token_env"]),
            chat_id=_required_env(telegram_cfg["chat_id_env"]),
            proxy=proxy,
            curl_wrapper=os.environ.get("TELEGRAM_CURL_WRAPPER"),
        )
    if backend == "wechat_qr":
        raise RuntimeError(
            "wechat_qr is not implemented because personal WeChat QR-login bots rely on unstable unofficial protocols. "
            "Use wecom/webhook/file, or add a custom Notifier implementation explicitly."
        )
    raise ValueError(f"Unsupported notification backend: {backend}")


def render_report_message(report: dict[str, Any]) -> tuple[str, str]:
    """Render a compact Chinese report notification."""

    status = report["health"]["status"]
    status_cn = _status_cn(status)
    title = f"APT 情报流水线日报 {report['date']} - {status_cn}"
    collection = report["collection"]
    processing = report["processing"]
    backlog = report["backlog"]
    lines = [
        f"健康状态：{status_cn}",
        f"采集概况：共 {collection['documents_collected']} 篇，新增 {collection['documents_inserted']} 篇，重复 {collection['documents_duplicate']} 篇",
        f"采集失败：{collection['failed_source_count']} 个来源，共 {collection['failed_run_count']} 次",
        f"模型抽取：成功 {processing['article_extract_success']} 次，失败 {processing['article_extract_failed']} 次",
        f"组织更新：{processing['groups_updated']} 次",
        f"待处理积压：{backlog.get('total_pending')}",
        "",
        "问题摘要：",
        *[f"- {line}" for line in report.get("problem_summary", [])],
    ]
    return title, "\n".join(lines)


def _status_cn(status: str) -> str:
    """Translate health status into Chinese."""

    return {"healthy": "正常", "warning": "警告", "critical": "严重"}.get(status, status)


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing notification env var: {name}")
    return value


def _split_telegram_text(text: str, max_chars: int = 3500, max_chunks: int = 5) -> list[str]:
    """Split Telegram messages under API limits without producing unbounded spam."""

    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    remaining = text
    while remaining and len(chunks) < max_chunks:
        chunk = remaining[:max_chars]
        split_at = max(chunk.rfind("\n"), chunk.rfind("。"), chunk.rfind("; "))
        if split_at > max_chars * 0.5:
            chunk = remaining[: split_at + 1]
        chunks.append(chunk)
        remaining = remaining[len(chunk) :]
    if remaining:
        chunks[-1] = chunks[-1][: max_chars - 80] + "\n...(后续内容已截断，完整内容见本地日报)"
    return chunks
