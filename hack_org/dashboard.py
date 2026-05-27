"""Local operations dashboard for the APT intelligence pipeline."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import threading
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .db_config import load_database_config
from .pg_client import connect_database
from .utils import utcnow


ROOT = Path.cwd()
STATE_DB = ROOT / ".state" / "hack_org.sqlite"
LOG_DIR = ROOT / ".state" / "logs"
MAX_LOG_LINES = 1000


class RunState:
    """Track one dashboard-triggered pipeline subprocess."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.process: subprocess.Popen[str] | None = None
        self.started_at: str | None = None
        self.finished_at: str | None = None
        self.return_code: int | None = None
        self.command: list[str] = []
        self.lines: deque[str] = deque(maxlen=MAX_LOG_LINES)

    def is_running(self) -> bool:
        with self.lock:
            return self.process is not None and self.process.poll() is None

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "running": self.process is not None and self.process.poll() is None,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "return_code": self.return_code,
                "command": self.command,
                "logs": list(self.lines),
            }

    def start(self, command: list[str]) -> None:
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                raise RuntimeError("流水线正在运行，不能重复启动")
            self.lines.clear()
            self.started_at = utcnow().astimezone().isoformat(timespec="seconds")
            self.finished_at = None
            self.return_code = None
            self.command = command
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"
            self.process = subprocess.Popen(
                command,
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env,
            )
            process = self.process
        threading.Thread(target=self._pump_output, args=(process,), daemon=True).start()

    def _pump_output(self, process: subprocess.Popen[str]) -> None:
        assert process.stdout is not None
        for line in process.stdout:
            with self.lock:
                self.lines.append(line.rstrip("\n"))
        return_code = process.wait()
        with self.lock:
            self.return_code = return_code
            self.finished_at = utcnow().astimezone().isoformat(timespec="seconds")
            self.lines.append(f"[dashboard] 流水线进程结束，return_code={return_code}")


RUN_STATE = RunState()


def main() -> None:
    parser = argparse.ArgumentParser(description="Start the local hack_org dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8008)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"Dashboard running: http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


class DashboardHandler(BaseHTTPRequestHandler):
    """Very small JSON API plus a single-page dashboard."""

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(INDEX_HTML)
            return
        if parsed.path == "/api/status":
            self._send_json(build_status())
            return
        if parsed.path == "/api/run":
            self._send_json(RUN_STATE.snapshot())
            return
        if parsed.path == "/api/errors":
            query = parse_qs(parsed.query)
            limit = int(query.get("limit", ["80"])[0])
            self._send_json({"errors": latest_errors(limit)})
            return
        self.send_error(404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/run":
            self.send_error(404)
            return
        try:
            payload = self._read_json()
            command = build_pipeline_command(payload)
            RUN_STATE.start(command)
            self._send_json({"ok": True, "run": RUN_STATE.snapshot()})
        except Exception as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def build_pipeline_command(payload: dict[str, Any]) -> list[str]:
    collect = bool(payload.get("collect", True))
    collect_limit = int(payload.get("collect_limit", 25))
    article_limit = int(payload.get("article_limit", 50))
    workers = int(payload.get("workers", 4))
    model_workers = int(payload.get("model_workers", 1))
    timeout = int(payload.get("timeout", 25))
    proxy = str(payload.get("proxy") or "http://127.0.0.1:7890")
    article_order = str(payload.get("article_order") or "oldest")
    no_export = bool(payload.get("no_export", False))
    command = [
        sys.executable,
        "-u",
        "-m",
        "hack_org.cli",
        "run_daily_pipeline",
        "--article-limit",
        str(article_limit),
        "--article-order",
        article_order,
        "--workers",
        str(workers),
        "--model-workers",
        str(model_workers),
        "--timeout",
        str(timeout),
        "--proxy",
        proxy,
    ]
    if collect:
        command.extend(["--collect", "--collect-limit", str(collect_limit)])
    if no_export:
        command.append("--no-export")
    return command


def build_status() -> dict[str, Any]:
    status: dict[str, Any] = {
        "generated_at": utcnow().astimezone().isoformat(timespec="seconds"),
        "run": RUN_STATE.snapshot(),
        "sqlite": sqlite_status(),
        "postgres": pg_status(),
        "latest_errors": latest_errors(20),
    }
    return status


def sqlite_status() -> dict[str, Any]:
    if not STATE_DB.exists():
        return {"ok": False, "error": f"SQLite state db not found: {STATE_DB}"}
    conn = sqlite3.connect(STATE_DB)
    conn.row_factory = sqlite3.Row
    try:
        counts = {}
        for table in ("sources", "articles", "collection_runs", "system_logs", "groups", "group_aliases"):
            counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        sources = conn.execute(
            """
            SELECT s.id, s.name, s.type, s.enabled, s.category, s.tier,
                   cr.status, cr.started_at, cr.finished_at, cr.collected_count,
                   cr.inserted_count, cr.duplicate_count, cr.error
            FROM sources s
            LEFT JOIN (
              SELECT source_id, MAX(id) AS max_id
              FROM collection_runs
              GROUP BY source_id
            ) latest ON latest.source_id = s.id
            LEFT JOIN collection_runs cr ON cr.id = latest.max_id
            ORDER BY s.enabled DESC, s.tier, s.id
            """
        ).fetchall()
        return {
            "ok": True,
            "counts": counts,
            "sources": [dict(row) for row in sources],
        }
    finally:
        conn.close()


def pg_status() -> dict[str, Any]:
    try:
        config = load_database_config(ROOT / "config" / "database.yaml", ROOT / ".env")
        conn = connect_database(config)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    try:
        with conn.cursor() as cur:
            counts = {}
            for table in (
                "collected_documents",
                "document_group_matches",
                "model_runs",
                "group_facts",
                "fact_evidence",
                "group_relations",
                "group_members",
                "activity_events",
                "apt_group_export",
            ):
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                counts[table] = cur.fetchone()[0]
            cur.execute(
                """
                SELECT run_type, status, COUNT(*)
                FROM model_runs
                GROUP BY run_type, status
                ORDER BY run_type, status
                """
            )
            model_runs = [{"run_type": r[0], "status": r[1], "count": r[2]} for r in cur.fetchall()]
            cur.execute(
                """
                SELECT d.source_id, COUNT(*) AS pending
                FROM collected_documents d
                WHERE NOT EXISTS (
                  SELECT 1 FROM model_runs mr
                  WHERE mr.document_id = d.id
                    AND mr.run_type = 'article_extract'
                    AND mr.status = 'success'
                )
                GROUP BY d.source_id
                ORDER BY pending DESC
                LIMIT 20
                """
            )
            backlog = [{"source_id": r[0], "pending": r[1]} for r in cur.fetchall()]
            cur.execute(
                """
                SELECT tg.canonical_name, COUNT(gf.id) AS facts
                FROM threat_groups tg
                JOIN group_facts gf ON gf.group_id = tg.id
                GROUP BY tg.canonical_name
                ORDER BY facts DESC, tg.canonical_name
                LIMIT 20
                """
            )
            result_groups = [{"group": r[0], "facts": r[1]} for r in cur.fetchall()]
            cur.execute(
                """
                SELECT apt_organization, team_name, storage_time
                FROM apt_group_export
                ORDER BY storage_time DESC
                LIMIT 20
                """
            )
            exports = [{"apt_organization": r[0], "team_name": r[1], "storage_time": r[2]} for r in cur.fetchall()]
        return {
            "ok": True,
            "counts": counts,
            "model_runs": model_runs,
            "backlog": backlog,
            "result_groups": result_groups,
            "exports": exports,
        }
    finally:
        conn.close()


def latest_errors(limit: int) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    if not LOG_DIR.exists():
        return errors
    day_dirs = sorted([p for p in LOG_DIR.iterdir() if p.is_dir()], reverse=True)
    for day_dir in day_dirs:
        for name in ("error.log", "collection.log", "processing.log", "storage.log"):
            path = day_dir / name
            if not path.exists():
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            for line in reversed(lines):
                if " ERROR " in line or " CRITICAL " in line or "WARNING" in line:
                    errors.append({"date": day_dir.name, "file": name, "line": line})
                    if len(errors) >= limit:
                        return errors
    return errors


INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>APT 情报流水线仪表盘</title>
  <style>
    :root { color-scheme: light; --bg:#f6f7f9; --panel:#fff; --line:#d9dee7; --text:#18202a; --muted:#697386; --ok:#12805c; --warn:#b76e00; --bad:#b42318; --blue:#155eef; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: "Segoe UI", "Microsoft YaHei", Arial, sans-serif; background:var(--bg); color:var(--text); }
    header { position: sticky; top:0; z-index:2; background:#fff; border-bottom:1px solid var(--line); padding:14px 20px; display:flex; justify-content:space-between; align-items:center; gap:16px; }
    h1 { font-size:20px; margin:0; }
    main { padding:18px 20px 40px; max-width:1500px; margin:0 auto; }
    section { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; margin-bottom:14px; }
    h2 { font-size:16px; margin:0 0 12px; }
    .grid { display:grid; grid-template-columns: repeat(4, minmax(160px,1fr)); gap:10px; }
    .card { border:1px solid var(--line); border-radius:8px; padding:12px; background:#fbfcfe; }
    .num { font-size:24px; font-weight:700; margin-top:4px; }
    .muted { color:var(--muted); font-size:12px; }
    .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
    label { display:flex; flex-direction:column; gap:4px; font-size:12px; color:var(--muted); }
    input, select { height:32px; min-width:110px; border:1px solid var(--line); border-radius:6px; padding:0 8px; background:white; color:var(--text); }
    button { height:34px; border:1px solid #0f4fd7; border-radius:6px; background:var(--blue); color:#fff; padding:0 12px; cursor:pointer; font-weight:600; }
    button:disabled { opacity:.55; cursor:not-allowed; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th, td { text-align:left; padding:8px 7px; border-bottom:1px solid #edf0f5; vertical-align:top; }
    th { color:#475467; font-weight:600; background:#fafbfc; position:sticky; top:57px; }
    .status { display:inline-block; padding:2px 7px; border-radius:999px; font-size:12px; border:1px solid var(--line); }
    .success { color:var(--ok); background:#e9f8f1; border-color:#b7e4d0; }
    .failed, .fatal { color:var(--bad); background:#fff0ee; border-color:#f5c1ba; }
    .running { color:var(--blue); background:#eef4ff; border-color:#bdd2ff; }
    .warning { color:var(--warn); background:#fff7e6; border-color:#f4cf8d; }
    .logbox { height:360px; overflow:auto; background:#101828; color:#d0d5dd; border-radius:8px; padding:10px; font:12px/1.5 Consolas, monospace; white-space:pre-wrap; }
    .tabs { display:flex; gap:8px; margin-bottom:10px; }
    .tab { background:#fff; color:#344054; border-color:var(--line); }
    .tab.active { background:#155eef; color:#fff; border-color:#155eef; }
    .hidden { display:none; }
    @media (max-width: 900px) { .grid { grid-template-columns: repeat(2, minmax(140px,1fr)); } }
  </style>
</head>
<body>
<header>
  <h1>APT 情报流水线仪表盘</h1>
  <div class="row"><span class="muted" id="generatedAt">加载中</span><button onclick="refresh()">刷新</button></div>
</header>
<main>
  <section>
    <h2>启动流水线</h2>
    <div class="row">
      <label>采集<input id="collect" type="checkbox" checked /></label>
      <label>采集条数/源<input id="collectLimit" type="number" value="25" /></label>
      <label>处理文章数<input id="articleLimit" type="number" value="50" /></label>
      <label>并发<input id="workers" type="number" value="4" /></label>
      <label>超时秒<input id="timeout" type="number" value="25" /></label>
      <label>处理顺序<select id="articleOrder"><option value="oldest">最早积压优先</option><option value="newest">最新优先</option></select></label>
      <label>代理<input id="proxy" value="http://127.0.0.1:7890" /></label>
      <label>不导出<input id="noExport" type="checkbox" /></label>
      <button id="runBtn" onclick="startRun()">启动</button>
    </div>
  </section>

  <section>
    <h2>总览</h2>
    <div class="grid" id="cards"></div>
  </section>

  <section>
    <h2>实时运行输出</h2>
    <div class="muted" id="runMeta"></div>
    <div class="logbox" id="runLogs"></div>
  </section>

  <section>
    <div class="tabs">
      <button class="tab active" onclick="showTab('sources')">采集源</button>
      <button class="tab" onclick="showTab('model')">模型/API处理</button>
      <button class="tab" onclick="showTab('storage')">入库与最终结果</button>
      <button class="tab" onclick="showTab('errors')">错误</button>
    </div>
    <div id="tab-sources"></div>
    <div id="tab-model" class="hidden"></div>
    <div id="tab-storage" class="hidden"></div>
    <div id="tab-errors" class="hidden"></div>
  </section>
</main>
<script>
let statusData = null;

function esc(v){ return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function badge(status){
  const cls = status === 'success' ? 'success' : status === 'failed' ? 'failed' : status === 'running' ? 'running' : status ? 'warning' : '';
  return `<span class="status ${cls}">${esc(status || '无记录')}</span>`;
}
async function refresh(){
  const res = await fetch('/api/status');
  statusData = await res.json();
  render(statusData);
}
function render(data){
  document.getElementById('generatedAt').textContent = `刷新时间 ${data.generated_at}`;
  const s = data.sqlite || {};
  const p = data.postgres || {};
  const sc = s.counts || {};
  const pc = p.counts || {};
  const running = data.run?.running;
  document.getElementById('runBtn').disabled = !!running;
  document.getElementById('cards').innerHTML = [
    ['本地原始文章', sc.articles],
    ['PG采集文档', pc.collected_documents],
    ['待模型处理源数', (p.backlog || []).length],
    ['模型调用记录', pc.model_runs],
    ['基本事实', pc.group_facts],
    ['组织关系', pc.group_relations],
    ['活动事件', pc.activity_events],
    ['最终宽表', pc.apt_group_export],
  ].map(([k,v]) => `<div class="card"><div class="muted">${k}</div><div class="num">${esc(v ?? 0)}</div></div>`).join('');
  renderRun(data.run || {});
  renderSources(s.sources || []);
  renderModel(p);
  renderStorage(p);
  renderErrors(data.latest_errors || []);
}
function renderRun(run){
  document.getElementById('runMeta').textContent = run.running ? `运行中：${(run.command||[]).join(' ')}` : `状态：${run.return_code == null ? '空闲' : '已结束 return_code=' + run.return_code}`;
  const box = document.getElementById('runLogs');
  box.textContent = (run.logs || []).join('\n');
  box.scrollTop = box.scrollHeight;
}
function renderSources(rows){
  document.getElementById('tab-sources').innerHTML = `<table><thead><tr><th>源</th><th>类型</th><th>启用</th><th>最近状态</th><th>采集/新增/重复</th><th>完成时间</th><th>错误</th></tr></thead><tbody>` +
    rows.map(r => `<tr><td><b>${esc(r.name)}</b><br><span class="muted">${esc(r.id)} · ${esc(r.category)} · ${esc(r.tier)}</span></td><td>${esc(r.type)}</td><td>${r.enabled ? '是' : '否'}</td><td>${badge(r.status)}</td><td>${esc(r.collected_count||0)} / ${esc(r.inserted_count||0)} / ${esc(r.duplicate_count||0)}</td><td>${esc(r.finished_at || r.started_at || '')}</td><td>${esc(r.error || '')}</td></tr>`).join('') +
    `</tbody></table>`;
}
function renderModel(p){
  const model = p.model_runs || [];
  const backlog = p.backlog || [];
  document.getElementById('tab-model').innerHTML = `<h2>模型/API处理情况</h2><table><thead><tr><th>任务</th><th>状态</th><th>次数</th></tr></thead><tbody>` +
    model.map(r => `<tr><td>${esc(r.run_type)}</td><td>${badge(r.status)}</td><td>${esc(r.count)}</td></tr>`).join('') +
    `</tbody></table><h2 style="margin-top:16px">待处理积压</h2><table><thead><tr><th>来源</th><th>待处理数</th></tr></thead><tbody>` +
    backlog.map(r => `<tr><td>${esc(r.source_id)}</td><td>${esc(r.pending)}</td></tr>`).join('') +
    `</tbody></table>`;
}
function renderStorage(p){
  const groups = p.result_groups || [];
  const exports = p.exports || [];
  document.getElementById('tab-storage').innerHTML = `<h2>已有最终结果</h2><table><thead><tr><th>组织</th><th>基本事实数</th></tr></thead><tbody>` +
    groups.map(r => `<tr><td>${esc(r.group)}</td><td>${esc(r.facts)}</td></tr>`).join('') +
    `</tbody></table><h2 style="margin-top:16px">宽表最新记录</h2><table><thead><tr><th>APT组织</th><th>组织名称</th><th>更新时间</th></tr></thead><tbody>` +
    exports.map(r => `<tr><td>${esc(r.apt_organization)}</td><td>${esc(r.team_name)}</td><td>${esc(r.storage_time)}</td></tr>`).join('') +
    `</tbody></table>`;
}
function renderErrors(rows){
  document.getElementById('tab-errors').innerHTML = `<table><thead><tr><th>日期</th><th>文件</th><th>日志</th></tr></thead><tbody>` +
    rows.map(r => `<tr><td>${esc(r.date)}</td><td>${esc(r.file)}</td><td>${esc(r.line)}</td></tr>`).join('') +
    `</tbody></table>`;
}
function showTab(name){
  for (const id of ['sources','model','storage','errors']) document.getElementById('tab-'+id).classList.toggle('hidden', id!==name);
  document.querySelectorAll('.tab').forEach((el,i)=>el.classList.toggle('active', ['sources','model','storage','errors'][i]===name));
}
async function startRun(){
  const payload = {
    collect: document.getElementById('collect').checked,
    collect_limit: Number(document.getElementById('collectLimit').value),
    article_limit: Number(document.getElementById('articleLimit').value),
    workers: Number(document.getElementById('workers').value),
    model_workers: Number(document.getElementById('modelWorkers').value),
    timeout: Number(document.getElementById('timeout').value),
    proxy: document.getElementById('proxy').value,
    article_order: document.getElementById('articleOrder').value,
    no_export: document.getElementById('noExport').checked,
  };
  const res = await fetch('/api/run', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
  const data = await res.json();
  if(!data.ok) alert(data.error || '启动失败');
  await refresh();
}
refresh();
setInterval(refresh, 15000);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
