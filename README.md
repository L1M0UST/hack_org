# APT/黑客组织公开情报采集与文件归档系统

## 系统设计说明

本项目把 CSV 中的 APT/黑客组织作为归档对象，从可配置 Source Registry 中采集公开资料，并按组织维护本地文件库。系统分为六层：CSV 导入、组织实体规范化、公开源采集、文章处理、置信度与实体抽取、文件归档。

采集源不写死在业务逻辑里，统一放在 `config/sources.yaml`。当前支持 RSS 和普通网页，后续可以按同一 `SourceConfig` 模型扩展搜索 API、商业情报 API 或内部公告源。采集结果会保存原始 HTML 和清洗正文，处理阶段再根据组织名称、别名、标题命中、正文多次命中、CVE/恶意软件/目标行业等上下文计算置信度并输出 reasons。

组织实体层使用 SQLite 保存稳定 `group_id`、confirmed alias、CSV observation 和 MiMo/结构化来源产生的 alias evidence。系统只使用 `confirmed`、`manual_confirmed`、`auto_confirmed` 别名做自动合并，不做 fuzzy 合并，避免把相关组织错误合并。

归档目录围绕时间线和主题展开，每个组织固定包含 `基本情况`、`组织架构`、`活动时间` 和 `_meta`。`_meta` 保存索引、指纹、来源和运行日志，便于增量抓取、去重和审计。

## 项目目录结构

```text
hack_org/
  archive.py          # 本地归档结构和文件写入
  aliasing.py         # alias seed、MiMo证据导入、严格提示词
  cli.py              # import_csv/collect_sources/process_articles/build_group_files/generate_summary
  collectors.py       # RSS/网页采集，重试，超时，原文保存
  config.py           # Source Registry 加载
  entities.py         # IOC 和上下文实体抽取
  importer.py         # CSV 导入和 alias/search_terms 生成
  harvesting.py       # 并发采集、SQLite去重、全局采集日志、MiMo输入包
  models.py           # Pydantic 数据模型
  normalization.py    # 名称规范化和稳定group_id
  scoring.py          # 相关性评分、误报控制、主题分类
  storage.py          # SQLite状态库
  utils.py            # 路径、JSON、hash、时间工具
config/
  sources.yaml        # 可配置公开源 registry
  alias_seed.yaml     # 人工维护confirmed alias种子
data/
  <group_name>/
    基本情况/
    组织架构/
    活动时间/
    _meta/
.state/
  hack_org.sqlite
  groups.json
  articles.json
  matches.json
  logs/collection.jsonl
  mimo_inbox/articles_*.jsonl
  raw/
```

## 配置文件样例

```yaml
sources:
  - id: unit42
    name: Palo Alto Unit 42
    type: rss
    url: https://unit42.paloaltonetworks.com/feed/
    enabled: true
    weight: 0.95
```

## 安装

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

## CLI 使用

```powershell
python -m hack_org.cli import_csv
python -m hack_org.cli import_alias_seed
python -m hack_org.cli collect_sources --limit 25
python -m hack_org.cli process_articles
python -m hack_org.cli build_group_files
python -m hack_org.cli generate_summary
```

当前推荐的日常主流程已经收口为一个命令：

```powershell
python -m hack_org.cli run_daily_pipeline --collect --collect-limit 25 --workers 4 --proxy http://127.0.0.1:7890
```

这个命令会依次完成：

1. 同步来源与组织到 PostgreSQL。
2. 可选执行公开源采集。
3. 把尚未成功处理过的文章送入 MiMo 做 `article_extract`。
4. 记录每次模型运行到 `model_runs`。
5. 只对本轮受影响的组织刷新基本情况、组织结构和 `apt_group_export`。
6. 自动晋升高置信显式别名，并回写到本地 SQLite 身份层，供后续匹配使用。
7. 自动刷新 `data/` 归档目录，并生成 `.state/apt_group_export.tsv`。
8. 在输出摘要中返回本轮结束后的 backlog 情况，便于决定下一批跑多少。

如果你只想先小批量试跑待处理文章：

```powershell
python -m hack_org.cli run_daily_pipeline --article-limit 5
```

第一次补历史积压时，建议从最早的未处理文档开始：

```powershell
python -m hack_org.cli run_daily_pipeline --article-limit 20 --article-order oldest
```

查看还没有成功完成 `article_extract` 的文档积压：

```powershell
python -m hack_org.cli show_backlog
```

生成当天运行日报：

```powershell
python -m hack_org.cli build_daily_report
python -m hack_org.cli build_daily_report --send
```

日报会输出到 `.state/logs/YYYY-MM-DD/daily_report.json`，包括：

- 采集运行数、新增数、重复数、失败来源
- 模型运行数、成功抽取数、失败抽取数
- 当天被更新的组织
- 当前 backlog
- 关键 PostgreSQL 表计数
- `healthy / warning / critical` 健康状态与告警列表

## 报告通知

通知配置在 `config/notifications.yaml`。默认关闭。支持：

- `file`: 写入 `.state/notifications/latest_report.txt`
- `webhook`: 通用 JSON webhook
- `wecom`: 企业微信群机器人 webhook

企业微信机器人推荐配置方式：

```yaml
notifications:
  enabled: true
  backend: wecom
```

然后在 `.env` 中配置：

```env
WECOM_BOT_WEBHOOK_URL=
```

个人微信扫码登录机器人没有接入主流程。它依赖非官方协议，长期稳定性和账号风险不适合做自动化系统的默认通知通道。需要时可以在 `hack_org/notification.py` 中新增一个自定义 `Notifier` 后端，但建议优先用企业微信机器人、Server 酱、WxPusher 或通用 webhook。

Telegram 通知配置：

```yaml
notifications:
  enabled: true
  backend: telegram
```

`.env`：

```env
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
TELEGRAM_PROXY=http://127.0.0.1:7890
```

## 中文化策略

内部 JSON Schema key 和 PostgreSQL 原始列名保持英文，保证自动入库稳定；面向人看的内容使用中文：

- 日志 message 使用中文
- 日报与 Telegram 消息使用中文
- MiMo 输出的摘要、事实展示值、事件标题/摘要、组织简介使用中文
- 证据文本 `evidence_text` 保留原文，便于溯源
- 宽表提供中文视图 `apt_group_export_cn`
- `export_apt_table` 默认导出中文表头；如需英文表头，使用 `--english-headers`

生成与 `table.txt` 字段顺序一致、可直接导入的表数据：

```powershell
python -m hack_org.cli export_apt_table --output .state/apt_group_export.tsv --format tsv
python -m hack_org.cli export_apt_table --output .state/apt_group_export.csv --format csv
```

把 PostgreSQL 中的最新综合结果同步回 `data/` 归档目录：

```powershell
python -m hack_org.cli export_group_archives
```

## 原始数据对象存储

默认配置仍然只落本地文件。需要把原始材料同步到 MinIO 时，先把 `config/storage.yaml`
中的 `backend` 改为 `minio`，再在 `.env` 中补齐：

```env
MINIO_ENDPOINT=
MINIO_ACCESS_KEY=
MINIO_SECRET_KEY=
MINIO_BUCKET=
MINIO_SECURE=true
```

采集时会保留本地文件，同时把：

- `raw.html`
- `clean.txt`
- `meta.json`

上传为 `raw/<source_id>/<url_hash_prefix>/...`，并把对象键写入 PostgreSQL
`collected_documents.raw_object_key / clean_object_key / meta_object_key`。

采集时默认可走本地代理：

```powershell
python -m hack_org.cli collect_sources --limit 25 --workers 4 --proxy http://127.0.0.1:7890
```

如果不需要代理：

```powershell
python -m hack_org.cli collect_sources --limit 25 --workers 4 --proxy=
```

采集策略是“先全量落本地，再本地过滤/标注”。RSS 不在采集阶段丢弃文章，后续在 MiMo JSONL 中通过 `candidate_groups`、`keyword_hits`、`source_tier`、`source_category` 进行分析和筛选。当前 Source Registry 只维护 A/B 类来源：A 类厂商威胁研究/知识库，B 类政府公告/API。

采集层会把每篇新增文章写入 SQLite `articles` 表，同时保留：

- `.state/raw/<source_id>/<url_hash>/raw.html`
- `.state/raw/<source_id>/<url_hash>/clean.txt`
- `.state/raw/<source_id>/<url_hash>/meta.json`
- `.state/logs/collection.jsonl`
- `.state/mimo_inbox/articles_*.jsonl`

MiMo 输入采用 JSONL，一行一篇文章，字段尽量完整，包含 `article_id`、来源、URL、发布时间、采集时间、标题、正文、raw/clean/meta 文件路径、RSS entry 元数据、候选组织、关键词命中、来源权重和任务类型。后续清洗结果再单独写回 evidence 或结构化结果表。

推荐首次运行顺序：

```powershell
python -m hack_org.cli init_db
python -m hack_org.cli import_alias_seed
python -m hack_org.cli --csv hacker_organizations.csv import_csv
python -m hack_org.cli generate_summary
```

MiMo 接入时先让模型输出 JSON/JSONL evidence，再导入证据并自动保守晋级：

```powershell
python -m hack_org.cli mimo_alias_prompt
python -m hack_org.cli import_mimo_evidence .state/mimo_alias_evidence.jsonl
python -m hack_org.cli promote_aliases --min-confidence 0.88 --min-sources 2
python -m hack_org.cli list_alias_candidates
```

自动合并规则：CSV 完全重复行通过 `row_hash` 去重；新增组织如果命中已有 canonical name 或 confirmed alias，则归入同一 `group_id`；否则创建新 group。括号中的明确别名和 APT 编号会作为 confirmed alias 入库。

## 输出文件

每个组织会生成：

- `基本情况/overview.md`
- `基本情况/aliases.json`
- `基本情况/targets.json`
- `基本情况/ttps.md`
- `组织架构/org_links.md`
- `组织架构/members.json`
- `组织架构/subgroups.json`
- `活动时间/YYYY-MM-DD_<slug>.md`
- `_meta/index.json`
- `_meta/fingerprints.json`
- `_meta/sources.json`
- `_meta/run_log.jsonl`
