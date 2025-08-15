# PlutoVulnSearch 项目手册

版本：2025-08-15 (修订：统一遍历模式→默认补齐缺失 skip-existing / 去除 run_batch & 多轮变量 / 去除文件锁 / 视图 cve_id 简化)

## 目录
- [PlutoVulnSearch 项目手册](#plutovulnsearch-项目手册)
  - [目录](#目录)
  - [1. 项目概述](#1-项目概述)
  - [2. 总体架构与数据流](#2-总体架构与数据流)
  - [3. 数据库结构](#3-数据库结构)
    - [3.1 表 cve](#31-表-cve)
    - [3.2 表 cnvd](#32-表-cnvd)
    - [3.3 表 cnnvd](#33-表-cnnvd)
    - [3.4 表 vuln\_version\_range](#34-表-vuln_version_range)
    - [3.5 视图 merged\_vulnerabilities\_view](#35-视图-merged_vulnerabilities_view)
  - [4. 主要模块说明](#4-主要模块说明)
    - [4.1 db.py](#41-dbpy)
    - [4.2 各 ingestion 脚本 (CVE/ingest\_cve.py 等)](#42-各-ingestion-脚本-cveingest_cvepy-等)
    - [4.3 llm\_version\_ranges.py](#43-llm_version_rangespy)
    - [4.4 pipeline\_daily.py](#44-pipeline_dailypy)
    - [4.5 search\_es.py / search\_db.py](#45-search_espy--search_dbpy)
  - [5. 全量 vs 增量流程](#5-全量-vs-增量流程)
  - [6. LLM 版本区间抽取设计（统一遍历，补齐模式）](#6-llm-版本区间抽取设计统一遍历补齐模式)
    - [6.1 回退 (fallback) 与 占位 (placeholder) 判定规则补充](#61-回退-fallback-与-占位-placeholder-判定规则补充)
  - [7. Elasticsearch 索引与搜索](#7-elasticsearch-索引与搜索)
  - [8. 代码规范与约定](#8-代码规范与约定)
  - [9. 运维与部署建议](#9-运维与部署建议)
  - [10. 未来可扩展点](#10-未来可扩展点)

---
## 1. 项目概述
PlutoVulnSearch 聚合多个国内外漏洞数据源（CVE / CNVD / CNNVD），统一入库，抽取受影响产品版本区间，并同步到 Elasticsearch 提供检索与条件（产品+版本）查询能力。

目标：
- 标准化数据结构，去重与融合。
- 自动化每日增量采集与入库（当前为追加模式，不更新历史）。
- 基于 LLM 解析“受影响产品”自然语言字段，抽取规范化版本区间。
- 提供多维度检索接口（关键词、产品版本匹配）。

---
## 2. 总体架构与数据流
```
数据源文件(JSON/XML) ──> 解析(parser) ──> 基础表(cve / cnvd / cnnvd)
                                            │
                                            ├─> merged_vulnerabilities_view (融合视图 + es_id)
                                            │
LLM 抽取 (llm_version_ranges) ──> vuln_version_range (版本区间规范化)
                                            │
                              导出/聚合 ──> Elasticsearch 索引 vulnerabilities
                                            │
                                      查询 (search_es / search_db)
```
关键点：
- 视图 merged_vulnerabilities_view 负责跨源合并、生成统一 ID(es_id)。
- vuln_version_range 存储按产品+区间的数值化版本范围(min_code/max_code)。
- ES 文档嵌套 version_ranges，支持 nested 查询锁定特定产品和版本范围。

---
## 3. 数据库结构
使用 PostgreSQL。所有对象在 `ensure_schema()` 中集中创建。

### 3.1 表 cve
| 字段 | 类型 | 说明 |
|------|------|------|
| id | SERIAL PK | 内部自增 |
| cve_id | TEXT UNIQUE | CVE 标识 |
| published_date | DATE | 发布时间 |
| affected_products | TEXT | 自由文本（后续解析）|
| solution | TEXT | 修复方案 |
| cvss_score | NUMERIC(3,1) | CVSS 分值 |
| vuln_description | TEXT | 描述 |

### 3.2 表 cnvd
| 字段 | 类型 | 说明 |
| cnvd_number | TEXT UNIQUE | CNVD 编号 |
| title | TEXT | 标题 |
| severity | TEXT | 严重性（高/中/低）|
| products | TEXT | 影响产品文本 |
| cvenumber | TEXT | 对应 CVE（可能为空）|
| cveurl | TEXT | CVE 链接 |
| is_event | TEXT | 是否事件型 |
| submit_time | DATE | 提交时间 |
| open_time | DATE | 公布时间 |
| reference_link | TEXT | 参考链接 |
| discoverer_name | TEXT | 发现者 |
| formal_way | TEXT | 正式公布方式 |
| description | TEXT | 描述 |
| patch_name | TEXT | 补丁名 |
| patch_description | TEXT | 补丁说明 |

### 3.3 表 cnnvd
| 字段 | 类型 | 说明 |
| vuln_id | TEXT UNIQUE | CNNVD 编号 |
| name | TEXT | 漏洞名称 |
| published | DATE | 发布时间 |
| modified | DATE | 修改时间 |
| source | TEXT | 来源 |
| severity | TEXT | 严重性（低/中危/高危/超危）|
| vuln_type | TEXT | 类型 |
| vuln_descript | TEXT | 描述 |
| products | TEXT | 影响产品文本 |
| cve_id | TEXT | 关联 CVE |
| bugtraq_id | TEXT | 关联 Bugtraq |
| vuln_solution | TEXT | 解决方案 |

### 3.4 表 vuln_version_range
| 字段 | 类型 | 说明 |
| es_id | TEXT | 对应融合视图主键 |
| product_id | TEXT | 规范化产品名（小写）|
| min_code | BIGINT | 版本编码下界 |
| max_code | BIGINT | 版本编码上界 |
| confidence | REAL | 置信度 0~1 |
| version_text | TEXT | 可读区间表达 |
| source_text | TEXT | 原始片段（截断）|
| raw_hash | TEXT | source_text MD5 去重基准 |
| extractor_ver | INT | 抽取器版本（算法升级标记）|

主键：(es_id, product_id, min_code, max_code)
索引：es_id / product_id / (min_code, max_code)

### 3.5 视图 merged_vulnerabilities_view
作用：合并三源，生成统一 es_id，聚合描述、产品、解决方案、风险等级。
- es_id：优先 CVE → CNVD → CNNVD，否则描述拼接 MD5。
- cve_id：`UPPER(COALESCE(cve.cve_id, cnvd.cvenumber, cnnvd.cve_id))`。
- risk_level：映射 CVSS / 中文严重级别至 0~4。

---
## 4. 主要模块说明

### 4.1 db.py
- get_conn(): 懒加载单例连接，优先 PG_DSN 环境变量。
- ensure_schema(): 依次执行基础表 DDL + 视图 DDL。

### 4.2 各 ingestion 脚本 (CVE/ingest_cve.py 等)
流程：扫描数据目录 → 解析文件 → 批量 insert (ON CONFLICT DO NOTHING) → 记录跳过与失败。

说明：原先每个源目录下的 main.py 独立入口已移除，统一改为：
- 日常批处理：使用根目录 `pipeline_daily.py`
- 单源调试：直接运行对应 `ingest_*.py`（例如 `python CVE/ingest_cve.py`）
- 外部文件批量导入：通过 FastAPI `/upload` 接口（app.py）上传 JSON/NDJSON。

### 4.3 llm_version_ranges.py
统一单入口：`run_all_exhaustive(batch=None, progress_every=..., only_es_ids=None)`。

当前默认策略：补齐缺失 (skip-existing)。
- 全量：`only_es_ids=None` 仅抓取“尚未在 vuln_version_range 出现”的 es_id；已有记录跳过，不重复 LLM 调用。
- 增量：`only_es_ids=[...]` 对集合内再做缺失过滤，已有记录跳过。

强制重抽：手动删除目标 es_id 在 vuln_version_range 中的记录后再运行；未来可加入 `FORCE_FULL=1` 环境变量回退到全量重建模式。

并发与控制：MAX_WORKERS / LLM_CONCURRENCY / INTRA_BATCH_LOG_EVERY / HEARTBEAT_SEC 保持不变。

处理流水（单任务 worker）：
1. 读取 affected_products。
2. LLM 抽取 + 重试 (1 + LLM_RETRIES)。
3. 失败或空 → 回退 (ENABLE_FALLBACK)。
4. 仍空 → 占位 (INSERT_PLACEHOLDER_ON_EMPTY)。
5. 区间归并：items_to_intervals。
6. 写入：直接 INSERT（缺失补齐不需 DELETE）。

版本编码：`a*1e9 + b*1e6 + c*1e3 + d`；含 `u` 形式按规则编码。

统计返回：`total_tasks, processed, skipped_existing, empty, failed, inserted_products, inserted_rows, fallback_used, placeholders, retry_total, batches, elapsed_sec`。

再抽取：EXTRACTOR_VER 仅做标记，不触发自动重跑；需重跑先删记录或未来启用 FORCE_FULL。

### 4.4 pipeline_daily.py
全量脚本（无文件锁，假设单实例）：
1. ensure_schema
2. ingest 三源
3. run_all_exhaustive 补齐缺失（不重写已有）
4. 组装全部视图文档 → ES upsert
5. 输出 summary JSON

退出码：0 success / 1 partial / 2 fatal（未捕获异常）。

### 4.5 search_es.py / search_db.py
- search_es: nested 版本范围查询（产品 + 版本号落在区间）。
- search_db: 关键词搜索封装（若未来加入 API）。

---
## 5. 全量 vs 增量流程
全量补齐：`run_all_exhaustive()` 只处理缺失的 es_id（跳过已有）。
增量补齐：上传文件 → 解析出 es_id → 对该列表执行缺失补齐。
刷新策略：不再自动“删除+重写”；若需刷新某些 es_id，手动删除其记录后再运行。
占位：首次进入的 es_id 至少 1 条记录（真实或 placeholder）。

---
## 6. LLM 版本区间抽取设计（统一遍历，补齐模式）
输入：`affected_products` 原始产品与版本描述（多源字段标准化后的汇总）。
输出：标准 JSON（products 数组）。`items` 支持类型：`lt/lte/gt/gte/eq/range/wildcard/list`。

处理流水：
1. 任务抓取：批次遍历缺失 es_id（或限定集合后过滤缺失）；已有记录不进入任务队列。
2. LLM 调用：Qwen 接口；失败 / 非 200 / 解析异常 → 触发重试。
3. 重试：最多 1 + LLM_RETRIES 次；指数退避；空 products 也算重试触发条件。
4. 回退：启用 `ENABLE_FALLBACK` 时对文本进行启发式拆分与版本正则抽取，生成低置信度 eq / wildcard items。
5. 占位：若仍无结果且 `INSERT_PLACEHOLDER_ON_EMPTY` 为 true，写 placeholder 记录（product_id=placeholder, version=0.0.0）。
6. 区间合并：`items_to_intervals()` 解析为离散区间 + 可读 `version_text`。
7. 写入：直接 INSERT（缺失补齐不涉及 DELETE）。

简化：回退 = “尽量给可能真实的版本列表（低置信度）”；占位 = “保证结构统一”。

占位意义：确保 ES 文档 version_ranges 数组存在，便于统计覆盖率；后续手动清理 + 重跑可替换占位。

### 6.1 回退 (fallback) 与 占位 (placeholder) 判定规则补充

| 情形 | 触发条件 | 产生内容 | 典型原因 | 处理策略 |
|------|----------|----------|----------|----------|
| 正常 LLM 输出 | LLM 返回 products 且有 items | 直接解析写入 | 文本含清晰版本模式 | — |
| 回退 (fallback) | LLM 多次失败/异常 或 返回空 且 ENABLE_FALLBACK=true | 正则/启发式提取 1.2.3 / 5.6 / 7u45 / 8.x 等，生成 eq/wildcard items，低置信度 | 简单格式或 LLM 不稳定 | 给出候选，后续再覆盖 |
| 占位 (placeholder) | LLM 与回退都空 且 INSERT_PLACEHOLDER_ON_EMPTY=true | product_id=placeholder, 0.0.0 | 无版本号/泛描述 | 保证有结构，可后来重跑 |

示例：`"php php"` 无真实版本；已在回退阶段过滤纯字母短 token，避免历史上出现的 `invalid literal for int()` 日志；仍无版本 → 占位。

统计指标：
- processed / failed / empty / skipped_existing
- fallback_used / placeholders / retry_total
- inserted_products / inserted_rows / batches / elapsed_sec

再抽取策略：默认不重写；需重跑删除记录或未来 FORCE_FULL；EXTRACTOR_VER 用于结果分析与对比。

---
## 7. Elasticsearch 索引与搜索
索引：test_vulnerabilities（默认，可自定义）
字段：
- 基本元数据 (es_id, cve_id, cnvd_number, cnnvd_number, description, affected_products, solution, risk_display, risk_level)
- version_ranges (nested): product_id / min_code / max_code / confidence / version_text / extractor_ver
查询：
- 产品+版本：nested + range(min_code<=code<=max_code)
- 关键词：可添加 multi_match(description, affected_products, solution)
索引构建：pipeline_daily.ensure_index() 不存在时创建 mapping。
更新策略：bulk index 覆盖（_id=es_id）。

---
## 8. 代码规范与约定
- 统一入口：pipeline_daily.py
- 数据追加：不更新历史行（无 updated_at）。
- 表/字段名：保持现有大小写。
- 日志：模块独立日志 + pipeline 汇总 JSON。
- 并发：线程池 + 连接池 (llm_version_ranges)。
- 异常：分类为 partial 或 fatal。

---
## 9. 运维与部署建议
调度：Windows 任务计划程序 / cron（Linux）。

db_config.ini 约定：
```
[postgresql]
host=127.0.0.1
port=5432
dbname=YOUR_DB
user=xxx
password=xxx
```

关键环境变量：
- 重试相关：LLM_RETRIES, LLM_RETRY_BACKOFF_BASE
- 回退 / 占位：ENABLE_FALLBACK, INSERT_PLACEHOLDER_ON_EMPTY
- 版本迭代：EXTRACTOR_VER
- 批次与并发：BATCH, MAX_WORKERS, LLM_CONCURRENCY
- 批内日志：INTRA_BATCH_LOG_EVERY, HEARTBEAT_SEC
- ES 优化：ES_SKIP_IF_EMPTY

健康检查：
1. 占位比例 placeholders/processed
2. 回退使用率 fallback_used/processed
3. retry_total/processed 平均值
4. ES 文档计数 vs 视图 COUNT(*)
5. 插入速度与批次数量趋势

备份：
- PostgreSQL：pg_dump
- ES：快照仓库

安全：
- DSN 环境变量 / secrets
- 内部 LLM 接口仅内网
- 日志避免敏感数据

容量规划：
- version_ranges 行数 ≈ (平均产品数 * 漏洞数)
- nested 字段量大时关注 ES shard & 内存

---
## 10. 未来可扩展点
1. FORCE_FULL 模式：按需恢复全量重建。
2. 自动质量回归：抽样比对旧/新 extractor_ver 差异。
3. 产品名归一化：别名字典或 embedding 聚类。
4. 指标监控：Prometheus + Grafana。
5. 失败任务延迟重试队列。
6. 多语言描述拆分字段。
7. 物化视图 + 增量 refresh。
8. 更细粒度版本正则 / 语言适配。
9. ES pipeline 预处理 (ingest)。
10. Web 管理界面（任务 / 指标 / 重跑）。

---
(完)
