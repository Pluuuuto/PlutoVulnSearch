# PlutoVulnSearch 项目手册

版本：2025-08-14

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
  - [5. 日常自动化流程 (pipeline\_daily)](#5-日常自动化流程-pipeline_daily)
  - [6. LLM 版本区间抽取设计（增强）](#6-llm-版本区间抽取设计增强)
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
- es_id 生成策略：优先现成编号（CVE → CNVD → CNNVD）；都无则对描述拼接 MD5。
- risk_level 统一标准：映射 CVSS 或中文严重级别到 0~4。

---
## 4. 主要模块说明

### 4.1 db.py
- get_conn(): 懒加载单例连接，优先 PG_DSN 环境变量。
- ensure_schema(): 依次执行基础表 DDL + 视图 DDL。

### 4.2 各 ingestion 脚本 (CVE/ingest_cve.py 等)
流程：扫描数据目录 → 解析文件 → 批量 insert (ON CONFLICT DO NOTHING) → 记录跳过与失败。

### 4.3 llm_version_ranges.py
核心：`run_batch()` 可复用，一次处理一批（BATCH 条）任务并返回统计。

任务获取：
- TEST_MODE=true：随机抽样 TEST_LIMIT 条
- 否则：`merged_vulnerabilities_view` 中未达到当前 `EXTRACTOR_VER` 的 es_id（左连接 vuln_version_range 过滤）

多线程 & 并发：
- 线程池大小 `MAX_WORKERS`
- LLM 调用并发通过 `LLM_CONCURRENCY` (BoundedSemaphore) 限流

重试 / 回退 / 占位（保证“都有记录”）：
1. 每条初次调用 LLM；若失败或返回空 products：进入重试，最多 `LLM_RETRIES` 额外次数，指数退避时间 `LLM_RETRY_BACKOFF_BASE^(attempt-1)`（上限 10s）。
2. 全部尝试后仍失败/空且 `ENABLE_FALLBACK=true`：启用启发式 fallback（基于简单正则抓取版本，置信度低）。
3. 仍无结果且 `INSERT_PLACEHOLDER_ON_EMPTY=true`：写入占位记录 `product_id=placeholder, version 0.0.0`，置信度 0，用于完整性与后续再加工标记。

写入策略：
- 写入前删除同 es_id 旧记录（需要 DELETE 权限；若权限不足，可去掉删除，但会残留旧数据）。
- 区间归并：LLM items → `items_to_intervals()` 生成 (min_code,max_code) + version_text。
- 并发安全：每 task 在 worker 内再次 select 进行断点续跑检查，避免重复写入。

版本编码：`a*1e9 + b*1e6 + c*1e3 + d` 支持最多四段（含 u 转换）。

统计字段（run_batch 返回）：
`total_tasks, processed, skipped, empty, failed, inserted_products, elapsed_sec, fallback_used, placeholders, retry_total`。

升级 / 重新抽取：当算法优化或模型升级时提升 `EXTRACTOR_VER`，旧 es_id 会再次成为候选，从而覆盖占位或低质量记录。

### 4.4 pipeline_daily.py
日跑调度脚本：
1. 获取文件锁（带陈旧锁清理：超过 `LOCK_STALE_SECONDS` 自动删除）
2. ensure_schema (幂等创建表/视图)
3. 三源 ingest（各自返回 inserted / skipped / failed）
4. 多轮 LLM 抽取循环：
  - 调用 `llm_run_batch()`（即 `run_batch()` 导入别名）收集一轮 stats
  - 若本轮 `processed=0` 且 `VR_STOP_ON_ZERO=true` 则提前停止
  - 最多进行 `VR_MAX_LOOPS` 轮
  - 汇总 accumulated 统计与 per-loop detail
5. 组装 ES 文档（视图查询）
6. 若文档为空且 `ES_SKIP_IF_EMPTY=true`：跳过 ES；否则 ensure_index + bulk upsert (doc_as_upsert)
7. 输出 summary JSON（含 loops_detail）
8. 释放锁

退出码：
- 0 success
- 1 partial（任一源 ingest 失败条数>0 或 LLM 有 failed >0 或 ES 批量存在失败）
- 2 fatal（无法获取锁 / 未捕获异常）

### 4.5 search_es.py / search_db.py
- search_es: nested 版本范围查询（产品 + 版本号落在区间）。
- search_db: 关键词搜索封装（若未来加入 API）。

---
## 5. 日常自动化流程 (pipeline_daily)
增强版流程：
1. acquire_lock（带陈旧锁回收）
2. ensure_schema
3. ingest 三源（幂等追加）
4. 多轮 LLM 抽取（VR_MAX_LOOPS / VR_STOP_ON_ZERO 控制）
5. 构建 ES 文档列表；若空且 ES_SKIP_IF_EMPTY=true 则跳过
6. ensure_index（不存在时创建 mapping）
7. bulk upsert（_id=es_id，幂等覆盖）
8. 写 summary JSON（包含 version_ranges.loops_detail 与 accumulated）
9. 释放锁

稳健性：LLM 保证每条最终有一条记录（真实或 placeholder），避免后续视图/映射断裂；失败统计不会中断主流程，除非为致命错误。

---
## 6. LLM 版本区间抽取设计（增强）
输入：`affected_products` 原始产品与版本描述（多源字段标准化后的汇总）。
输出：标准 JSON（products 数组）。`items` 支持类型：`lt/lte/gt/gte/eq/range/wildcard/list`。

处理流水：
1. 任务筛选：按 `EXTRACTOR_VER` 过滤，确保升级后可重新处理旧数据。
2. LLM 调用：Qwen 接口；失败 / 非 200 / 解析异常抛错交由重试机制。
3. 重试：最多 1 + LLM_RETRIES 次；指数退避；判定“空”也算重试触发条件。
4. 回退：启用 `ENABLE_FALLBACK` 时对文本进行启发式拆分与版本正则抽取，生成 eq items。
5. 占位：若仍无结果且 `INSERT_PLACEHOLDER_ON_EMPTY` 为 true，写 placeholder 记录（product_id=placeholder, version=0.0.0）
6. 区间合并：`items_to_intervals()` 解析为离散区间 + 可读 `version_text`。
7. 写入：删除旧 es_id → UPSERT 每个区间；含 `extractor_ver` 以支持后续升级。

占位意义：保证下游 ES 文档嵌套结构存在 version_ranges 数组元素，便于统计“覆盖率”；未来提升 `EXTRACTOR_VER` 后会被覆盖。

统计指标：
- processed / failed / empty / skipped
- fallback_used（多少条使用回退）
- placeholders（写入占位的条数）
- retry_total（总重试次数，便于观测稳定性）
- inserted_products（写入的产品条目聚合）

再抽取策略：当模型或解析逻辑升级：提升 `EXTRACTOR_VER` → 旧数据全部重新纳入任务（包括 placeholder）。

---
## 7. Elasticsearch 索引与搜索
索引：vulnerabilities
字段：
- 基本元数据 (es_id, cve_id, cnvd_number, cnnvd_number, description, affected_products, solution, risk_display, risk_level)
- version_ranges (nested): product_id / min_code / max_code / confidence / version_text / extractor_ver
查询：
- 产品+版本：nested + range(min_code<=code<=max_code)
- 关键词：可添加 multi_match(description, affected_products, solution)
索引构建：pipeline_daily.ensure_index() 在不存在时创建 mapping（已替代旧 generate_index.py 脚本）。
更新策略：bulk index 覆盖（_id=es_id）。

---
## 8. 代码规范与约定
- 统一入口：pipeline_daily.py
- 数据追加：不更新历史行（无 updated_at）。
- 表/字段名：保持现有大小写（PostgreSQL 非带引号会折叠为小写）。
- 日志：模块独立日志 + pipeline 汇总 JSON。
- 并发：线程池 + 连接池 (llm_version_ranges)。
- 异常：捕获后分类为 partial 或 fatal。

---
## 9. 运维与部署建议
调度：Windows 任务计划程序 / cron（Linux）。

关键环境变量（补充）：
- 重试相关：LLM_RETRIES, LLM_RETRY_BACKOFF_BASE
- 回退 / 占位：ENABLE_FALLBACK, INSERT_PLACEHOLDER_ON_EMPTY
- 多轮：VR_MAX_LOOPS, VR_STOP_ON_ZERO
- 版本迭代：EXTRACTOR_VER（升级算法后递增）
- ES 优化：ES_SKIP_IF_EMPTY 避免空跑

健康检查：
1. 每日 summary JSON 解析：比对 `version_ranges.accumulated.processed + skipped + empty + failed` == `version_ranges.accumulated.total_tasks`（若未来加 total_tasks 聚合）
2. 占位比例：placeholders / processed（过高表示模型效果差）
3. 重试压力：retry_total / processed 平均值（>1 需关注）
4. Fallback 使用率：fallback_used / processed（上升表示主 LLM 质量或稳定性下降）
5. ES 文档计数 vs merged_vulnerabilities_view COUNT(*)（差距代表漏同步）

备份：
- PostgreSQL：逻辑备份 (pg_dump) + 定期校验
- ES：注册快照仓库（如使用）

安全：
- DSN 使用环境变量 / secrets 管理
- 内部 LLM 接口限制内网访问 + 日志脱敏（避免敏感 payload）

容量规划：
- version_ranges 行数 ≈ (平均产品数 * 漏洞数)，占位控制在可接受比例
- 索引 mapping 含 nested; 若数据增长大，可考虑分片数调整（当前默认 1）

---
## 10. 未来可扩展点
1. 增量策略：基于新文件时间戳或外部队列；或加入 ingestion_time 列。
2. 质量评估：对比 LLM 输出与规则提取结果自动回归验证。
3. 风险级别统一：引入专门 risk_score 数值模型。
4. API 服务：FastAPI 封装搜索、统计、导出。
5. 监控：Prometheus + Grafana（处理量 / 失败数 / LLM 耗时）。
6. 重试策略：已实现一次批内多次重试 + 多轮循环；可新增失败任务持久化队列实现延迟重试。
7. 产品名归一：基于别名字典或 embeddings 归一化 product_id；占位可作为人工标注起点。
8. 视图性能：改物化视图 + 定时 refresh。
9. 安全审核：对外部输出做脱敏处理（若涉及 POC）。
10. 国际化支持：多语言风险描述分字段。

---
(完)
