# PlutoVulnSearch 项目手册

版本：2025-08-12

## 目录
- [1. 项目概述](#1-项目概述)
- [2. 总体架构与数据流](#2-总体架构与数据流)
- [3. 数据库结构](#3-数据库结构)
- [4. 主要模块说明](#4-主要模块说明)
- [5. 日常自动化流程 (pipeline_daily)](#5-日常自动化流程-pipeline_daily)
- [6. LLM 版本区间抽取设计](#6-llm-版本区间抽取设计)
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
核心：run_batch() 抽出为可复用接口。
- 预取任务：随机（TEST_MODE）或未处理 es_id 列表（按 extractor_ver 过滤去重）。
- 多线程 worker：
  1. 再次去重（防并发重复）
  2. 调 Qwen 返回 JSON
  3. 解析 items → 区间 → UPSERT
- 版本编码：a*1e9 + b*1e6 + c*1e3 + d
- 区间表达：<=X, >=Y, A-B, 组合 AND。

### 4.4 pipeline_daily.py
日跑调度脚本：锁 → ensure_schema → 三源 ingest → run_batch() → 建索引 & bulk upsert ES → 输出 summary JSON。

### 4.5 search_es.py / search_db.py
- search_es: nested 版本范围查询（产品 + 版本号落在区间）。
- search_db: 关键词搜索封装（若未来加入 API）。

---
## 5. 日常自动化流程 (pipeline_daily)
步骤：
1. acquire_lock: 文件锁避免并行。
2. ensure_schema: 保证结构存在。
3. run_ingest 三源：返回 inserted / skipped / failed。
4. llm_run_batch: 解析新增漏洞的版本范围。
5. ensure_index + bulk_upsert_es: 构建/刷新 ES 文档。
6. 输出 summary：写入 log/pipeline_summary_*.json。
7. release_lock。

失败与退出码：
- fatal: 锁失败 / 未捕获异常 → 2
- partial: ingest 某源失败或 ES 有失败条目 → 1
- success: 0

---
## 6. LLM 版本区间抽取设计
输入：affected_products 自由文本。
输出：products 数组，每个含 product_id / items / confidence。
items -> 统一语义：lt/lte/gt/gte/eq/range/wildcard/list。
区间合并逻辑：items_to_intervals() 将开放/闭合端点组合为连续区间。
去重策略：删除原 es_id 旧记录 + UPSERT 确保同区间幂等；raw_hash 便于未来变更检测。
并发控制：BoundedSemaphore(LLM_CONCURRENCY)。
错误处理：异常回滚该任务；统计 failed。

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
环境变量：PG_DSN / ES_URL / QWEN_COMPLETION_URL / MAX_WORKERS / LLM_CONCURRENCY。
健康检查：
- 每日 summary JSON → 监控平台
- ES 文档总数 vs merged_vulnerabilities_view 计数
备份：
- PostgreSQL 定期逻辑备份 (pg_dump)
- ES 快照（如启用）
安全：
- DSN 走环境变量；避免硬编码密码
- LLM 内部服务访问需网络 ACL

---
## 10. 未来可扩展点
1. 增量策略：基于新文件时间戳或外部队列；或加入 ingestion_time 列。
2. 质量评估：对比 LLM 输出与规则提取结果自动回归验证。
3. 风险级别统一：引入专门 risk_score 数值模型。
4. API 服务：FastAPI 封装搜索、统计、导出。
5. 监控：Prometheus + Grafana（处理量 / 失败数 / LLM 耗时）。
6. 重试策略：LLM 调用失败的 es_id 入队二次处理。
7. 产品名归一：基于别名字典或 embeddings 归一化 product_id。
8. 视图性能：改物化视图 + 定时 refresh。
9. 安全审核：对外部输出做脱敏处理（若涉及 POC）。
10. 国际化支持：多语言风险描述分字段。

---
(完)
