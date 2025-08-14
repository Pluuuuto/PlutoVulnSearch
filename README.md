# PlutoVulnSearch

集中式收集 + 结构化提取 + 搜索 的漏洞数据管道。

## 目录
- 背景与目标
- 系统架构
- 主要组件
- 数据库与索引
- 运行方式
- 环境变量
- 每日自动流程 (pipeline_daily)
- LLM 版本范围抽取
- 手动常用操作
- 开发与测试
- 目录结构
- 常见问题

## 背景与目标
全量（按需）或定时：爬取 (CVE / CNVD / CNNVD) 最新数据 → 写入 PostgreSQL → 调用 LLM 抽取受影响产品版本范围 → 同步至 Elasticsearch。新增单个源文件可通过 API 增量快速导入；历史补齐/再抽取走全量脚本。模式为追加，不做更新/删除。

## 系统架构
```
[Sources(XML/HTML)] -> [Parsers] -> PostgreSQL (raw tables)
                                      \
                                       +--> LLM 抽取 (vuln_version_range)
                                                \
                                                 -> 合并视图 merged_vulnerabilities_view -> Elasticsearch index
FastAPI (keyword / 条件搜索) 直接查 ES
```

## 主要组件
| 模块 | 功能 |
|------|------|
| db.py | 统一连接 + 初始化 schema/view |
| CNNVD/, CNVD/, CVE/ | 各数据源 parser + ingest 脚本 |
| llm_version_ranges.py | 统一遍历方式调用 LLM 提取版本区间（run_all_exhaustive + only_es_ids 增量） |
| pipeline_daily.py | 全量流程：爬取→入库→单次遍历 LLM→全量 ES 同步 |
| search_db.py / search_es.py | 关键字 / 产品+版本 搜索 |
| PROJECT_MANUAL.md | 更完整的设计/维护手册 |

## 数据库与索引
表：cve / cnvd / cnnvd (结构相似) + vuln_version_range
视图：merged_vulnerabilities_view 聚合三源并生成统一 es_id；cve_id 简化为 COALESCE(cve.cve_id, cnvd.cvenumber, cnnvd.cve_id)。
ES 索引：test_vulnerabilities (嵌套字段 version_ranges，默认名称，可自定义)。

## 运行方式
### 1. 安装依赖
```powershell
pip install -r requirements.txt
```

### 2. 准备 PostgreSQL / Elasticsearch
- Postgres 建库并提供连接 (PG_DSN)
- pipeline_daily 会自动检测并创建 Elasticsearch 索引，无需手动脚本

### 3. 全量导入（首次或周期性补齐）
```powershell
python pipeline_daily.py
```
说明：
- 若 data 目录缺失或为空，ingest 步骤会自动跳过（或仅记录 partial），不会阻断后续 LLM/ES 合并。
- 只要数据库三表已有数据，仍会自动合并视图并同步 ES。
- 适合“只做合并+ES重刷”场景。

### 4. 启动 API 服务（/search 与 /upload 增量导入）
```powershell
uvicorn app:app --reload --port 8000
```

### 5. 增量导入示例
上传单文件并触发增量（单轮 LLM/ES 针对该文件）：
```powershell
curl -X POST "http://127.0.0.1:8000/upload?src=cve&mode=incremental" -F "file=@CVE_2025_08_14.json"
```
或用辅助脚本：
```powershell
python main.py --file CVE/data/2025-08-14.json --src cve
```
不传 --file 调用脚本即执行全量：
```powershell
python main.py
```

### 6. 数据库已有数据时的全量/合并行为
- pipeline_daily.py 或 main.py（无 --file）会自动合并数据库三表，无需本地 data 文件夹。
- ingest 步骤如遇缺失仅标记 partial，不影响 LLM/ES 合并。
- 只要表有数据，视图和 ES 都会被重建/同步。

### 7. 离线构建 / 无网环境部署
目标：目标服务器无外网，仅能接收打包文件或镜像。

方式 A：直接传输已构建镜像
```powershell
# 有网环境
docker build -t pluto-vulnsearch:latest .
docker save -o pluto-vulnsearch.tar pluto-vulnsearch:latest

# 复制 pluto-vulnsearch.tar 到离线机器
docker load -i pluto-vulnsearch.tar
docker run -d -p 8000:8000 --name vuln pluto-vulnsearch:latest
```

方式 B：离线重新构建（预下所有依赖）
```powershell
# 有网环境：下载依赖 wheel
mkdir wheels
pip download -r requirements.txt -d wheels

# 打包源码 + wheels 目录传输后：
docker build -f Dockerfile.offline -t pluto-vulnsearch:offline .
docker run -d -p 8000:8000 --name vuln pluto-vulnsearch:offline
```

提示：
- wheels 目录不要被 .dockerignore 排除。
- 若要跑每日 ETL 改 CMD 为：`python pipeline_daily.py`。
- PostgreSQL 与 Elasticsearch 需独立提供（或使用 docker-compose 编排）。

## 环境变量
| 名称 | 默认 | 说明 |
|------|------|------|
| PG_DSN | host=localhost port=5432 dbname=vul user=test password=test | PostgreSQL 连接串（或使用 db_config.ini） |
| ES_URL / ES_HOST | http://localhost:9200 | Elasticsearch 地址 |
| ES_INDEX | test_vulnerabilities | 索引名 (默认 test_vulnerabilities) |
| QWEN_COMPLETION_URL | (需配置) | LLM 接口地址 |
| QWEN_MODEL | Qwen | 模型名 |
| BATCH | 1000 | 每批从数据库抓取任务上限 |
| MAX_WORKERS | 8 | 线程池大小（批次内并发 worker 数） |
| LLM_CONCURRENCY | 4 | 实际 LLM 调用并发上限 (信号量) |
| REQUEST_TIMEOUT | 60 | 单次 LLM 请求超时秒 |
| LLM_RETRIES | 2 | LLM 失败或空结果时额外重试次数（不含首次） |
| LLM_RETRY_BACKOFF_BASE | 1.5 | 重试指数退避基数 (sleep = base^(attempt-1) 上限10s) |
| ENABLE_FALLBACK | true | LLM 失败/空结果后启用启发式回退抽取 |
| INSERT_PLACEHOLDER_ON_EMPTY | true | 最终仍无结果时写入占位 (product_id=placeholder, 0.0.0) 保证有记录 |
| EXTRACTOR_VER | 1 | 版本抽取器版本号（用于跳过已处理数据） |
| LLM_THREADS | 4 | pipeline 兼容参数（实际并发由 MAX_WORKERS/LLM_CONCURRENCY 控制） |
| INTRA_BATCH_LOG_EVERY | 100 | 单批内处理多少条输出一次进度日志 |
| HEARTBEAT_SEC | 30 | 单批内若超过该秒数无完成则输出心跳进度 |
| (已废弃 TEST_MODE / TEST_LIMIT / VR_MAX_LOOPS / VR_STOP_ON_ZERO) |  | 统一遍历后不再使用，多轮逻辑已删除 |
| ES_SKIP_IF_EMPTY | true | 当无文档需要写入时跳过 ES 同步 |

## 全量流程 (pipeline_daily) 与 增量 (/upload)
全量（pipeline_daily / main 无文件参数）：
1. ensure_schema
2. ingest 三源（幂等追加）
3. run_all_exhaustive 一次性遍历所有未达到当前 EXTRACTOR_VER 的 es_id（不再多轮）
4. 汇总视图全部文档 → ES bulk upsert
5. 输出 summary JSON

增量（/upload mode=incremental）：
1. 解析上传文件并入库（新 es_id）
2. run_all_exhaustive(only_es_ids=[...])：仅遍历该集合直到处理完（跳过已存在 >=EXTRACTOR_VER 的）
3. 仅同步这些 es_id 到 ES（bulk）
4. 返回统计

mode=full 仍执行全量 run_all_exhaustive。

失败与健壮性：
- LLM：重试 → 回退 → 占位。
- ES：失败计数不阻断。
- 全量 summary 标记 partial 若存在失败。

## LLM 版本范围抽取
统一遍历模式：
1. 每批（BATCH）查询未达当前 EXTRACTOR_VER 的 es_id；若指定 only_es_ids 则限定集合。
2. 批次内线程池 (MAX_WORKERS) 并发 worker；LLM 调用再受 LLM_CONCURRENCY 信号量节流。
3. 每条：LLM 调用 → 重试 (LLM_RETRIES, 指数退避) → 回退启发式 (ENABLE_FALLBACK) → 占位 (INSERT_PLACEHOLDER_ON_EMPTY)。
4. 写入：先 DELETE 旧记录，再 UPSERT 新区间；占位将被后续更高 EXTRACTOR_VER 覆盖。
5. 日志：
  - 批次开始/结束统计 (processed / failed / empty / skipped / placeholders / fallback / rows)。
  - 批次内每 INTRA_BATCH_LOG_EVERY 条日志进度；若超 HEARTBEAT_SEC 未有完成输出心跳。
6. 统计字段（最终汇总）：total_tasks, processed, skipped, empty, failed, inserted_products, inserted_rows, fallback_used, placeholders, retry_total, batches, elapsed_sec。

## 手动常用操作
单独运行 LLM 抽取:
```powershell
python llm_version_ranges.py
```

## 开发与测试
快速单测（版本区间函数）：
```powershell
python test_llm_version_ranges.py
```
建议：
- 新增字段：先改视图 / 索引 mapping，再改搜索代码
- 大批量导入：未来可改为 COPY 或批量事务

## 目录结构 (节选)
```
PlutoVulnSearch/
  db.py
  pipeline_daily.py
  llm_version_ranges.py
  search_es.py
  CNNVD/ CNVD/ CVE/ (各源脚本、parser、数据)
  PROJECT_MANUAL.md
  README.md
  requirements.txt
```

## 常见问题
Q: 连接失败？
A: 检查 PG_DSN 或 db_config.ini；确认网络与权限。

Q: ES 写入 403？
A: 若有认证需在代码里加 basic_auth；当前默认公开集群。

Q: LLM 超时 / 429？
A: 已内置重试 + 指数退避，可调 LLM_RETRIES / LLM_RETRY_BACKOFF_BASE；必要时降低 LLM_CONCURRENCY 或提升 REQUEST_TIMEOUT。

Q: 为什么会出现 placeholder 记录？
A: 当 LLM 抽取与回退均无结果且 INSERT_PLACEHOLDER_ON_EMPTY=true，为保持数据完整性写入占位；升级 EXTRACTOR_VER 后统一重新抽取覆盖。

Q: 如何新增新的漏洞源？
A: 新增表 + parser + ingest_xxx.py；更新 ensure_schema & merged_vulnerabilities_view；ES 读取视图即可。

更多细节参见 PROJECT_MANUAL.md（已更新为统一遍历模式）。
