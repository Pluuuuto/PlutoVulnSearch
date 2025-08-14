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
| llm_version_ranges.py | 批量调用 LLM 提取版本区间并写入 vuln_version_range |
| pipeline_daily.py | 全量流程：爬取→入库→多轮 LLM→全量 ES 同步 |
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
（pipeline_daily 会自动检测并创建 Elasticsearch 索引，无需手动脚本）

### 3. 全量导入（首次或周期性补齐）
```powershell
python pipeline_daily.py
```
(包含 schema 检查 / 爬取 / LLM / ES)

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

### 6. 离线构建 / 无网环境部署
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
| BATCH | 1000 | 单次 LLM 抽取批次查询上限 |
| MAX_WORKERS | 8 | LLM 线程池大小 |
| LLM_CONCURRENCY | 4 | 并发调用上限 (Semaphore) |
| REQUEST_TIMEOUT | 60 | 单次 LLM 请求超时秒 |
| LLM_RETRIES | 2 | LLM 失败或空结果时额外重试次数（不含首次） |
| LLM_RETRY_BACKOFF_BASE | 1.5 | 重试指数退避基数 (sleep = base^(attempt-1) 上限10s) |
| ENABLE_FALLBACK | true | LLM 失败/空结果后启用启发式回退抽取 |
| INSERT_PLACEHOLDER_ON_EMPTY | true | 最终仍无结果时写入占位 (product_id=placeholder, 0.0.0) 保证有记录 |
| TEST_MODE | false | true 时使用随机少量样本 |
| TEST_LIMIT | 20 | TEST_MODE 下样本条数 |
| EXTRACTOR_VER | 1 | 版本抽取器版本号（用于跳过已处理数据） |
| LLM_THREADS | 4 | pipeline 兼容参数（实际并发由 MAX_WORKERS/LLM_CONCURRENCY 控制） |
| (已移除锁相关变量) |  | pipeline 已不使用文件锁 |
| VR_MAX_LOOPS | 5 | pipeline 中多轮 LLM 抽取最多循环次数 |
| VR_STOP_ON_ZERO | true | 某轮 processed=0 时提前停止 |
| ES_SKIP_IF_EMPTY | true | 当无文档需要写入时跳过 ES 同步 |

## 全量流程 (pipeline_daily) 与 增量 (/upload)
全量：
1. ensure_schema
2. ingest 三源（幂等追加）
3. 多轮 LLM（VR_MAX_LOOPS / VR_STOP_ON_ZERO）
4. 汇总视图全部文档 → ES upsert
5. 输出 summary JSON

增量：
1. 单文件解析并入库
2. mode=incremental → 针对该文件产生的 es_id 单轮 LLM + ES
3. mode=full → 触发全量多轮（耗时）
4. 返回插入与处理统计

失败与健壮性：
- LLM：重试 → 回退 → 占位。
- ES：失败计数不阻断。
- 全量 summary 标记 partial 若存在失败。

## LLM 版本范围抽取
- 只处理 merged_vulnerabilities_view 中尚未达到当前 EXTRACTOR_VER 的 es_id
- 多线程 + 并发限制 (MAX_WORKERS + LLM_CONCURRENCY)
- 失败 / 空结果：进入重试（指数退避）直到耗尽 LLM_RETRIES
- 若仍无：可启用 ENABLE_FALLBACK 的启发式回退；最终仍空且 INSERT_PLACEHOLDER_ON_EMPTY=true 则写占位
- 每条写入前删除旧同 es_id 记录，保证最新抽取（需要 DELETE 权限）
- 区间合并：输出 items 归并为离散区间转 version_text 保存
- 统计字段：processed / skipped / empty / failed / inserted_products / fallback_used / placeholders / retry_total / elapsed_sec

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
A: 当 LLM 抽取与回退均无结果且 INSERT_PLACEHOLDER_ON_EMPTY=true，为保持数据完整性写入占位，以便后续统计；可在提升模型后提高 EXTRACTOR_VER 重新跑覆盖。

Q: 如何新增新的漏洞源？
A: 新增表 + parser + ingest_xxx.py；更新 ensure_schema & merged_vulnerabilities_view；ES 读取视图即可。

更多细节参见 PROJECT_MANUAL.md。
