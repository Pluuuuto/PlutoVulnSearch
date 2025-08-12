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
每日自动：爬取 (CVE / CNVD / CNNVD) 最新数据 → 写入 PostgreSQL → 调用 LLM 抽取受影响产品版本范围 → 同步至 Elasticsearch 供搜索。仅新增，不做更新/删除。

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
| pipeline_daily.py | 一键每日全流程：爬取→入库→LLM→ES 同步 |
| search_db.py / search_es.py | 关键字 / 产品+版本 搜索 |
| PROJECT_MANUAL.md | 更完整的设计/维护手册 |

## 数据库与索引
表：cve / cnvd / cnnvd (结构相似) + vuln_version_range
视图：merged_vulnerabilities_view 聚合三源并 LEFT JOIN 对应版本范围。
ES 索引：vulnerabilities (嵌套字段 version_ranges)。

## 运行方式
### 1. 安装依赖
```powershell
pip install -r requirements.txt
```

### 2. 准备 PostgreSQL / Elasticsearch
- Postgres 建库并提供连接 (PG_DSN)
（pipeline_daily 会自动检测并创建 Elasticsearch 索引，无需手动脚本）

### 3. 首次初始化 & 全量导入
```powershell
python pipeline_daily.py
```
(包含 schema 检查 / 爬取 / LLM / ES)

### 4. 启动 API 服务
```powershell
uvicorn main:app --reload --port 8000
```

## 环境变量
| 名称 | 默认 | 说明 |
|------|------|------|
| PG_DSN | host=localhost port=5432 dbname=vul user=test password=test | PostgreSQL 连接串（或使用 db_config.ini） |
| ES_URL / ES_HOST | http://localhost:9200 | Elasticsearch 地址 |
| ES_INDEX | vulnerabilities | 索引名 |
| QWEN_COMPLETION_URL | (需配置) | LLM 接口地址 |
| QWEN_MODEL | Qwen | 模型名 |
| BATCH | 1000 | LLM 抽取批次查询 size |
| MAX_WORKERS | 8 | LLM 线程池大小 |
| LLM_CONCURRENCY | 4 | 并发调用上限 (Semaphore) |
| REQUEST_TIMEOUT | 60 | LLM 请求超时秒 |
| TEST_MODE | false | true 时限量数据 TEST_LIMIT |
| TEST_LIMIT | 20 | TEST_MODE 下处理上限 |
| LLM_THREADS | 4 | pipeline 中控制 run_batch 线程数（兼容） |
| LOCK_TIMEOUT | 10 | pipeline 文件锁等待秒 |

## 每日自动流程 pipeline_daily
1. 文件锁防并发
2. ensure_schema 创建表/视图
3. 调用各 ingest_xxx 脚本（内部解析 XML → insert）
4. run_batch 调 LLM 抽取版本范围（仅对缺失记录）
5. 查询 merged_vulnerabilities_view 组装文档
6. 确保 ES 索引存在（mapping）
7. bulk upsert (按 source+source_id 生成 _id)
8. 写入运行日志 JSON

失败重试：LLM 层单条失败记录 error_message，整体不中断；ES 批量失败单条记录 error。

## LLM 版本范围抽取
- 依据 vuln_version_range 缺失记录进行增量
- 哈希 prompt+产品 做幂等去重
- 解析模型 JSON / 回退正则
- 版本区间归一化为 [a,b] 文本（支持 open/closed）

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
  search_db.py
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
A: 降低 LLM_CONCURRENCY 或提高 REQUEST_TIMEOUT，加入重试策略（待扩展）。

Q: 如何新增新的漏洞源？
A: 仿照现有目录结构：parser → ingest_xxx.py 调 insert_vulnerabilities；表结构加入 ensure_schema；视图扩展 UNION；ES 文档生成逻辑合并 source。

更多细节参见 PROJECT_MANUAL.md。
