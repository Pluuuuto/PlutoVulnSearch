"""Daily vulnerability data pipeline.

Steps:
  1. Acquire lock (file based) to prevent concurrent runs.
  2. Ensure DB schema.
  3. Ingest sources (CVE, CNVD, CNNVD).
  4. Extract version ranges (LLM) for new es_id without ranges.
  5. Sync (full upsert) to Elasticsearch.
  6. Output summary metrics.

Environment variables:
  PG_DSN        PostgreSQL DSN, or configured in db_config.ini if unset
  ES_URL        Elasticsearch base URL (default http://localhost:9200)
  ES_INDEX      Target index name (default vulnerabilities)
  LLM_THREADS   Thread pool size for version range extraction (default 4)
  LOCK_TIMEOUT  Seconds to wait before giving up acquiring lock (default 10)

Idempotence:
  - DB inserts use ON CONFLICT DO NOTHING (append-only).
  - Version range extraction only processes es_id not present in vuln_version_range.
  - ES sync overwrites (doc_as_upsert) so repeated runs are safe.

Exit codes:
  0 success, 1 partial (some non-critical failures), 2 fatal.
"""
from __future__ import annotations

import os
import sys
import time
import json
import logging
import hashlib
import contextlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

import psycopg2
import psycopg2.extras
import requests

from db import ensure_schema, get_conn
from llm_version_ranges import run_batch as llm_run_batch

# Configure logging early
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('log/pipeline_daily.log', encoding='utf-8')
    ]
)
LOG = logging.getLogger('pipeline')

ES_URL = os.getenv('ES_URL', 'http://localhost:9200')
ES_INDEX = os.getenv('ES_INDEX', 'test_vulnerabilities')
LLM_THREADS = int(os.getenv('LLM_THREADS', '4'))
LOCK_TIMEOUT = int(os.getenv('LOCK_TIMEOUT', '10'))
LOCK_STALE_SECONDS = int(os.getenv('LOCK_STALE_SECONDS', '3600'))  # 超过此秒认为陈旧锁可被清理
LOCK_FILE = Path('pipeline_daily.lock')

# Import ingestion routines dynamically (fallback if missing)
def run_ingest(label: str, module_path: str) -> Dict[str, int]:
    """动态导入并执行 ingestion 脚本的 run() 函数。

    参数:
        label       日志标识（CVE/CNVD/CNNVD）
        module_path 相对路径 'CVE/ingest_cve.py'
    返回:
        {inserted, skipped, failed}
    注意:
        - 失败返回 failed=-1 以便标记 partial。
        - 临时修改 sys.path 仅在该模块执行期间生效。"""
    start = time.time()
    module_dir, module_file = os.path.split(module_path)
    old_path = sys.path[:]
    mod_name = module_file[:-3]
    try:
        # 独立隔离 sys.path，防止前一个源残留目录影响下一个源的 parser 解析
        sys.path = [module_dir] + old_path
        # 确保 parser 不被前一个源缓存；多源都有 parser.py
        for name in ['parser', 'db_handler', mod_name]:
            if name in sys.modules:
                del sys.modules[name]
        mod = __import__(mod_name)
        if not hasattr(mod, 'run'):
            raise RuntimeError(f"{module_path} missing run()")
        res = mod.run()
        if not isinstance(res, dict):
            LOG.warning("%s run() did not return dict, treating as zeroes", label)
            res = {"inserted": 0, "skipped": 0, "failed": 0}
        LOG.info("%s ingest finished in %.2fs -> %s", label, time.time() - start, res)
        return {"inserted": res.get('inserted', 0), "skipped": res.get('skipped', 0), "failed": res.get('failed', 0)}
    except Exception:
        LOG.exception("%s ingest error", label)
        return {"inserted": 0, "skipped": 0, "failed": -1}
    finally:
        sys.path = old_path
        # 清理缓存的 parser 以防下一个源解析到错误文件
        for name in ['parser', 'db_handler']:
            if name in sys.modules:
                del sys.modules[name]

#############################################
# LLM 版本区间抽取：使用 llm_version_ranges.run_batch
#############################################

# Elasticsearch index helpers

def es_index_exists() -> bool:
    """检查 ES 索引是否存在（HTTP 200 即认为存在）。"""
    r = requests.get(f"{ES_URL}/{ES_INDEX}")
    return r.status_code == 200

INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "es_id": {"type": "keyword"},
            "cve_id": {"type": "keyword"},
            "cnvd_number": {"type": "keyword"},
            "cnnvd_number": {"type": "keyword"},
            "description": {"type": "text"},
            "affected_products": {"type": "text"},
            "solution": {"type": "text"},
            "risk_display": {"type": "keyword"},
            "risk_level": {"type": "integer"},
            "version_ranges": {"type": "nested", "properties": {
                "product_id": {"type": "keyword"},
                "min_code": {"type": "long"},
                "max_code": {"type": "long"},
                "confidence": {"type": "float"},
                "version_text": {"type": "text"},
                "extractor_ver": {"type": "integer"}
            }}
        }
    }
}

def ensure_index():
    """保证索引存在；不存在则创建 mapping。

    幂等：若已存在则直接返回。"""
    if es_index_exists():
        return
    r = requests.put(f"{ES_URL}/{ES_INDEX}", json=INDEX_MAPPING)
    r.raise_for_status()
    LOG.info("Created ES index %s", ES_INDEX)


def fetch_docs_for_es(batch_size: int = 1000):
    """游标读取全部融合视图 + 关联版本区间并 yield 文档。

    参数：batch_size 预留（当前一次性取出，可按需要改为游标分批）。"""
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT mv.*, COALESCE(json_agg(json_build_object(
                'product_id', r.product_id,
                'min_code', r.min_code,
                'max_code', r.max_code,
                'confidence', r.confidence,
                'version_text', r.version_text,
                'extractor_ver', r.extractor_ver
            ) ORDER BY r.product_id, r.min_code) FILTER (WHERE r.es_id IS NOT NULL), '[]') AS ranges
            FROM merged_vulnerabilities_view mv
            LEFT JOIN vuln_version_range r ON r.es_id = mv.es_id
            GROUP BY mv.es_id, mv.cve_id, mv.cnvd_number, mv.cnnvd_number, mv.description, mv.affected_products, mv.solution, mv.risk_display, mv.risk_level
        """)
        rows = cur.fetchall()
    for row in rows:
        doc = {
            k: row[k] for k in ["es_id", "cve_id", "cnvd_number", "cnnvd_number", "description", "affected_products", "solution", "risk_display", "risk_level"]
        }
        doc["version_ranges"] = row["ranges"]
        yield doc


def bulk_upsert_es(docs, chunk: int = 500) -> Dict[str, int]:
    """分块发送 bulk upsert（index 动作覆盖同 _id）。

    返回：成功/失败条数统计。"""
    success = 0
    failed = 0
    buffer = []
    for d in docs:
        buffer.append(d)
        if len(buffer) >= chunk:
            s, f = _send_bulk(buffer)
            success += s
            failed += f
            buffer.clear()
    if buffer:
        s, f = _send_bulk(buffer)
        success += s
        failed += f
    return {"es_success": success, "es_failed": failed}


def _send_bulk(batch: List[Dict[str, Any]]):
    """构造 NDJSON 并发送一次 bulk 请求，返回 (success, failed)。"""
    lines = []
    for doc in batch:
        meta = {"index": {"_index": ES_INDEX, "_id": doc['es_id']}}
        lines.append(json.dumps(meta, ensure_ascii=False))
        lines.append(json.dumps(doc, ensure_ascii=False))
    data = "\n".join(lines) + "\n"
    r = requests.post(f"{ES_URL}/_bulk", data=data.encode('utf-8'), headers={'Content-Type': 'application/x-ndjson'})
    if r.status_code >= 300:
        LOG.error("Bulk request failed status=%s body=%s", r.status_code, r.text[:500])
        return 0, len(batch)
    js = r.json()
    err = js.get('errors')
    if not err:
        return len(batch), 0
    s = 0
    f = 0
    for item in js['items']:
        if 'error' in item['index']:
            f += 1
            LOG.warning("ES index error id=%s err=%s", item['index'].get('_id'), item['index']['error'].get('type'))
        else:
            s += 1
    return s, f

# Lock handling

def acquire_lock() -> bool:
    """尝试获得文件锁，支持检测/清理由崩溃遗留的陈旧锁。

    逻辑：
      - 常规尝试创建新文件 (O_EXCL)。
      - 存在则检查修改时间；若超出 LOCK_STALE_SECONDS 视为陈旧并删除再试。
      - 在等待窗口 (LOCK_TIMEOUT) 内持续轮询。"""
    start = time.time()
    while time.time() - start < LOCK_TIMEOUT:
        try:
            fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, 'w') as f:
                f.write(str(os.getpid()))
            LOG.info("Acquired lock %s", LOCK_FILE)
            return True
        except FileExistsError:
            try:
                stat = LOCK_FILE.stat()
                age = time.time() - stat.st_mtime
                if age > LOCK_STALE_SECONDS:
                    LOG.warning("Stale lock (age %.0fs > %ss) detected, removing %s", age, LOCK_STALE_SECONDS, LOCK_FILE)
                    with contextlib.suppress(Exception):
                        LOCK_FILE.unlink()
                    continue
            except FileNotFoundError:
                continue  # race 删除后重试
            time.sleep(1)
    return False

def release_lock():
    """释放文件锁（忽略不存在的情况）。"""
    with contextlib.suppress(FileNotFoundError):
        LOCK_FILE.unlink()
        LOG.info("Released lock")


def main():
    """日常全流程入口：锁→建表→三源导入→LLM 区间→ES 同步→汇总输出。"""
    run_start = datetime.now(timezone.utc)
    if not acquire_lock():
        LOG.error("Could not acquire lock within %ss", LOCK_TIMEOUT)
        sys.exit(2)
    partial = False
    try:
        ensure_schema()

        ingest_stats = {
            'cve': run_ingest('CVE', 'CVE/ingest_cve.py'),
            'cnvd': run_ingest('CNVD', 'CNVD/ingest_cnvd.py'),
            'cnnvd': run_ingest('CNNVD', 'CNNVD/ingest_cnnvd.py')
        }
        if any(v['failed'] == -1 for v in ingest_stats.values()):
            partial = True

        vr_stats = llm_run_batch()

        ensure_index()
        es_stats = bulk_upsert_es(fetch_docs_for_es())
        if es_stats['es_failed'] > 0:
            partial = True

        summary = {
            'run_start': run_start.isoformat(),
            'run_end': datetime.now(timezone.utc).isoformat(),
            'ingest': ingest_stats,
            'version_ranges': vr_stats,
            'es': es_stats,
            'status': 'partial' if partial else 'success'
        }
        LOG.info("SUMMARY %s", json.dumps(summary, ensure_ascii=False))
        # Write JSON summary
        Path('log').mkdir(exist_ok=True)
        with open(f"log/pipeline_summary_{run_start.strftime('%Y%m%d_%H%M%S')}.json", 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        if partial:
            sys.exit(1)
    except Exception:
        LOG.exception("Fatal pipeline error")
        sys.exit(2)
    finally:
        release_lock()

if __name__ == '__main__':
    main()
