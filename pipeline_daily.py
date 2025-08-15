"""每日漏洞数据流水线（统一遍历模式）。

流程：
    1. ensure_schema 创建/确认表与视图。
    2. 三源 ingest 幂等追加写入 (CVE / CNVD / CNNVD)。
    3. 单次遍历 LLM 版本区间抽取 (run_all_exhaustive) 直到所有未达当前 EXTRACTOR_VER 的 es_id 处理完。
    4. 聚合视图+版本区间，批量 upsert 到 Elasticsearch。
    5. 输出汇总 JSON（含遍历统计 + 覆盖率 + ES 成功/失败）。

核心环境变量（精简后）：
    PG_DSN                 PostgreSQL 连接（或使用 db_config.ini）
    ES_URL / ES_INDEX      Elasticsearch 目标
    BATCH                  每次抓取任务批大小
    MAX_WORKERS            worker 线程数
    LLM_CONCURRENCY        实际 LLM 并发（信号量）
    LLM_RETRIES / LLM_RETRY_BACKOFF_BASE 重试与退避
    ENABLE_FALLBACK        失败/空结果启用启发式回退
    INSERT_PLACEHOLDER_ON_EMPTY 仍无结果时写占位
    EXTRACTOR_VER          抽取器版本（升级触发重跑）
    INTRA_BATCH_LOG_EVERY  批内进度日志频率
    HEARTBEAT_SEC          批内心跳日志间隔
    ES_SKIP_IF_EMPTY       无文档时跳过 ES 同步

幂等性：
    - ingest 追加：ON CONFLICT DO NOTHING。
    - LLM：同一 es_id + extractor_ver 仅处理一次；提升 EXTRACTOR_VER 触发重跑覆盖旧行。
    - ES：bulk index 以 _id 覆盖。

退出码：
    0 success
    1 partial（某些步骤非致命失败）
    2 fatal（未捕获异常）
"""
from __future__ import annotations

import os
import sys
import time
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

import psycopg2
import psycopg2.extras
import requests

from db import ensure_schema, get_conn
from llm_version_ranges import run_all_exhaustive

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
LLM_THREADS = int(os.getenv('LLM_THREADS', '4'))  # placeholder (actual concurrency inside module)
# === 模式切换：改为一次性遍历抽取（不再使用多轮控制） ===
ES_SKIP_IF_EMPTY = os.getenv('ES_SKIP_IF_EMPTY', 'true').lower() in ('1','true','yes','y')
TRAVERSE_BATCH = int(os.getenv('TRAVERSE_BATCH', os.getenv('BATCH', '1000')))  # 默认复用 LLM 脚本 BATCH
TRAVERSE_PROGRESS_EVERY = int(os.getenv('TRAVERSE_PROGRESS_EVERY', '2000'))
FORCE_REEXTRACT = os.getenv('FORCE_REEXTRACT', 'false').lower() in ('1','true','yes','y')

def compute_coverage_stats() -> dict:
    """统计版本区间覆盖率。一次性遍历后应当 uncovered=0（若启用占位策略）。"""
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM merged_vulnerabilities_view")
        total_vulns = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT es_id) FROM vuln_version_range")
        covered_vulns = cur.fetchone()[0]
        cur.execute("""
            SELECT COUNT(*) FROM (
              SELECT es_id, bool_and(product_id='placeholder') AS all_ph
              FROM vuln_version_range
              GROUP BY es_id
              HAVING bool_and(product_id='placeholder')
            ) t
        """)
        placeholder_only_vulns = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM vuln_version_range")
        total_version_rows = cur.fetchone()[0]
    real_extracted_vulns = covered_vulns - placeholder_only_vulns
    uncovered_vulns = total_vulns - covered_vulns
    def pct(n):
        return round(n / total_vulns * 100, 3) if total_vulns else 0.0
    return {
        'total_vulns': total_vulns,
        'covered_vulns': covered_vulns,
        'real_extracted_vulns': real_extracted_vulns,
        'placeholder_only_vulns': placeholder_only_vulns,
        'uncovered_vulns': uncovered_vulns,
        'total_version_rows': total_version_rows,
        'real_pct': pct(real_extracted_vulns),
        'placeholder_pct': pct(placeholder_only_vulns),
        'uncovered_pct': pct(uncovered_vulns)
    }

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
# LLM 版本区间抽取：现在统一使用一次性遍历 (run_all_exhaustive)；增量模式单批 only_es_ids。
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



def main():
    """Entry point: schema → ingest → multi-loop LLM → ES sync → summary.

    说明：已移除文件锁；假设单进程运行。如需并发保护可在调度层控制。"""
    run_start = datetime.now(timezone.utc)
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

        # 一次性遍历抽取（仅补齐缺失，已存在跳过）
        traverse_stats = run_all_exhaustive(batch=TRAVERSE_BATCH, progress_every=TRAVERSE_PROGRESS_EVERY)
        if traverse_stats.get('failed', 0) > 0:
            partial = True
        vr_stats = {'mode': 'skip_existing', 'stats': traverse_stats}

        # 遍历后直接统计覆盖（单次，无 before/after 对比）
        coverage_after = compute_coverage_stats()

        docs_iter = list(fetch_docs_for_es())
        if not docs_iter and ES_SKIP_IF_EMPTY:
            es_stats = {'es_success': 0, 'es_failed': 0, 'skipped': True}
            LOG.info("ES sync skipped (no documents) ES_SKIP_IF_EMPTY=%s", ES_SKIP_IF_EMPTY)
        else:
            ensure_index()
            es_stats = bulk_upsert_es(iter(docs_iter))
            if es_stats['es_failed'] > 0:
                partial = True

        summary = {
            'run_start': run_start.isoformat(),
            'run_end': datetime.now(timezone.utc).isoformat(),
            'ingest': ingest_stats,
            'version_ranges': vr_stats,
            'coverage': coverage_after,
            'es': es_stats,
            'status': 'partial' if partial else 'success'
        }
        LOG.info("SUMMARY %s", json.dumps(summary, ensure_ascii=False))
        Path('log').mkdir(exist_ok=True)
        with open(f"log/pipeline_summary_{run_start.strftime('%Y%m%d_%H%M%S')}.json", 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        if partial:
            sys.exit(1)
    except Exception:
        LOG.exception("Fatal pipeline error")
        sys.exit(2)

#############################################################
# 增量同步（上传触发场景）
#############################################################

def _run_llm_multi_loop() -> dict:
    """兼容调用入口：full 模式一次性遍历抽取。"""
    stats = run_all_exhaustive(batch=TRAVERSE_BATCH, progress_every=TRAVERSE_PROGRESS_EVERY)
    return {'mode': 'traverse_all', 'stats': stats}

def incremental_sync(run_llm: bool = True, es_sync: bool = True, mode: str = "incremental", es_ids: list[str] | None = None) -> dict:
    """上传文件后调用：执行 LLM 抽取与 ES 同步。

    参数:
      mode: incremental | full
        incremental: 仅对传入 es_ids 做 LLM 与 ES upsert；若 es_ids 为空则返回空。
        full:       没有过滤，保持原全量行为。
      es_ids: 新增/更新的 es_id 列表（仅 incremental 使用）。
    """
    vr_stats = {}
    target_ids = es_ids if (mode == 'incremental') else None
    if run_llm:
        if mode == 'incremental':
            if not target_ids:
                vr_stats = {'loops': 0, 'accumulated': {k:0 for k in ['total_tasks','processed','skipped','empty','failed','inserted_products','fallback_used','placeholders','retry_total']}}
            else:
                # 使用统一遍历：限定 only_es_ids
                stats = run_all_exhaustive(batch=TRAVERSE_BATCH, progress_every=TRAVERSE_PROGRESS_EVERY, only_es_ids=target_ids)
                vr_stats = {
                    'mode': 'traverse_incremental',
                    'stats': stats
                }
        else:  # full
            vr_stats = _run_llm_multi_loop()
    es_stats = {}
    if es_sync:
        if mode == 'incremental':
            if not target_ids:
                es_stats = {'es_success': 0, 'es_failed': 0, 'skipped': True}
            else:
                # 仅取得指定 es_ids 文档
                conn = get_conn()
                docs = []
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
                        WHERE mv.es_id = ANY(%s)
                        GROUP BY mv.es_id, mv.cve_id, mv.cnvd_number, mv.cnnvd_number, mv.description, mv.affected_products, mv.solution, mv.risk_display, mv.risk_level
                    """, (target_ids,))
                    rows = cur.fetchall()
                for row in rows:
                    doc = {k: row[k] for k in ["es_id", "cve_id", "cnvd_number", "cnnvd_number", "description", "affected_products", "solution", "risk_display", "risk_level"]}
                    doc["version_ranges"] = row["ranges"]
                    docs.append(doc)
                ensure_index()
                es_stats = bulk_upsert_es(docs)
        else:
            docs_iter = list(fetch_docs_for_es())
            if not docs_iter and ES_SKIP_IF_EMPTY:
                es_stats = {'es_success': 0, 'es_failed': 0, 'skipped': True}
                LOG.info("[INCREMENTAL] Skip ES (no docs)")
            else:
                ensure_index()
                es_stats = bulk_upsert_es(iter(docs_iter))
    return {
        'version_ranges': vr_stats,
        'es': es_stats
    }

if __name__ == '__main__':
    main()