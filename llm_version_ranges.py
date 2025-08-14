"""LLM 版本区间抽取模块（统一遍历模式）

仅保留一个入口：run_all_exhaustive(..., only_es_ids=None)
    - 全量：only_es_ids=None → 逐批拉取所有尚未抽取 (extractor_ver 覆盖) 的漏洞直到耗尽。
    - 增量：only_es_ids=[...] → 仅在给定集合内遍历，直到这些 es_id 全部写入/跳过。

不再保留 run_batch / fill_missing_placeholders：占位仍由 worker 内置 INSERT_PLACEHOLDER_ON_EMPTY 控制。
"""
# 多线程版本：读取待处理列表 → 并发调用 Qwen → 写入 vuln_version_range
import os, json, hashlib, logging, traceback, time
import psycopg2
import psycopg2.extras as pg_extras
from psycopg2.extras import execute_values
import psycopg2.pool as pg_pool
import requests
from datetime import datetime
from typing import List, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import BoundedSemaphore

# ====================== 日志配置 ======================
LOG_FILE = f"log/llm_version_ranges_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
console_handler.setFormatter(console_formatter)

file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
file_handler.setFormatter(file_formatter)

logging.basicConfig(level=logging.DEBUG, handlers=[console_handler, file_handler])
logger = logging.getLogger(__name__)

# ====================== 基础配置 ======================
PG_DSN = os.getenv("PG_DSN")  # 若为空则回退读取 db_config.ini
BATCH = int(os.getenv("BATCH", "1000"))  # 全量时每次抓取多少候选
EXTRACTOR_VER = int(os.getenv("EXTRACTOR_VER", "1"))

# 私有 Qwen 接口
COMPLETION_URL = os.getenv("QWEN_COMPLETION_URL",
                           "http://192.168.85.121:30402/service/c0ae9380ad9609aef1dc678142b38258")
QWEN_MODEL = os.getenv("QWEN_MODEL", "Qwen")

# 多线程
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "8"))             # 线程数
LLM_CONCURRENCY = int(os.getenv("LLM_CONCURRENCY", "4"))     # 同时进行的 LLM 调用数上限（可小于 MAX_WORKERS）
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "60"))  # 单次 LLM 请求超时秒
ENABLE_FALLBACK = os.getenv("ENABLE_FALLBACK", "true").lower() in ("1","true","yes","y")  # LLM 失败/空结果时启用简易回退提取
LLM_RETRIES = int(os.getenv("LLM_RETRIES", "2"))             # LLM 失败或空结果时额外重试次数（不含首次）
LLM_RETRY_BACKOFF_BASE = float(os.getenv("LLM_RETRY_BACKOFF_BASE", "1.5"))  # 重试指数退避基数
INSERT_PLACEHOLDER_ON_EMPTY = os.getenv("INSERT_PLACEHOLDER_ON_EMPTY", "true").lower() in ("1","true","yes","y")
INTRA_BATCH_LOG_EVERY = int(os.getenv("INTRA_BATCH_LOG_EVERY", "100"))  # 单批多少条输出一次进度

#（已移除 TEST_MODE/TEST_LIMIT：采用直接遍历或 only_es_ids）

# ====================== 版本解析与区间处理 ======================
def parse_semver(s: str) -> Tuple[int,int,int,int]:
    """解析语义版本/特殊格式(u 构造) 返回四元组 (major, minor, patch, build)。"""
    if not s:
        return (0,0,0,0)
    s = s.strip().lower()
    if s.startswith("v"):
        s = s[1:]
    if "u" in s and "." not in s:
        parts = s.split("u")
        try:
            major = int(parts[0].strip())
            build = int(parts[1].strip())
            return major, 0, 0, build
        except:
            return (0,0,0,0)
    parts = [p.strip() for p in s.split(".") if p.strip()!=""]
    nums = []
    for p in parts:
        nums.append(int(p) if p.isdigit() else 0)
    while len(nums) < 4:
        nums.append(0)
    if len(nums) > 4:
        nums = nums[:4]
    return tuple(nums)

def code(a:int,b:int,c:int,d:int) -> int:
    """四段版本编码成统一整数，便于区间比较/索引。"""
    return a*1_000_000_000 + b*1_000_000 + c*1_000 + d

def code_from_str(v: str) -> int:
    """字符串版本直接转整数编码。"""
    return code(*parse_semver(v))

def wildcard_range(vx: str) -> Tuple[int,int]:
    """处理 '8.x' / '1.18.x' 通配符，返回编码范围。"""
    vx = (vx or "").strip().lower()
    if not vx:
        return (0,0)
    if vx.endswith(".x"):
        core = vx[:-2].strip()
        if "." in core:
            parts = core.split(".")
            return code(int(parts[0]), int(parts[1]), 0, 0), code(int(parts[0]), int(parts[1]), 999, 0)
        return code(int(core), 0, 0, 0), code(int(core), 999, 999, 0)
    if vx.endswith("x"):
        return code(int(vx[:-1]),0,0,0), code(int(vx[:-1]),999,999,0)
    return (0,0)

def items_to_intervals(items: List[Dict[str, Any]]) -> List[Tuple[int,int,str,str,bool,bool]]:
    """将 LLM 输出的 items 数组归并为离散区间列表。

    返回: [(min_code, max_code, min_str, max_str, left_incl, right_incl)]"""
    INF_MIN, INF_MAX = -2**31, 2**31 - 1
    res = []
    lower_bound = upper_bound = None
    lower_str = upper_str = None
    lower_inclusive = upper_inclusive = None

    for it in items or []:
        typ = (it.get("type") or "").lower().strip()
        vs = it.get("versions") or []
        if not vs:
            continue
        base_code = code_from_str(vs[0])
        if typ == "eq":
            res.append((base_code, base_code, vs[0], vs[0], True, True))
        elif typ == "lt":
            res.append((INF_MIN, base_code, "-∞", vs[0], False, False))
        elif typ == "lte":
            if lower_bound is not None:
                res.append((lower_bound, base_code, lower_str, vs[0], lower_inclusive, True))
                lower_bound = None
            else:
                upper_bound, upper_str, upper_inclusive = base_code, vs[0], True
        elif typ == "gt":
            res.append((base_code, INF_MAX, vs[0], "+∞", False, False))
        elif typ == "gte":
            if upper_bound is not None:
                res.append((base_code, upper_bound, vs[0], upper_str, True, upper_inclusive))
                upper_bound = None
            else:
                lower_bound, lower_str, lower_inclusive = base_code, vs[0], True
        elif typ == "range" and len(vs) >= 2:
            start = code_from_str(vs[0]); end = code_from_str(vs[1])
            if start > end:
                start, end = end, start
                vs[0], vs[1] = vs[1], vs[0]
            res.append((start, end, vs[0], vs[1], True, True))
        elif typ == "wildcard":
            lo, hi = wildcard_range(vs[0])
            res.append((lo, hi, vs[0], vs[0], True, True))
        elif typ == "list":
            for v in vs:
                c = code_from_str(v)
                res.append((c, c, v, v, True, True))

    if upper_bound is not None:
        res.append((INF_MIN, upper_bound, "-∞", upper_str, False, upper_inclusive))
    if lower_bound is not None:
        res.append((lower_bound, INF_MAX, lower_str, "+∞", lower_inclusive, False))
    return res

def interval_to_text(iv: List[Tuple[int,int,str,str,bool,bool]]) -> str:
    """把区间元组列表格式化为可读字符串表达。"""
    parts = []
    for a, b, as_, bs_, incl_a, incl_b in iv:
        if as_ == "-∞":
            parts.append(f"<={bs_}" if incl_b else f"<{bs_}")
        elif bs_ == "+∞":
            parts.append(f">={as_}" if incl_a else f">{as_}")
        elif as_ == bs_:
            parts.append(as_)
        elif incl_a and incl_b:
            parts.append(f"{as_}-{bs_}")
        else:
            left = f">={as_}" if incl_a else f">{as_}"
            right = f"<={bs_}" if incl_b else f"<{bs_}"
            parts.append(f"{left} & {right}")
    return "; ".join(parts)

# ====================== LLM 调用（私有 Qwen） ======================
LLM_SYSTEM = """你是“产品版本条件抽取器”。只输出 JSON，不要任何解释。
输出格式（严格遵守，字段名固定）：
{
  "products": [
    {
      "product_id": "规范化产品名(小写)",
      "items": [
        {"type":"lt|lte|gt|gte|eq|range|wildcard|list", "versions": ["..."] }
      ],
      "confidence": 0.0
    }
  ]
}
约定：
- 统一将版本写成 "major[.minor[.patch]]"；'8u121' 规范成 '8.0.121'。
- wildcard 仅用 '8.x' 或 '1.18.x'。
- range 为闭区间；prior to/before => lt；through/up to and including/包含至 => lte；since/自…之后 => gte。
- 文中可能包含多个产品，请分多项返回；无法判断时 items 为空并降低 confidence。
- 保持原文的版本粒度，例如：
    原文 1.20.1 → 输出 1.20.1
    原文 1.20 → 输出 1.20
    原文 1.20.x → 输出 1.20.x
"""

def _extract_json_str(s: str) -> str:
    """从可能包裹额外内容的响应中裁剪最外层 JSON。"""
    s = (s or "").strip()
    i, j = s.find("{"), s.rfind("}")
    if i != -1 and j != -1 and j > i:
        return s[i:j+1]
    return s

session = requests.Session()
llm_sem = BoundedSemaphore(LLM_CONCURRENCY)

def call_llm(text: str) -> Dict[str, Any]:
    """调用 Qwen 模型，返回解析后的 dict。

    异常：HTTP / JSON 结构不符合预期时抛出。"""
    payload = {
        "model": QWEN_MODEL,
        "messages": [
            {"role": "system", "content": LLM_SYSTEM},
            {"role": "user", "content": text}
        ],
        "temperature": 0.1
    }
    with llm_sem:
        resp = session.post(COMPLETION_URL, json=payload, timeout=REQUEST_TIMEOUT)
    if resp.status_code != 200:
        raise RuntimeError(f"Qwen API error: {resp.status_code} - {resp.text}")

    try:
        data = resp.json()
    except Exception as e:
        raise RuntimeError(f"Qwen API 返回不是 JSON: {e} - {resp.text}")

    # 兼容常见两种结构
    if isinstance(data, dict) and "choices" in data and data["choices"]:
        content = data["choices"][0]["message"]["content"]
    elif isinstance(data, dict) and "output" in data and isinstance(data["output"], dict) and "text" in data["output"]:
        content = data["output"]["text"]
    else:
        raise RuntimeError(f"Qwen API 返回格式不符合预期: {data}")

    jtxt = _extract_json_str(content)
    return json.loads(jtxt)

# ====================== 回退启发式（可选） ======================
def fallback_extract(text: str) -> List[Dict[str, Any]]:
    """当 LLM 不可用或返回空时的简易启发式：
    - 基于分隔符 '||' / ';' / 换行拆分产品片段
    - 用正则找出版本样式 (含数字与点，最多 4 段)
    - 每个产品片段生成一个 product_id（前 3 个单词小写拼接）
    - 版本生成 eq 列表 items
    置信度固定很低 (0.05)。"""
    import re
    pieces = []
    for sep in ['||', '\n', ';']:
        if sep in text:
            pieces = [p.strip() for p in re.split(re.escape(sep), text) if p.strip()]
            break
    if not pieces:
        pieces = [text] if text.strip() else []
    products = []
    ver_pattern = re.compile(r"\b\d+(?:\.\d+){0,3}\b")
    for seg in pieces[:20]:  # 避免太多
        vers = list({m.group(0) for m in ver_pattern.finditer(seg)})[:10]
        base_tokens = [t for t in re.split(r"\s+", seg) if t][:3]
        if not base_tokens:
            continue
        pid = "_".join([t.lower() for t in base_tokens])[:40]
        items = [{"type": "eq", "versions": [v]} for v in vers] if vers else []
        products.append({
            "product_id": pid,
            "items": items,
            "confidence": 0.05
        })
    return products

# ====================== 数据库工具 ======================
def _load_dsn_from_config() -> str:
    """当环境变量未提供 PG_DSN 时，从 db_config.ini 读取配置并构造 DSN 字符串。

    期望文件结构:
    [postgresql]
    host=...
    port=5432
    dbname=...
    user=...
    password=...
    """
    import configparser
    cfg = configparser.ConfigParser()
    if not cfg.read('db_config.ini', encoding='utf-8'):
        raise RuntimeError("未找到 db_config.ini 且 PG_DSN 未设置")
    if 'postgresql' not in cfg:
        raise RuntimeError("db_config.ini 缺少 [postgresql] 段")
    section = cfg['postgresql']
    parts = []
    for k in ['host','port','dbname','user','password']:
        if k in section and section[k]:
            parts.append(f"{k}={section[k]}")
    return " ".join(parts)

def _effective_dsn() -> str:
    return PG_DSN if PG_DSN else _load_dsn_from_config()
def md5(s: str) -> str:
    """生成字符串 MD5（空串安全）。"""
    return hashlib.md5((s or "").encode("utf-8")).hexdigest()

def upsert_ranges(conn, es_id: str, src_text: str, products: List[Dict[str,Any]]) -> int:
    """按产品列表写入区间：
    - 先删除旧 es_id（保持最新抽取）
    - 对每个区间 UPSERT（幂等 + 更新 meta 字段）
    返回：写入/更新的区间行数（不区分 insert/update）。"""
    raw_hash = md5(src_text)
    row_count = 0
    with conn.cursor() as cur:
        cur.execute("DELETE FROM vuln_version_range WHERE es_id=%s", (es_id,))
        for p in products or []:
            pid = (p.get("product_id") or "unknown").strip().lower()
            ivs = items_to_intervals(p.get("items") or [])
            if not ivs:
                continue
            conf = float(p.get("confidence") or 0.0)
            for lo, hi, as_, bs_, incl_a, incl_b in ivs:
                vtext = interval_to_text([(lo, hi, as_, bs_, incl_a, incl_b)])
                cur.execute(
                    """
                    INSERT INTO vuln_version_range
                    (es_id, product_id, min_code, max_code, confidence, version_text, source_text, raw_hash, extractor_ver)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (es_id, product_id, min_code, max_code)
                    DO UPDATE SET confidence=EXCLUDED.confidence,
                                  version_text=EXCLUDED.version_text,
                                  source_text=EXCLUDED.source_text,
                                  raw_hash=EXCLUDED.raw_hash,
                                  extractor_ver=EXCLUDED.extractor_ver
                    """,
                    (es_id, pid, lo, hi, conf, vtext, src_text, raw_hash, EXTRACTOR_VER)
                )
                row_count += 1
    return row_count

# ====================== 工作线程 ======================
def worker(task: Dict[str, str], pool: pg_pool.SimpleConnectionPool) -> Dict[str, Any]:
        """处理单条：去重检查 → LLM 多次尝试 → 回退 → （可选占位写入） → 写库。

        返回字段：
            es_id, inserted, count, skipped, empty, error, fallback(bool), placeholder(bool), retries(int)
        """
        es_id = task["es_id"]
        text = task["affected_products"] or ""
        conn = None
        try:
            conn = pool.getconn()
            # 去重（断点续跑）
            with conn.cursor() as c2:
                c2.execute("""
                  SELECT 1 FROM vuln_version_range
                   WHERE es_id=%s AND extractor_ver >= %s
                   LIMIT 1
                """, (es_id, EXTRACTOR_VER))
                if c2.fetchone():
                    return {"es_id": es_id, "skipped": True}

            products: List[Dict[str, Any]] = []
            llm_error: str | None = None
            attempts = 0
            max_attempts = 1 + max(0, LLM_RETRIES)
            while attempts < max_attempts:
                attempts += 1
                try:
                    result = call_llm(text)
                    products = result.get("products") or []
                    if products:
                        break
                    llm_error = "empty_products"
                    logger.debug(f"LLM 空结果 es_id={es_id} attempt={attempts}/{max_attempts}")
                except Exception as le:
                    llm_error = str(le)
                    logger.warning(f"LLM 调用失败 es_id={es_id} attempt={attempts}/{max_attempts}: {llm_error}")
                if attempts < max_attempts:
                    backoff = round(LLM_RETRY_BACKOFF_BASE ** (attempts-1), 2)
                    time.sleep(min(backoff, 10))

            used_fallback = False
            used_placeholder = False
            if ENABLE_FALLBACK and (llm_error or not products):
                fb = fallback_extract(text)
                if fb:
                    logger.info(f"启用回退抽取 es_id={es_id} products={len(fb)} (llm_error={bool(llm_error)})")
                    products = fb
                    used_fallback = True

            if not products and INSERT_PLACEHOLDER_ON_EMPTY:
                products = [{
                    "product_id": "placeholder",
                    "items": [{"type": "eq", "versions": ["0.0.0"]}],
                    "confidence": 0.0
                }]
                used_placeholder = True
                logger.info(f"占位写入 es_id={es_id} (placeholder) 以保证落库")

            if products:
                try:
                    rows_written = upsert_ranges(conn, es_id, text, products)
                    conn.commit()
                    return {
                        "es_id": es_id,
                        "inserted": True,
                        "count": len(products),
                        "interval_rows": rows_written,
                        "fallback": used_fallback,
                        "placeholder": used_placeholder,
                        "retries": attempts-1
                    }
                except Exception as we:
                    if conn:
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                    logger.error(f"写入失败 es_id={es_id}: {we}")
                    return {"es_id": es_id, "error": str(we), "retries": attempts-1}
            return {"es_id": es_id, "empty": True, "retries": attempts-1}
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            logger.error(f"处理失败 es_id={es_id} - {e}")
            logger.debug(traceback.format_exc())
            return {"es_id": es_id, "error": str(e)}
        finally:
            if conn:
                pool.putconn(conn)

def run_all_exhaustive(batch: int | None = None, progress_every: int = 1000, only_es_ids: list[str] | None = None) -> dict:
    """一次性遍历模式：不停拉取未处理任务直到耗尽（忽略 VR_MAX_LOOPS / TEST_MODE）。

    适用：一次性全量跑完；可随时 Ctrl+C 终止，已写入的不会重复（依赖 extractor_ver 去重）。

    参数：
    batch            每次数据库 LIMIT（默认取环境 BATCH）
    progress_every   每处理多少条打印一次进度累计。
    only_es_ids      若提供，仅在该集合中遍历（适用于增量）。

    返回：聚合统计，与 run_batch 类似但覆盖整个运行：
      {
        total_tasks, processed, skipped, empty, failed,
        inserted_products, inserted_rows, fallback_used, placeholders,
        retry_total, elapsed_sec, batches
      }
    """
    bt = BATCH if batch is None else batch
    dsn = _effective_dsn()
    minc = max(2, min(4, MAX_WORKERS//2))
    maxc = max(MAX_WORKERS*2, 8)
    pool = psycopg2.pool.SimpleConnectionPool(minc, maxc, dsn)
    total_tasks = processed = skipped = empty = failed = 0
    inserted_products = inserted_rows = fallback_used = placeholders = retry_total = 0
    batches = 0
    start = time.time()
    try:
        while True:
            # 拉一批未覆盖 extractor_ver 的
            conn = pool.getconn()
            try:
                with conn.cursor(cursor_factory=pg_extras.RealDictCursor) as cur:
                    sql = """
                        SELECT mv.es_id, mv.affected_products
                        FROM merged_vulnerabilities_view mv
                        LEFT JOIN (
                            SELECT DISTINCT es_id FROM vuln_version_range WHERE extractor_ver >= %s
                        ) v ON mv.es_id = v.es_id
                        WHERE v.es_id IS NULL
                        {only_filter}
                        LIMIT %s
                    """.format(only_filter="AND mv.es_id = ANY(%s)" if only_es_ids else "")
                    if only_es_ids:
                        cur.execute(sql, (EXTRACTOR_VER, only_es_ids, bt))
                    else:
                        cur.execute(sql, (EXTRACTOR_VER, bt))
                    tasks = cur.fetchall()
            finally:
                pool.putconn(conn)
            if not tasks:
                logger.info("[TRAVERSE] 没有更多未处理任务，结束。")
                break
            batches += 1
            total_tasks += len(tasks)
            scope = f"only_ids={len(only_es_ids)}" if only_es_ids else "ALL"
            logger.info(f"[TRAVERSE] 批次 {batches} 获取 {len(tasks)} 条 (batch={bt}, scope={scope})")
            # 并发处理本批
            processed_before = processed
            skipped_before = skipped
            empty_before = empty
            failed_before = failed
            placeholders_before = placeholders
            fallback_before = fallback_used
            rows_before = inserted_rows
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
                done_in_batch = 0
                heartbeat_sec = int(os.getenv('HEARTBEAT_SEC', '30'))
                last_heartbeat = time.time()
                futures_map = {ex.submit(worker, t, pool): t for t in tasks}
                for fut in as_completed(futures_map):
                    res = fut.result()
                    if res.get('inserted'):
                        processed += 1
                        inserted_products += int(res.get('count') or 0)
                        inserted_rows += int(res.get('interval_rows') or 0)
                        retry_total += int(res.get('retries') or 0)
                        if res.get('fallback'): fallback_used += 1
                        if res.get('placeholder'): placeholders += 1
                    elif res.get('skipped'):
                        skipped += 1
                    elif res.get('empty'):
                        empty += 1
                    else:
                        failed += 1
                    done_in_batch += 1
                    if done_in_batch % max(1, INTRA_BATCH_LOG_EVERY) == 0:
                        logger.info(
                            f"[TRAVERSE][BATCH {batches}] 进度 {done_in_batch}/{len(tasks)} processed={processed-processed_before} "
                            f"empty={empty-empty_before} skipped={skipped-skipped_before} failed={failed-failed_before} rows+={inserted_rows-rows_before}"
                        )
                    now = time.time()
                    if (now - last_heartbeat) >= heartbeat_sec:
                        logger.info(
                            f"[TRAVERSE][BATCH {batches}] 心跳 {done_in_batch}/{len(tasks)} processed={processed-processed_before} "
                            f"empty={empty-empty_before} skipped={skipped-skipped_before} failed={failed-failed_before} rows+={inserted_rows-rows_before} (threads={MAX_WORKERS})"
                        )
                        last_heartbeat = now
            # 本批增量统计
            batch_processed = processed - processed_before
            batch_failed = failed - failed_before
            batch_empty = empty - empty_before
            batch_skipped = skipped - skipped_before
            batch_placeholders = placeholders - placeholders_before
            batch_fallback = fallback_used - fallback_before
            batch_rows = inserted_rows - rows_before
            logger.info(
                f"[TRAVERSE] 批次 {batches} 完成: 本批 processed={batch_processed} failed={batch_failed} empty={batch_empty} "
                f"skipped={batch_skipped} placeholders={batch_placeholders} fallback={batch_fallback} rows={batch_rows}; "
                f"累计 processed={processed} failed={failed} placeholders={placeholders} rows={inserted_rows}"
            )
            if processed and processed % progress_every == 0:
                logger.info(f"[TRAVERSE] 累计 processed={processed} inserted_rows={inserted_rows} failed={failed} placeholders={placeholders}")
        elapsed = time.time() - start
        stats = {
            'mode': 'traverse_all',
            'total_tasks': total_tasks,
            'processed': processed,
            'skipped': skipped,
            'empty': empty,
            'failed': failed,
            'inserted_products': inserted_products,
            'inserted_rows': inserted_rows,
            'fallback_used': fallback_used,
            'placeholders': placeholders,
            'retry_total': retry_total,
            'batches': batches,
            'elapsed_sec': round(elapsed, 3)
        }
        logger.info(f"[TRAVERSE] 完成 {stats}")
        return stats
    finally:
        try: pool.closeall()
        except Exception: pass


def main():  # 直接全量遍历
    run_all_exhaustive()


if __name__ == "__main__":
    main()
