# llm_version_ranges_mt.py
# 多线程版本：读取待处理列表 → 并发调用 Qwen → 写入 vuln_version_range
import os, json, hashlib, logging, traceback, time
import psycopg2
import psycopg2.extras as pg_extras
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
PG_DSN = os.getenv("PG_DSN", "host=localhost port=5432 dbname=vul user=test password=test")
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

# 模式
TEST_MODE = os.getenv("TEST_MODE", "false").lower() in ("1","true","yes","y")
TEST_LIMIT = int(os.getenv("TEST_LIMIT", "20"))

# ====================== 版本解析与区间处理 ======================
def parse_semver(s: str) -> Tuple[int,int,int,int]:
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
    return a*1_000_000_000 + b*1_000_000 + c*1_000 + d

def code_from_str(v: str) -> int:
    return code(*parse_semver(v))

def wildcard_range(vx: str) -> Tuple[int,int]:
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
    s = (s or "").strip()
    i, j = s.find("{"), s.rfind("}")
    if i != -1 and j != -1 and j > i:
        return s[i:j+1]
    return s

session = requests.Session()
llm_sem = BoundedSemaphore(LLM_CONCURRENCY)

def call_llm(text: str) -> Dict[str, Any]:
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

# ====================== 数据库工具 ======================
def md5(s: str) -> str:
    return hashlib.md5((s or "").encode("utf-8")).hexdigest()

def upsert_ranges(conn, es_id: str, src_text: str, products: List[Dict[str,Any]]):
    raw_hash = md5(src_text)
    with conn.cursor() as cur:
        # 如无 DELETE 权限可去掉本句，但可能导致旧区间残留
        cur.execute("DELETE FROM vuln_version_range WHERE es_id=%s", (es_id,))
        for p in products or []:
            pid = (p.get("product_id") or "unknown").strip().lower()
            ivs = items_to_intervals(p.get("items") or [])
            if not ivs:
                continue
            conf = float(p.get("confidence") or 0.0)
            for lo, hi, as_, bs_, incl_a, incl_b in ivs:
                vtext = interval_to_text([(lo, hi, as_, bs_, incl_a, incl_b)])
                cur.execute("""
                  INSERT INTO vuln_version_range
                  (es_id, product_id, min_code, max_code, confidence, version_text, source_text, raw_hash, extractor_ver)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                  ON CONFLICT (es_id, product_id, min_code, max_code)
                  DO UPDATE SET confidence=EXCLUDED.confidence,
                                version_text=EXCLUDED.version_text,
                                source_text=EXCLUDED.source_text,
                                raw_hash=EXCLUDED.raw_hash,
                                extractor_ver=EXCLUDED.extractor_ver,
                                updated_at=now()
                """, (es_id, pid, lo, hi, conf, vtext, src_text, raw_hash, EXTRACTOR_VER))

# ====================== 工作线程 ======================
def worker(task: Dict[str, str], pool: pg_pool.SimpleConnectionPool) -> Dict[str, Any]:
    """处理单条：去重检查 → 调 LLM → 写库。返回结果字典用于统计。"""
    es_id = task["es_id"]; text = task["affected_products"] or ""
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

        # 调 LLM
        result = call_llm(text)
        products = result.get("products") or []

        # 写库
        if products:
            upsert_ranges(conn, es_id, text, products)
            conn.commit()
            return {"es_id": es_id, "inserted": True, "count": len(products)}
        else:
            # 无抽取也记个空结果的 info（不写库）
            return {"es_id": es_id, "empty": True}
    except Exception as e:
        if conn:
            try: conn.rollback()
            except: pass
        logger.error(f"处理失败 es_id={es_id} - {e}")
        logger.debug(traceback.format_exc())
        return {"es_id": es_id, "error": str(e)}
    finally:
        if conn:
            pool.putconn(conn)

# ====================== 主流程 ======================
def main():
    # 连接池（读写一个池即可；每线程取独立连接）
    minc = max(2, min(4, MAX_WORKERS//2))
    maxc = max(MAX_WORKERS*2, 8)
    pool = psycopg2.pool.SimpleConnectionPool(minc, maxc, PG_DSN)

    # 预取待处理列表（避免服务端游标被并发写操作干掉）
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=pg_extras.RealDictCursor) as cur:
            if TEST_MODE:
                cur.execute(f"""
                    SELECT es_id, affected_products
                    FROM merged_vulnerabilities_view
                    ORDER BY random()
                    LIMIT {TEST_LIMIT}
                """)
            else:
                # 全量：优先只取“未处理”的，减少无用调用
                cur.execute("""
                    SELECT mv.es_id, mv.affected_products
                    FROM merged_vulnerabilities_view mv
                    LEFT JOIN (
                        SELECT DISTINCT es_id FROM vuln_version_range WHERE extractor_ver >= %s
                    ) v ON mv.es_id = v.es_id
                    WHERE v.es_id IS NULL
                    LIMIT %s
                """, (EXTRACTOR_VER, BATCH))
            tasks = cur.fetchall()
    finally:
        pool.putconn(conn)

    if not tasks:
        logger.info("没有需要处理的数据。")
        return

    logger.info(f"本批待处理: {len(tasks)} 条，线程: {MAX_WORKERS}，LLM并发: {LLM_CONCURRENCY}")

    ok, skip, empty, err = 0, 0, 0, 0
    started = time.time()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        future_map = {ex.submit(worker, t, pool): t for t in tasks}
        for fut in as_completed(future_map):
            res = fut.result()
            es_id = res.get("es_id")
            if res.get("inserted"):
                ok += 1
                logger.info(f"✅ 写入完成 {es_id}（products={res.get('count')})")
            elif res.get("skipped"):
                skip += 1
                logger.debug(f"跳过已处理 {es_id}")
            elif res.get("empty"):
                empty += 1
                logger.info(f"⚠️ 无抽取结果 {es_id}")
            else:
                err += 1
                logger.error(f"❌ 失败 {es_id}: {res.get('error')}")

    elapsed = time.time() - started
    logger.info(f"批次完成: 写入 {ok} 条, 跳过 {skip} 条, 无结果 {empty} 条, 失败 {err} 条，用时 {elapsed:.1f}s")

    # 连接池关闭
    try:
        pool.closeall()
    except Exception:
        pass

if __name__ == "__main__":
    main()
