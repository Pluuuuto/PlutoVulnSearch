"""LLM 版本区间抽取模块

功能：
    1. 读取待处理 es_id + affected_products（按 extractor_ver 过滤）
    2. 多线程调用 Qwen 抽取产品版本条件
    3. 解析区间 → 规范化 → UPSERT 写入 vuln_version_range

直接运行：python llm_version_ranges.py  # 执行一批（受 TEST_MODE / BATCH 控制）
集成方式：from llm_version_ranges import run_batch; stats = run_batch()
返回 stats 示例：
    {
        'total_tasks': 120,
        'processed': 90,
        'skipped': 20,
        'empty': 5,
        'failed': 5,
        'inserted_products': 210,
        'elapsed_sec': 12.34
    }
"""
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

# 模式
TEST_MODE = os.getenv("TEST_MODE", "false").lower() in ("1","true","yes","y")
TEST_LIMIT = int(os.getenv("TEST_LIMIT", "20"))

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

def upsert_ranges(conn, es_id: str, src_text: str, products: List[Dict[str,Any]]):
    """按产品列表写入区间：
    - 先删除旧 es_id（保持最新抽取）
    - 对每个区间 UPSERT（幂等 + 更新 meta 字段）"""
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
                                extractor_ver=EXCLUDED.extractor_ver
                """, (es_id, pid, lo, hi, conf, vtext, src_text, raw_hash, EXTRACTOR_VER))

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
                    upsert_ranges(conn, es_id, text, products)
                    conn.commit()
                    return {
                        "es_id": es_id,
                        "inserted": True,
                        "count": len(products),
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

# ====================== 主流程 ======================
def run_batch(test_mode: bool | None = None, batch: int | None = None) -> dict:
    """执行一批抽取任务并返回统计。

    参数: test_mode 覆盖 TEST_MODE; batch 覆盖 BATCH。
    返回: 统计字典（详见模块顶部示例）。"""
    """执行一批抽取任务并返回统计。

    参数允许覆盖环境变量以便 pipeline 细粒度控制。
    """
    tm = TEST_MODE if test_mode is None else test_mode
    bt = BATCH if batch is None else batch

    minc = max(2, min(4, MAX_WORKERS//2))
    maxc = max(MAX_WORKERS*2, 8)
    dsn = _effective_dsn()
    pool = psycopg2.pool.SimpleConnectionPool(minc, maxc, dsn)

    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=pg_extras.RealDictCursor) as cur:
            if tm:
                cur.execute("""
                    SELECT es_id, affected_products
                    FROM merged_vulnerabilities_view
                    ORDER BY random()
                    LIMIT %s
                """, (TEST_LIMIT,))
            else:
                cur.execute("""
                    SELECT mv.es_id, mv.affected_products
                    FROM merged_vulnerabilities_view mv
                    LEFT JOIN (
                        SELECT DISTINCT es_id FROM vuln_version_range WHERE extractor_ver >= %s
                    ) v ON mv.es_id = v.es_id
                    WHERE v.es_id IS NULL
                    LIMIT %s
                """, (EXTRACTOR_VER, bt))
            tasks = cur.fetchall()
            logger.debug(f"任务获取 rows={len(tasks)} extractor_ver>={EXTRACTOR_VER} test_mode={tm}")
            if tasks:
                sample = tasks[:3]
                logger.debug("任务样例: %s", [ { 'es_id': t['es_id'], 'len_text': len(t.get('affected_products') or '') } for t in sample ])
    finally:
        pool.putconn(conn)

    if not tasks:
        logger.info("没有需要处理的数据。")
        try: pool.closeall()
        except Exception: pass
        return {
            'total_tasks': 0,
            'processed': 0,
            'skipped': 0,
            'empty': 0,
            'failed': 0,
            'inserted_products': 0,
            'elapsed_sec': 0.0
        }

    logger.info(f"本批待处理: {len(tasks)} 条，线程: {MAX_WORKERS}，LLM并发: {LLM_CONCURRENCY}")

    ok, skip, empty, err, prod_total = 0, 0, 0, 0, 0
    fb_cnt = 0
    ph_cnt = 0
    retry_total = 0
    started = time.time()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        future_map = {ex.submit(worker, t, pool): t for t in tasks}
        for fut in as_completed(future_map):
            res = fut.result()
            es_id = res.get("es_id")
            if res.get("inserted"):
                ok += 1
                prod_total += int(res.get('count') or 0)
                retry_total += int(res.get('retries') or 0)
                if res.get("fallback"):
                    fb_cnt += 1
                if res.get("placeholder"):
                    ph_cnt += 1
                tag = []
                if res.get("fallback"): tag.append("fallback")
                if res.get("placeholder"): tag.append("placeholder")
                if res.get('retries'):
                    tag.append(f"retries={res.get('retries')}")
                tag_str = (" " + ",".join(tag)) if tag else ""
                logger.info(f"✅ 写入完成 {es_id}（products={res.get('count')}){tag_str}")
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
    stats = {
        'total_tasks': len(tasks),
        'processed': ok,
        'skipped': skip,
        'empty': empty,
        'failed': err,
        'inserted_products': prod_total,
    'elapsed_sec': round(elapsed, 3),
    'fallback_used': fb_cnt,
    'placeholders': ph_cnt,
    'retry_total': retry_total
    }
    logger.info("批次完成统计 %s", stats)

    try:
        pool.closeall()
    except Exception:
        pass
    return stats


def main():  # 保持向后兼容脚本执行
    run_batch()


if __name__ == "__main__":
    main()
