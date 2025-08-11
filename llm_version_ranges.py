import logging
import os, json, hashlib, psycopg2
import psycopg2.extras as pg_extras
from typing import List, Tuple, Dict, Any
from dashscope import Generation
import traceback
from datetime import datetime

# ====================== 日志配置 ======================
LOG_FILE = f"log/llm_version_ranges_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

# 控制台日志（简洁）
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
console_handler.setFormatter(console_formatter)

# 文件日志（详细）
file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
file_handler.setFormatter(file_formatter)

logging.basicConfig(level=logging.DEBUG, handlers=[console_handler, file_handler])
logger = logging.getLogger(__name__)

# ====================== 基础配置 ======================
PG_DSN = os.getenv("PG_DSN", "host=localhost port=5432 dbname=vul user=test password=test")
BATCH = int(os.getenv("BATCH", "500"))
EXTRACTOR_VER = int(os.getenv("EXTRACTOR_VER", "1"))
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY")
QWEN_MODEL = os.getenv("QWEN_MODEL", "qwen-turbo")

# 测试模式参数
TEST_MODE = False
TEST_LIMIT = 20

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
            start = code_from_str(vs[0])
            end = code_from_str(vs[1])
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

# ====================== LLM 调用 ======================
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

def call_llm(text: str) -> Dict[str, Any]:
    if not DASHSCOPE_API_KEY:
        raise RuntimeError("缺少 DASHSCOPE_API_KEY 环境变量")
    messages = [
        {"role": "system", "content": LLM_SYSTEM},
        {"role": "user", "content": text}
    ]
    resp = Generation.call(model=QWEN_MODEL, messages=messages, temperature=0.1)
    logger.debug(f"LLM 原始响应: {resp}")

    if resp.status_code != 200:
        raise RuntimeError(f"Qwen API error: {resp.status_code} - {getattr(resp, 'message', '')}")

    if hasattr(resp, "output") and getattr(resp.output, "text", None):
        content = resp.output.text
    elif hasattr(resp, "output") and getattr(resp.output, "choices", None):
        content = resp.output.choices[0]["message"]["content"]
    else:
        raise RuntimeError(f"Qwen API 返回格式不符合预期: {resp}")

    jtxt = _extract_json_str(content)
    return json.loads(jtxt)

# ====================== 数据库写入 ======================
def md5(s: str) -> str:
    return hashlib.md5((s or "").encode("utf-8")).hexdigest()

def upsert_ranges(conn, es_id: str, src_text: str, products: List[Dict[str,Any]]):
    raw_hash = md5(src_text)
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

# ====================== 主流程 ======================
def main():
    conn_read = psycopg2.connect(PG_DSN)   # 读连接
    conn_write = psycopg2.connect(PG_DSN)  # 写连接

    if TEST_MODE:
        cur = conn_read.cursor(cursor_factory=pg_extras.RealDictCursor)
        cur.execute(f"""
            SELECT es_id, affected_products
            FROM merged_vulnerabilities_view
            ORDER BY random()
            LIMIT {TEST_LIMIT}
        """)
        rows = cur.fetchall()
    else:
        cur = conn_read.cursor(name="mv_llm_cursor", cursor_factory=pg_extras.RealDictCursor)
        cur.itersize = BATCH
        cur.execute("SELECT es_id, affected_products FROM merged_vulnerabilities_view")
        rows = cur

    processed = 0
    for row in rows:
        es_id = row["es_id"]
        text = row["affected_products"] or ""

        logger.info(f"[{processed+1}] 处理 es_id: {es_id}")

        with conn_write.cursor() as c2:
            c2.execute("""
              SELECT 1 FROM vuln_version_range
               WHERE es_id=%s AND extractor_ver >= %s
               LIMIT 1
            """, (es_id, EXTRACTOR_VER))
            if c2.fetchone():
                logger.debug(f"跳过已处理 es_id: {es_id}")
                continue

        try:
            result = call_llm(text)
            logger.debug(f"LLM 解析结果: {json.dumps(result, ensure_ascii=False, indent=2)}")
            products = result.get("products") or []
        except Exception as e:
            logger.error(f"LLM 调用失败 - es_id: {es_id} - {e}")
            logger.debug(traceback.format_exc())
            products = []

        if products:
            try:
                upsert_ranges(conn_write, es_id, text, products)
                conn_write.commit()
                logger.debug(f"写入完成: {es_id}")
            except Exception as e:
                logger.error(f"写入数据库失败 - es_id: {es_id} - {e}")
                logger.debug(traceback.format_exc())
                conn_write.rollback()
        else:
            logger.warning(f"未提取到产品信息 - es_id: {es_id}")

        processed += 1
        if TEST_MODE and processed >= TEST_LIMIT:
            logger.info(f"测试模式：已处理 {TEST_LIMIT} 条，提前结束。")
            break

    cur.close()
    conn_read.close()
    conn_write.close()
    logger.info(f"done. total scanned: {processed}")

if __name__ == "__main__":
    main()
