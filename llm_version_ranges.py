# llm_version_ranges.py
# 仅用通义千问（阿里云百炼 DashScope）抽取版本范围，不做正则规则解析。
# 功能：读取 merged_vulnerabilities_view(es_id, affected_products) ->
#       调 LLM 返回统一 JSON -> 转换为整数区间 -> 写入 vuln_version_range

import os, json, hashlib, psycopg2
import psycopg2.extras as pg_extras
from typing import List, Tuple, Dict, Any

# ====================== 基础配置 ======================
PG_DSN = os.getenv("PG_DSN", "host=localhost port=5432 dbname=vul user=test password=test")
BATCH = int(os.getenv("BATCH", "500"))
EXTRACTOR_VER = int(os.getenv("EXTRACTOR_VER", "1"))

# 通义千问（阿里云百炼）
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY")  # 在系统/终端设置：$env:DASHSCOPE_API_KEY="xxx"
QWEN_MODEL = os.getenv("QWEN_MODEL", "qwen-turbo")  # 可改为 qwen-plus / qwen-long

# ====================== 版本编码与区间 ======================
def parse_semver(s: str) -> Tuple[int,int,int,int]:
    """支持2~4段版本号，缺位补0，超出4段截断"""
    if not s:
        return (0,0,0,0)
    s = s.strip().lower()
    if s.startswith("v"):
        s = s[1:]
    if "u" in s and "." not in s:  # 8u121 -> 8.0.0.121
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
        if p == "x":
            nums.append(0)
        else:
            try:
                nums.append(int(p))
            except:
                nums.append(0)
    while len(nums) < 4:  # 不足补0
        nums.append(0)
    if len(nums) > 4:     # 超出截断
        nums = nums[:4]
    return nums[0], nums[1], nums[2], nums[3]

def code(a:int,b:int,c:int,d:int) -> int:
    """四段版本编码"""
    return a*1_000_000_000 + b*1_000_000 + c*1_000 + d

def code_from_str(v: str) -> int:
    a,b,c,d = parse_semver(v)
    return code(a,b,c,d)


def wildcard_range(vx: str) -> Tuple[int,int]:
    """支持 '8.x' 或 '1.18.x'（约定 LLM 输出）。"""
    vx = (vx or "").strip().lower()
    if not vx:
        return (0,0)
    # 标准形态
    if vx.endswith(".x"):
        core = vx[:-2].strip()
        if not core:
            return (0,0)
        if "." in core:
            parts = core.split(".")
            try:
                major = int(parts[0].strip())
                minor = int(parts[1].strip())
                return code(major, minor, 0), code(major, minor, 999)
            except:
                return (0,0)
        else:
            try:
                major = int(core)
                return code(major, 0, 0), code(major, 999, 999)
            except:
                return (0,0)
    # 兼容 '8x'
    if vx.endswith("x"):
        try:
            major = int(vx[:-1])
            return code(major,0,0), code(major,999,999)
        except:
            return (0,0)
    return (0,0)

def merge_intervals(iv: List[Tuple[int,int]]) -> List[Tuple[int,int]]:
    if not iv: return []
    iv = sorted(iv)
    out = [iv[0]]
    for a,b in iv[1:]:
        la,lb = out[-1]
        if a <= lb+1:
            out[-1] = (la, max(lb,b))
        else:
            out.append((a,b))
    return out

def merge_intervals_with_labels(iv: List[Tuple[int,int,str,str]]) -> List[Tuple[int,int,str,str]]:
    """合并区间，保留显示用的 min_str/max_str"""
    if not iv: return []
    iv = sorted(iv, key=lambda x: x[0])
    out = [iv[0]]
    for a,b,as_,bs_ in iv[1:]:
        la,lb,las, lbs = out[-1]
        if a <= lb+1:
            # 合并时：保留原来的 min_str，用新的 max_str
            out[-1] = (la, max(lb,b), las, bs_)
        else:
            out.append((a,b,as_,bs_))
    return out

def items_to_intervals(items: List[Dict[str, Any]]) -> List[Tuple[int, int, str, str, bool, bool]]:
    """
    返回: (下界, 上界, 下界原文, 上界原文, 下界是否包含, 上界是否包含)
    """
    INF_MIN, INF_MAX = -2**31, 2**31 - 1
    res = []
    lower_bound = None
    upper_bound = None
    lower_str = None
    upper_str = None
    lower_inclusive = None
    upper_inclusive = None

    for it in items or []:
        typ = (it.get("type") or "").lower().strip()
        vs = it.get("versions") or []
        if not vs:
            continue

        a,b,c,d = parse_semver(vs[0])
        base_code = code(a,b,c,d)

        if typ == "eq":
            res.append((base_code, base_code, vs[0], vs[0], True, True))

        elif typ == "lt":
            res.append((INF_MIN, base_code, "-∞", vs[0], False, False))

        elif typ == "lte":
            if lower_bound is not None:
                res.append((lower_bound, base_code, lower_str, vs[0], lower_inclusive, True))
                lower_bound, lower_str, lower_inclusive = None, None, None
            else:
                upper_bound, upper_str, upper_inclusive = base_code, vs[0], True

        elif typ == "gt":
            res.append((base_code, INF_MAX, vs[0], "+∞", False, False))

        elif typ == "gte":
            if upper_bound is not None:
                res.append((base_code, upper_bound, vs[0], upper_str, True, upper_inclusive))
                upper_bound, upper_str, upper_inclusive = None, None, None
            else:
                lower_bound, lower_str, lower_inclusive = base_code, vs[0], True

        elif typ == "range" and len(vs) >= 2:
            a1,b1,c1,d1 = parse_semver(vs[0])
            a2,b2,c2,d2 = parse_semver(vs[1])
            start = code(a1,b1,c1,d1)
            end = code(a2,b2,c2,d2)
            if start > end:
                start, end = end, start
                vs[0], vs[1] = vs[1], vs[0]
            res.append((start, end, vs[0], vs[1], True, True))

        elif typ == "wildcard":
            lo, hi = wildcard_range(vs[0])
            res.append((lo, hi, vs[0], vs[0], True, True))

        elif typ == "list":
            for v in vs:
                a,b,c,d = parse_semver(v)
                res.append((code(a,b,c,d), code(a,b,c,d), v, v, True, True))

    # 循环结束后，处理未配对的 gte/lte
    if upper_bound is not None:
        res.append((INF_MIN, upper_bound, "-∞", upper_str, False, upper_inclusive))
    if lower_bound is not None:
        res.append((lower_bound, INF_MAX, lower_str, "+∞", lower_inclusive, False))

    return res


def interval_to_text(iv: List[Tuple[int,int,str,str,bool,bool]]) -> str:
    parts = []
    for a, b, as_, bs_, incl_a, incl_b in iv:
        if as_ == "-∞":
            # 上界
            if incl_b:
                parts.append(f"<={bs_}")
            else:
                parts.append(f"<{bs_}")
        elif bs_ == "+∞":
            # 下界
            if incl_a:
                parts.append(f">={as_}")
            else:
                parts.append(f">{as_}")
        elif as_ == bs_:
            parts.append(as_)
        elif incl_a and incl_b and as_ != "-∞" and bs_ != "+∞":
            # 闭区间范围
            parts.append(f"{as_}-{bs_}")
        else:
            # 范围
            left = f">={as_}" if incl_a else f">{as_}"
            right = f"<={bs_}" if incl_b else f"<{bs_}"
            parts.append(f"{left} & {right}")
    return "; ".join(parts)
# ====================== LLM（通义千问） ======================
# pip install dashscope
from dashscope import Generation

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
    """从响应中提取 JSON（防止模型加了说明文字/代码块）。"""
    s = (s or "").strip()
    i = s.find("{"); j = s.rfind("}")
    if i != -1 and j != -1 and j > i:
        return s[i:j+1]
    return s

def call_llm(affected_products: str) -> Dict[str, Any]:
    if not DASHSCOPE_API_KEY:
        raise RuntimeError("缺少 DASHSCOPE_API_KEY 环境变量")
    messages = [
        {"role": "system", "content": LLM_SYSTEM},
        {"role": "user", "content": f"原始文本（可能多语言/多产品）：\n{(affected_products or '')[:8000]}\n请严格输出上述 JSON。"}
    ]
    resp = Generation.call(
        model=QWEN_MODEL,
        messages=messages,
        temperature=0.1,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Qwen API error: {resp.status_code}, {getattr(resp, 'message', '')}")
    # 获取文本内容
    content = ""
    try:
        content = resp.output.choices[0]["message"]["content"]
    except Exception:
        content = resp.output.get("text", "")

    jtxt = _extract_json_str(content)
    try:
        return json.loads(jtxt)
    except Exception as e:
        raise RuntimeError(f"LLM 返回非 JSON，内容片段: {content[:400]} ...") from e

# ====================== DB 写入 ======================
def md5(s: str) -> str:
    return hashlib.md5((s or "").encode("utf-8")).hexdigest()

def upsert_ranges(conn, es_id: str, src_text: str, products: List[Dict[str,Any]]):
    raw_hash = md5(src_text)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM vuln_version_range WHERE es_id=%s", (es_id,))
        conn.commit()
    with conn.cursor() as cur:
        for p in products or []:
            pid = (p.get("product_id") or "unknown").strip().lower()
            iv = items_to_intervals(p.get("items") or [])
            if not iv:  # 无区间就不写
                continue
            vtext = interval_to_text(iv)
            conf = float(p.get("confidence") or 0.0)
            for lo,hi in iv:
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
        conn.commit()

# ====================== 主流程 ======================
def main():
    conn = psycopg2.connect(PG_DSN)
    cur = conn.cursor(name="mv_llm_cursor", cursor_factory=pg_extras.RealDictCursor)
    cur.itersize = BATCH
    cur.execute("SELECT es_id, affected_products FROM merged_vulnerabilities_view")

    processed = 0
    for row in cur:
        es_id = row["es_id"]
        text = row["affected_products"] or ""
        # 变更检测（相同 hash 且抽取器版本不低于当前就跳过）
        with conn.cursor() as c2:
            c2.execute("""
              SELECT 1 FROM vuln_version_range
               WHERE es_id=%s AND raw_hash=%s AND extractor_ver >= %s
               LIMIT 1
            """, (es_id, md5(text), EXTRACTOR_VER))
            if c2.fetchone():
                continue

        try:
            result = call_llm(text)
            products = result.get("products") or []
        except Exception as e:
            # 失败：跳过当前记录（也可以记录错误表，这里保持基础功能简洁）
            products = []

        if products:
            upsert_ranges(conn, es_id, text, products)

        processed += 1
        if processed % 200 == 0:
            print(f"processed: {processed}")

    cur.close()
    conn.close()
    print(f"done. total scanned: {processed}")

if __name__ == "__main__":
    main()
