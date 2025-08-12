from elasticsearch import Elasticsearch

def parse_semver(s: str):
    if not s:
        return (0,0,0,0)
    s = s.strip().lower()
    if s.startswith("v"):
        s = s[1:]
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

def search_vulnerabilities_by_product_version(es_host, index, product_name, version_str):
    """按产品(模糊) + 版本号查找漏洞。

    product_name 支持: 部分词 / 任一大小写。例如 product_name='Adobe' 能命中 product_id='adobe bridge'.
    实现方式: 将输入按空白拆分为 tokens, 对每个 token 构造 case_insensitive wildcard *token* 约束。
    说明: version_ranges.product_id 是 keyword, 使用 wildcard 而非 match; 若版本为空可仅按产品过滤。
    """
    es = Elasticsearch(es_host)
    tokens = [t.strip().lower() for t in (product_name or '').split() if t.strip()]
    version_filters = []
    if version_str:
        version_code = code(*parse_semver(version_str))
        version_filters = [
            { "range": { "version_ranges.min_code": { "lte": version_code } } },
            { "range": { "version_ranges.max_code": { "gte": version_code } } }
        ]
    else:
        version_code = None
    name_filters = []
    for tk in tokens or [product_name.lower()]:
        if not tk:
            continue
        name_filters.append({
            "wildcard": {
                "version_ranges.product_id": {
                    "value": f"*{tk}*",
                    "case_insensitive": True
                }
            }
        })
    must_clauses = name_filters + version_filters if name_filters else version_filters
    if not must_clauses:  # 没有任何筛选，避免全索引扫描
        raise ValueError("必须提供 product_name 或 version_str 至少一项")
    query = {
        "query": {
            "nested": {
                "path": "version_ranges",
                "query": {
                    "bool": {
                        "must": must_clauses
                    }
                }
            }
        }
    }
    res = es.search(index=index, body=query)

    hits = res.get("hits", {}).get("hits", [])
    print(f"\n=== 查询条件 ===")
    print(f"产品查询: {product_name}")
    if version_code is not None:
        print(f"版本号: {version_str} (code={version_code})")
    print(f"匹配到 {len(hits)} 条结果\n")

    if hits:
        for hit in hits:
            src = hit["_source"]
            print(f"es_id: {src['es_id']}")
            print(f"affected_products: {src['affected_products']}")
            if src.get("version_ranges"):
                for vr in src["version_ranges"]:
                    print(f"  - product_id: {vr['product_id']}")
                    print(f"    version_text: {vr['version_text']}")
                    print(f"    min_code: {vr['min_code']}, max_code: {vr['max_code']}")
            print("-" * 40)
    else:
        print("⚠️ 没有匹配的漏洞记录。")

    return [hit["_source"] for hit in hits]

# 使用示例
if __name__ == "__main__":
    results = search_vulnerabilities_by_product_version(
        es_host="http://localhost:9200",
        index="test_vulnerabilities",
        product_name="wordpress",
        version_str="22.0"
    )
