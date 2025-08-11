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
    es = Elasticsearch(es_host)
    version_code = code(*parse_semver(version_str))
    query = {
        "query": {
            "nested": {
                "path": "version_ranges",
                "query": {
                    "bool": {
                        "must": [
                            { "match_phrase": { "version_ranges.product_id": product_name } },
                            { "range": { "version_ranges.min_code": { "lte": version_code } } },
                            { "range": { "version_ranges.max_code": { "gte": version_code } } }
                        ]
                    }
                }
            }
        }
    }
    res = es.search(index=index, body=query)

    hits = res.get("hits", {}).get("hits", [])
    print(f"\n=== 查询条件 ===")
    print(f"软件名: {product_name}")
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
        index="vulnerabilities",
        product_name="freebsd",
        version_str="3.9.0"
    )
