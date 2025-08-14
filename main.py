from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
from typing import Optional

from search_db import search_by_keyword
from search_es import search_vulnerabilities_by_product_version

ES_URL = os.getenv("ES_URL", os.getenv("ES_HOST", "http://localhost:9200"))
ES_INDEX = os.getenv("ES_INDEX", "test_vulnerabilities")

app = FastAPI(title="PlutoVulnSearch API")

# 允许跨域（可用于前端调试）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/search", summary="统一搜索接口")
def search(
    q: Optional[str] = Query(None, description="关键词（软件名、版本号、CVE编号）"),
    product: Optional[str] = Query(None, description="产品名称（模糊，空格分词）"),
    version: Optional[str] = Query(None, description="版本号，可与 product 搭配"),
    limit: int = Query(20, ge=1, le=200, description="返回条数上限")
):
    """搜索模式：
    1) 关键词模式：提供 q → multi_match （affected_products / version text 等）
    2) 产品+版本模式：提供 product（可选 version）→ nested wildcard + 范围过滤
    规则：优先使用产品模式（如果提供了 product）；否则使用关键词模式；两者皆空则 400。
    """
    if product:
        try:
            docs = search_vulnerabilities_by_product_version(
                es_host=ES_URL,
                index=ES_INDEX,
                product_name=product,
                version_str=version or ""
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        # search_vulnerabilities_by_product_version 已返回全部匹配，截取 limit
        docs = docs[:limit]
        return {"mode": "product_version", "count": len(docs), "results": docs}
    if q:
        docs = search_by_keyword(q, limit)
        return {"mode": "keyword", "count": len(docs), "results": docs}
    raise HTTPException(status_code=400, detail="需要提供 q 或 product 至少一个参数")


if __name__ == "__main__":
    # 简单测试示例：在本地直接运行 python main.py 执行这些测试打印结果
    print("[TEST] Keyword search: 'openssl'")
    try:
        kw_results = search_by_keyword("openssl", 5)
        print(f"  -> {len(kw_results)} hit(s)")
    except Exception as e:
        print("  !! keyword search error", e)

    print("[TEST] Product search: product=wordpress version=6.2.1")
    try:
        pv_results = search_vulnerabilities_by_product_version(
            es_host=ES_URL,
            index=ES_INDEX,
            product_name="wordpress",
            version_str="5.1"
        )
        print(f"  -> {len(pv_results)} hit(s)")
    except Exception as e:
        print("  !! product search error", e)

    print("[TEST DONE]")
