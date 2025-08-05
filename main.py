from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from search_db import search_by_keyword

app = FastAPI(title="PlutoVulnSearch API")

# 允许跨域（可用于前端调试）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/search")
def search(
    q: str = Query(..., description="关键词（软件名、版本号、CVE编号）"),
    limit: int = Query(20, description="返回条数")
):
    print(q)
    print(limit)
    results = search_by_keyword(q, limit)
    return {"count": len(results), "results": results}
