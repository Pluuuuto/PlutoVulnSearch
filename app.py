"""FastAPI 应用：
功能：
    - /search 关键词 或 产品+版本 查询 ES。
    - /upload 单文件增量导入（自动写库 + 可选触发 LLM 与 ES）。

当前仅支持单文件上传（JSON=推断 cve, XML 需明确 src=cnvd|cnnvd）。后续如需批量可扩展 zip。"""
from __future__ import annotations
from fastapi import FastAPI, Query, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import os, tempfile
from typing import Optional, List

from search_es import search_vulnerabilities_by_product_version, search_by_keyword
from db import ensure_schema
from pipeline_daily import incremental_sync

ES_URL = os.getenv("ES_URL", os.getenv("ES_HOST", "http://localhost:9200"))
ES_INDEX = os.getenv("ES_INDEX", "test_vulnerabilities")

app = FastAPI(title="PlutoVulnSearch API")

# CORS (开发阶段放开)
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
    1) 关键词模式：提供 q → multi_match
    2) 产品+版本模式：提供 product（可选 version）→ nested wildcard + 范围过滤
    优先产品模式；都未给出则 400。
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
        return {"mode": "product_version", "count": len(docs[:limit]), "results": docs[:limit]}
    if q:
        docs = search_by_keyword(ES_URL, ES_INDEX, q, limit)
        return {"mode": "keyword", "count": len(docs), "results": docs}
    raise HTTPException(status_code=400, detail="需要提供 q 或 product 至少一个参数")

@app.post("/upload", summary="上传原始源文件（单个）并写库 + 可选 LLM + ES (增量/全量)")
async def upload_file(
    file: UploadFile = File(...),
    run_llm: bool = True,
    sync_es: bool = True,
    mode: str = Query("incremental", description="处理模式 incremental|full"),
    src: str | None = Query(None, description="数据来源: cve|cnvd|cnnvd (若未指定则根据文件名后缀判断)")
):
    """最小原则：不在这里重写解析，只调用各目录 parser + db_handler。

    约束：一次仅上传一个源的单文件。若需要批量，请自行打多次请求或后续扩展 zip 支持。
    """
    ensure_schema()
    name = (file.filename or '').lower()
    if not src:
        if name.endswith('.json'):
            src = 'cve'
        elif name.endswith('.xml'):
            # 无法区分 cnvd/cnnvd，只能要求显式传 src
            raise HTTPException(status_code=400, detail='XML 请显式指定 src=cnvd 或 src=cnnvd')
        else:
            raise HTTPException(status_code=400, detail='无法自动识别文件类型，请提供 src 参数')
    src = src.lower()
    raw = await file.read()
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=( '.json' if src=='cve' else '.xml'))
        tmp.write(raw)
        tmp_path = tmp.name
        tmp.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'写临时文件失败: {e}')

    inserted_stats = {"inserted": 0, "skipped": 0, "failed": 0}
    try:
        if src == 'cve':
            from CVE.parser import parse_vulnerabilities as parse_cve
            from CVE.db_handler import insert_vulnerabilities as insert_cve, connect_db as conn_cve
            vulns = parse_cve(tmp_path)
            conn = conn_cve()
            s, skipped, failed = insert_cve(conn, vulns, source_file=name)
            inserted_stats = {"inserted": s, "skipped": len(skipped), "failed": len(failed)}
            conn.close()
        elif src == 'cnvd':
            from CNVD.parser import parse_vulnerabilities as parse_cnvd
            from CNVD.db_handler import insert_vulnerabilities as insert_cnvd, connect_db as conn_cnvd
            vulns = parse_cnvd(tmp_path)
            conn = conn_cnvd()
            s, skipped, failed = insert_cnvd(conn, vulns, source_file=name)
            inserted_stats = {"inserted": s, "skipped": len(skipped), "failed": len(failed)}
            conn.close()
        elif src == 'cnnvd':
            from CNNVD.parser import parse_vulnerabilities as parse_cnnvd
            from CNNVD.db_handler import insert_vulnerabilities as insert_cnnvd, connect_db as conn_cnnvd
            vulns = parse_cnnvd(tmp_path)
            conn = conn_cnnvd()
            s, skipped, failed = insert_cnnvd(conn, vulns, source_file=name)
            inserted_stats = {"inserted": s, "skipped": len(skipped), "failed": len(failed)}
            conn.close()
        else:
            raise HTTPException(status_code=400, detail='不支持的 src')
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'解析或写入失败: {e}')
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass

    # 收集刚插入/跳过的 es_id（推断规则：es_id 由三个源各自唯一键组成，使用视图逻辑: cve->cve_id, cnvd->cnvd_number, cnnvd->vuln_id）
    es_ids: list[str] = []
    if mode == 'incremental':
        if src == 'cve':
            es_ids = [v['cve_id'] for v in vulns if v.get('cve_id')]
        elif src == 'cnvd':
            es_ids = [v['cnvd_number'] for v in vulns if v.get('cnvd_number')]
        elif src == 'cnnvd':
            es_ids = [v['vuln_id'] for v in vulns if v.get('vuln_id')]
    inc_stats = incremental_sync(run_llm=run_llm, es_sync=sync_es, mode=mode, es_ids=es_ids)
    return {
        "source": src,
        "mode": mode,
        **inserted_stats,
        "llm": inc_stats.get('version_ranges', {}),
        "es": inc_stats.get('es', {})
    }

if __name__ == "__main__":
    # 简单自测
    print("[SELFTEST] try keyword search 'openssl'")
    try:
        rs = search(q="openssl", product=None, version=None)  # type: ignore
        print(" ->", rs.get('count'))
    except Exception as e:
        print(" !! error", e)
    print("[DONE]")
