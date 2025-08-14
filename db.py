"""数据库工具模块

职责：
 1. 提供统一的 PostgreSQL 连接 (get_conn)。
 2. 统一集中管理所有表/索引/视图 DDL，避免各子目录重复创建。
 3. 通过 ensure_schema() 在启动 pipeline 或独立导入前保证结构存在（幂等）。

表说明：
    - cve / cnvd / cnnvd    原始三方数据表（追加写入，不更新删除）。
    - vuln_version_range     版本区间规范化表（LLM 解析结果写入）。
    - merged_vulnerabilities_view 融合视图，对三源进行去重、聚合、生成 es_id。

注意：不随意修改表结构；新增列需评估对现有脚本与 ES 数据的影响。
"""
from __future__ import annotations

import os
import logging
import psycopg2
from psycopg2 import errors
from psycopg2.extensions import connection as PGConnection

LOG = logging.getLogger(__name__)

PG_DSN = os.getenv("PG_DSN")  # 优先环境变量；为空时回退读取 db_config.ini

_GLOBAL_CONN: PGConnection | None = None

BASE_TABLE_DDL = [  # 按顺序执行的 DDL 语句列表（幂等）
    """
    CREATE TABLE IF NOT EXISTS cve (
        id SERIAL PRIMARY KEY,
        cve_id TEXT UNIQUE,
        published_date DATE,
        affected_products TEXT,
        solution TEXT,
        cvss_score NUMERIC(3,1),
    vuln_description TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS cnvd (
        id SERIAL PRIMARY KEY,
        cnvd_number TEXT UNIQUE,
        title TEXT,
        severity TEXT,
        products TEXT,
        cvenumber TEXT,
        cveurl TEXT,
        is_event TEXT,
        submit_time DATE,
        open_time DATE,
        reference_link TEXT,
        discoverer_name TEXT,
        formal_way TEXT,
        description TEXT,
        patch_name TEXT,
    patch_description TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS cnnvd (
        id SERIAL PRIMARY KEY,
        name TEXT,
        vuln_id TEXT UNIQUE,
        published DATE,
        modified DATE,
        source TEXT,
        severity TEXT,
        vuln_type TEXT,
        vuln_descript TEXT,
        products TEXT,
        cve_id TEXT,
        bugtraq_id TEXT,
    vuln_solution TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS vuln_version_range (
      es_id          TEXT        NOT NULL,
      product_id     TEXT        NOT NULL,
      min_code       BIGINT      NOT NULL,
      max_code       BIGINT      NOT NULL,
      confidence     REAL        NULL,
      version_text   TEXT        NULL,
      source_text    TEXT        NULL,
      raw_hash       TEXT        NOT NULL,
    extractor_ver  INT         NOT NULL,
      PRIMARY KEY (es_id, product_id, min_code, max_code)
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_vr_esid  ON vuln_version_range(es_id);",
    "CREATE INDEX IF NOT EXISTS idx_vr_prod  ON vuln_version_range(product_id);",
    "CREATE INDEX IF NOT EXISTS idx_vr_range ON vuln_version_range(min_code, max_code);",
]

MERGED_VIEW_SQL = """-- 融合视图：按优先级(cve->cnvd->cnnvd) 组合统一漏洞 ID 与字段（cve_id 简化：直接取 cve.cve_id -> cnvd.cvenumber -> cnnvd.cve_id）
CREATE OR REPLACE VIEW merged_vulnerabilities_view AS
SELECT DISTINCT ON (
    COALESCE(UPPER(cve.cve_id), UPPER(cnvd.cnvd_number), UPPER(cnnvd.vuln_id))
)
    COALESCE(
        UPPER(cve.cve_id),
        UPPER(cnvd.cnvd_number),
        UPPER(cnnvd.vuln_id),
        md5(COALESCE(cve.vuln_description,'') || COALESCE(cnvd.description,'') || COALESCE(cnnvd.vuln_descript,''))
    ) AS es_id,
    UPPER(COALESCE(cve.cve_id, cnvd.cvenumber, cnnvd.cve_id)) AS cve_id,
    cnvd.cnvd_number,
    cnnvd.vuln_id AS cnnvd_number,
    CONCAT_WS('; ', NULLIF(cve.vuln_description,''), NULLIF(cnvd.description,''), NULLIF(cnnvd.vuln_descript,'')) AS description,
    CONCAT_WS(' || ', NULLIF(cve.affected_products,''), NULLIF(cnvd.products,''), NULLIF(cnnvd.products,'')) AS affected_products,
    CONCAT_WS(' || ', NULLIF(cve.solution,''), NULLIF(cnvd.patch_description,''), NULLIF(cnnvd.vuln_solution,'')) AS solution,
    COALESCE(cve.cvss_score::TEXT, cnvd.severity, cnnvd.severity) AS risk_display,
    CASE
        WHEN cve.cvss_score >= 9.5 THEN 4
        WHEN cve.cvss_score >= 7.0 THEN 3
        WHEN cve.cvss_score >= 4.0 THEN 2
        WHEN cve.cvss_score IS NOT NULL THEN 1
        WHEN cnvd.severity = '高' THEN 3
        WHEN cnvd.severity = '中' THEN 2
        WHEN cnvd.severity = '低' THEN 1
        WHEN cnnvd.severity = '超危' THEN 4
        WHEN cnnvd.severity = '高危' THEN 3
        WHEN cnnvd.severity = '中危' THEN 2
        WHEN cnnvd.severity = '低危' THEN 1
        ELSE 0
    END AS risk_level
FROM cve
LEFT JOIN cnvd ON UPPER(cve.cve_id) = UPPER(cnvd.cvenumber)
LEFT JOIN cnnvd ON UPPER(cve.cve_id) = UPPER(cnnvd.cve_id)
UNION
SELECT DISTINCT ON (
    COALESCE(UPPER(cnvd.cnvd_number), UPPER(cnnvd.vuln_id))
)
    COALESCE(
        UPPER(cnvd.cnvd_number),
        UPPER(cnnvd.vuln_id),
        md5(COALESCE(cnvd.description,'') || COALESCE(cnnvd.vuln_descript,''))
    ) AS es_id,
    UPPER(COALESCE(cnvd.cvenumber, cnnvd.cve_id)) AS cve_id,
    cnvd.cnvd_number,
    cnnvd.vuln_id AS cnnvd_number,
    CONCAT_WS('; ', NULLIF(cnvd.description,''), NULLIF(cnnvd.vuln_descript,'')) AS description,
    CONCAT_WS(' || ', NULLIF(cnvd.products,''), NULLIF(cnnvd.products,'')) AS affected_products,
    CONCAT_WS(' || ', NULLIF(cnvd.patch_description,''), NULLIF(cnnvd.vuln_solution,'')) AS solution,
    COALESCE(cnvd.severity, cnnvd.severity) AS risk_display,
    CASE
        WHEN cnvd.severity = '高' THEN 3
        WHEN cnvd.severity = '中' THEN 2
        WHEN cnvd.severity = '低' THEN 1
        WHEN cnnvd.severity = '超危' THEN 4
        WHEN cnnvd.severity = '高危' THEN 3
        WHEN cnnvd.severity = '中危' THEN 2
        WHEN cnnvd.severity = '低危' THEN 1
        ELSE 0
    END AS risk_level
FROM cnvd
LEFT JOIN cnnvd ON UPPER(cnvd.cvenumber) = UPPER(cnnvd.cve_id)
WHERE NOT EXISTS (
    SELECT 1 FROM cve WHERE UPPER(cve.cve_id) = UPPER(cnvd.cvenumber)
);
"""


def get_conn() -> PGConnection:
    """获取（或创建）全局单例连接。

    返回：psycopg2 connection 对象（autocommit=False）。
    说明：单实例复用，减少频繁握手开销；调用方应避免显式关闭全局连接。"""
    global _GLOBAL_CONN
    if _GLOBAL_CONN and not _GLOBAL_CONN.closed:
        return _GLOBAL_CONN
    if not PG_DSN:
        import configparser
        cfg = configparser.ConfigParser()
        cfg.read('db_config.ini')
        d = cfg['postgresql']
        _GLOBAL_CONN = psycopg2.connect(**d)
    else:
        _GLOBAL_CONN = psycopg2.connect(PG_DSN)
    _GLOBAL_CONN.autocommit = False
    return _GLOBAL_CONN


def ensure_schema():
    """幂等创建全部表、索引与视图。

    兼容：若当前数据库用户不是现有对象 owner，部分 CREATE INDEX / VIEW 可能抛出
    InsufficientPrivilege；此时记录警告并继续，不阻塞整体流程（表已存在仍可使用）。
    建议后续由有权限账号执行 ALTER TABLE/VIEW OWNER 以恢复自动管理能力。
    """
    conn = get_conn()
    priv_warnings = 0
    with conn.cursor() as cur:
        for ddl in BASE_TABLE_DDL:
            try:
                cur.execute(ddl)
                conn.commit()
            except errors.InsufficientPrivilege:
                conn.rollback()
                priv_warnings += 1
                first_line = next((ln.strip() for ln in ddl.splitlines() if ln.strip()), ddl[:60])
                LOG.warning("Skip DDL due to privilege issue: %s", first_line)
                continue
            except Exception:
                conn.rollback()
                LOG.exception("Unexpected DDL error; re-raising (statement aborted)")
                raise
        try:
            cur.execute(MERGED_VIEW_SQL)
            conn.commit()
        except errors.InsufficientPrivilege:
            conn.rollback()
            priv_warnings += 1
            LOG.warning("Skip view creation (not owner). Existing view may remain or be absent.")
        except Exception:
            conn.rollback()
            LOG.exception("Unexpected error creating view; re-raising")
            raise
    if priv_warnings:
        LOG.warning("Schema ensured with %d privilege warning(s). Consider adjusting ownership.", priv_warnings)
    else:
        LOG.info("Schema ensured (tables + merged view).")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    ensure_schema()
    print('✅ DB schema ready')
