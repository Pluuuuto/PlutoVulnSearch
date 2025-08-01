CREATE MATERIALIZED VIEW merged_vulnerabilities AS
SELECT
    COALESCE(UPPER(cnvd.cvenumber), UPPER(cnnvd.cve_id)) AS cve_id,

    -- CNVD 表字段
    cnvd.cnvd_number,
    cnvd.title AS cnvd_title,
    cnvd.products,
    cnvd.severity AS cnvd_severity,
    cnvd.submit_time,
    cnvd.open_time,
    cnvd.description AS cnvd_description,

    -- CNNVD 表字段
    cnnvd.vuln_id,
    cnnvd.name AS cnnvd_name,
    cnnvd.severity AS cnnvd_severity,
    cnnvd.vuln_type,
    cnnvd.published,
    cnnvd.modified,
    cnnvd.vuln_descript AS cnnvd_description,
    cnnvd.vuln_solution,

    -- 合并字段
    CONCAT_WS(' || ',
        NULLIF(cnvd.products, ''),
        NULLIF(cnnvd.vuln_descript, '')
    ) AS all_products,

    CONCAT_WS(';',
        NULLIF(cnvd.description, ''),
        NULLIF(cnnvd.vuln_descript, '')
    ) AS all_description

FROM
    cnvd
FULL OUTER JOIN
    cnnvd
ON
    UPPER(cnvd.cvenumber) = UPPER(cnnvd.cve_id);


REFRESH MATERIALIZED VIEW merged_vulnerabilities;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- 建在 cnnvd.name 上
CREATE INDEX idx_cnnvd_name_trgm ON cnnvd USING gin (name gin_trgm_ops);

-- 建在 cnnvd.vuln_descript 上
CREATE INDEX idx_cnnvd_desc_trgm ON cnnvd USING gin (vuln_descript gin_trgm_ops);

-- 如果你搜索 CNVD.products，也可以建
CREATE INDEX idx_cnvd_products_trgm ON cnvd USING gin (products gin_trgm_ops);
