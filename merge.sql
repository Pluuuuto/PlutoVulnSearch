-- (Deprecated) 视图定义已集中到 db.py 的 MERGED_VIEW_SQL 常量；此文件仅为历史遗留，可删除。
-- 保留空内容避免误用旧版本。
-- 若需查看当前视图，请打开 db.py。
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
LEFT JOIN cnvd
    ON UPPER(cve.cve_id) = UPPER(cnvd.cvenumber)
LEFT JOIN cnnvd
    ON UPPER(cve.cve_id) = UPPER(cnnvd.cve_id)


UNION

-- 第二部分：CNVD 独立记录（无对应 CVE）
SELECT DISTINCT ON (
    COALESCE(
        UPPER(cnvd.cnvd_number),
        UPPER(cnnvd.vuln_id)
    )
)
    COALESCE(
        UPPER(cnvd.cnvd_number),
        UPPER(cnnvd.vuln_id),
        md5(COALESCE(cnvd.description, '') || COALESCE(cnnvd.vuln_descript, ''))
    ) AS es_id,
    NULL AS cve_id,
    cnvd.cnvd_number,
    cnnvd.vuln_id AS cnnvd_number,
    CONCAT_WS('; ',
        NULLIF(cnvd.description, ''),
        NULLIF(cnnvd.vuln_descript, '')
    ) AS description,
    CONCAT_WS(' || ',
        NULLIF(cnvd.products, ''),
        NULLIF(cnnvd.products, '')
    ) AS affected_products,
    CONCAT_WS(' || ',
        NULLIF(cnvd.patch_description, ''),
        NULLIF(cnnvd.vuln_solution, '')
    ) AS solution,
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
LEFT JOIN cnnvd
    ON UPPER(cnvd.cvenumber) = UPPER(cnnvd.cve_id)
WHERE NOT EXISTS (
    SELECT 1 FROM cve WHERE UPPER(cve.cve_id) = UPPER(cnvd.cvenumber)
);
