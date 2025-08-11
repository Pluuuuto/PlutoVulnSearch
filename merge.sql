CREATE OR REPLACE VIEW merged_vulnerabilities_view AS

-- 第一部分：以 CVE 为主
SELECT DISTINCT ON (
    COALESCE(
        UPPER(cve.cve_id),
        UPPER(cnvd.cnvd_number),
        UPPER(cnnvd.vuln_id)
    )
)
    COALESCE(
        UPPER(cve.cve_id),
        UPPER(cnvd.cnvd_number),
        UPPER(cnnvd.vuln_id),
        md5(COALESCE(cve.vuln_description, '') || COALESCE(cnvd.description, '') || COALESCE(cnnvd.vuln_descript, ''))
    ) AS es_id,
    UPPER(cve.cve_id) AS cve_id,
    cnvd.cnvd_number,
    cnnvd.vuln_id AS cnnvd_number,
    CONCAT_WS('; ',
        NULLIF(cve.vuln_description, ''),
        NULLIF(cnvd.description, ''),
        NULLIF(cnnvd.vuln_descript, '')
    ) AS description,
    CONCAT_WS(' || ',
        NULLIF(cve.affected_products, ''),
        NULLIF(cnvd.products, ''),
        NULLIF(cnnvd.products, '')
    ) AS affected_products,
    CONCAT_WS(' || ',
        NULLIF(cve.solution, ''),
        NULLIF(cnvd.patch_description, ''),
        NULLIF(cnnvd.vuln_solution, '')
    ) AS solution,
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
