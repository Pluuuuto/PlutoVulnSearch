TRUNCATE TABLE merged_vulnerabilities_index;

INSERT INTO merged_vulnerabilities_index (
    doc_id,
    cve_id,
    cnvd_number,
    title,
    products,
    cnvd_severity,
    submit_time,
    open_time,
    description,
    vuln_id,
    name,
    cnnvd_severity,
    vuln_type,
    published,
    modified,
    vuln_descript,
    vuln_solution,
    all_products,
    all_description
)
SELECT DISTINCT ON (doc_id)
    CASE
        WHEN cnvd.cvenumber IS NOT NULL AND cnnvd.cve_id IS NOT NULL THEN 'BOTH_' || cnvd.cvenumber
        WHEN cnvd.cvenumber IS NOT NULL THEN 'CNVD_' || cnvd.cvenumber
        WHEN cnnvd.cve_id IS NOT NULL THEN 'CNNVD_' || cnnvd.cve_id
        ELSE 'ID_' || COALESCE(cnvd.cnvd_number, cnnvd.vuln_id)
    END AS doc_id,

    COALESCE(UPPER(cnvd.cvenumber), UPPER(cnnvd.cve_id)) AS cve_id,
    cnvd.cnvd_number,
    cnvd.title,
    cnvd.products,
    cnvd.severity AS cnvd_severity,
    cnvd.submit_time,
    cnvd.open_time,
    cnvd.description,
    cnnvd.vuln_id,
    cnnvd.name,
    cnnvd.severity AS cnnvd_severity,
    cnnvd.vuln_type,
    cnnvd.published,
    cnnvd.modified,
    cnnvd.vuln_descript,
    cnnvd.vuln_solution,

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
FULL OUTER JOIN cnnvd ON UPPER(cnvd.cvenumber) = UPPER(cnnvd.cve_id)

ORDER BY doc_id, cnnvd.published DESC NULLS LAST;