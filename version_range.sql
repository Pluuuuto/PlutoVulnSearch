-- 版本区间表：一条漏洞可有多产品、多区间
CREATE TABLE IF NOT EXISTS vuln_version_range (
  es_id          TEXT        NOT NULL,      -- 关联 merged_vulnerabilities_view.es_id
  product_id     TEXT        NOT NULL,      -- 规范化产品名(小写)
  min_code       BIGINT         NOT NULL,      -- 版本编码：a*1e6 + b*1e3 + c
  max_code       BIGINT         NOT NULL,
  confidence     REAL        NULL,          -- 0~1
  version_text   TEXT        NULL,          -- 可读展示 "8.0.0-8.6.0; 9.0.0-9.0.10"
  source_text    TEXT        NULL,          -- 原始 products 片段(建议写 merged_vulnerabilities_view.affected_products)
  raw_hash       TEXT        NOT NULL,      -- 对 source_text 的 MD5，用于变更检测
  extractor_ver  INT         NOT NULL,      -- 抽取器版本，升级规则时可重算
  updated_at     TIMESTAMP   NOT NULL DEFAULT now(),
  PRIMARY KEY (es_id, product_id, min_code, max_code)
);

-- 查询与关联索引
CREATE INDEX IF NOT EXISTS idx_vr_esid   ON vuln_version_range(es_id);
CREATE INDEX IF NOT EXISTS idx_vr_prod   ON vuln_version_range(product_id);
CREATE INDEX IF NOT EXISTS idx_vr_range  ON vuln_version_range(min_code, max_code);


CREATE OR REPLACE VIEW merged_vulnerabilities_export AS
SELECT
  m.*,
  a.version_std_text,
  a.ranges_json
FROM merged_vulnerabilities_view m
LEFT JOIN LATERAL (
  SELECT
    COALESCE(STRING_AGG(DISTINCT r.version_text, '; ' ORDER BY r.version_text), '') AS version_std_text,
    JSONB_AGG(
      JSONB_BUILD_OBJECT(
        'product_id', r.product_id,
        'min_code',   r.min_code,
        'max_code',   r.max_code,
        'confidence', r.confidence
      )
      ORDER BY r.product_id, r.min_code
    ) FILTER (WHERE r.es_id IS NOT NULL) AS ranges_json
  FROM vuln_version_range r
  WHERE r.es_id = m.es_id
) a ON TRUE;

