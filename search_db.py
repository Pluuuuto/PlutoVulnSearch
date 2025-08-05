import re
from db import connect_db

def search_by_keyword(keyword, limit=20):
    conn = connect_db()
    with conn.cursor() as cur:
        keywords = keyword.strip().split()
        conditions = []
        params = []

        for kw in keywords:
            if re.match(r'^CVE-\d{4}-\d+$', kw, re.IGNORECASE):
                conditions.append("cve_id ILIKE %s")
                params.append(f"%{kw}%")
            else:
                conditions.append("all_products ILIKE %s")
                params.append(f"%{kw}%")

        where_clause = " AND ".join(conditions)

        sql = f"""
            SELECT
                cve_id,
                COALESCE(cnvd_number, '-') AS cnvd_number,
                COALESCE(cnnvd_name, '-') AS cnnvd_name,
                COALESCE(cnvd_title, '-') AS cnvd_title,
                COALESCE(products, '-') AS products,
                COALESCE(cnnvd_description, cnvd_description, '-') AS description
            FROM merged_vulnerabilities
            WHERE {where_clause}
            ORDER BY cve_id NULLS LAST
            LIMIT %s;
        """

        params.append(limit)
        cur.execute(sql, params)
        rows = cur.fetchall()

    conn.close()

    result = []
    for row in rows:
        cve, cnvd, name, title, prod, desc = row
        result.append({
            "cve_id": cve or "N/A",
            "cnvd_number": cnvd,
            "title": title or name,
            "products": prod,
            "description": desc or ""
        })
    return result

# 示例调用
if __name__ == '__main__':
    search_by_keyword("Drupal 4 CVE-2007-3689")

