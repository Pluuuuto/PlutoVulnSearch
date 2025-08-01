import psycopg2
import configparser

def connect_db(config_file='db_config.ini'):
    config = configparser.ConfigParser()
    config.read(config_file)
    return psycopg2.connect(**config['postgresql'])

def search_by_keyword(keyword, limit=20):
    conn = connect_db()
    with conn.cursor() as cur:
        # 处理关键词：按空格拆分，构造 AND 条件
        keywords = keyword.strip().split()
        conditions = " AND ".join(["all_products ILIKE %s" for _ in keywords])

        sql = f"""
            SELECT
                cve_id,
                COALESCE(cnvd_number, '-') AS cnvd_number,
                COALESCE(cnnvd_name, '-') AS cnnvd_name,
                COALESCE(cnvd_title, '-') AS cnvd_title,
                COALESCE(products, '-') AS products,
                COALESCE(cnnvd_description, cnvd_description, '-') AS description
            FROM merged_vulnerabilities
            WHERE {conditions}
            ORDER BY cve_id NULLS LAST
            LIMIT %s;
        """

        # 构造参数列表
        params = [f"%{k}%" for k in keywords] + [limit]

        cur.execute(sql, params)
        rows = cur.fetchall()

        print(f"\n🔍 搜索关键词：{' + '.join(keywords)}")
        print(f"共匹配到 {len(rows)} 条记录：\n")

        for idx, row in enumerate(rows, start=1):
            cve, cnvd, name, title, prod, desc = row
            print(f"{idx}. CVE: {cve or 'N/A'} | CNVD: {cnvd}")
            print(f"   标题: {title or name}")
            print(f"   产品: {prod}")
            clean_desc = (desc or '').replace('\n', ' ').replace('\r', ' ')
            print(f"   描述: {clean_desc[:100]}...\n")

    conn.close()


# 示例调用
if __name__ == '__main__':
    search_by_keyword("Drupal")

