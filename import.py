from elasticsearch import Elasticsearch, helpers
import psycopg2
import psycopg2.extras as pg_extras
import os

PG_DSN = os.getenv("PG_DSN", "host=localhost port=5432 dbname=vul user=test password=test")
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX = "vulnerabilities"

def sync_to_es(full_import=True, last_sync_time=None):
    es = Elasticsearch(ES_HOST)
    conn = psycopg2.connect(PG_DSN)
    cur = conn.cursor(cursor_factory=pg_extras.RealDictCursor)

    if full_import:
        cur.execute("""
            SELECT mv.es_id, mv.affected_products,
                   vvr.product_id, vvr.min_code, vvr.max_code,
                   vvr.confidence, vvr.version_text, vvr.extractor_ver, vvr.updated_at
            FROM merged_vulnerabilities_view mv
            LEFT JOIN vuln_version_range vvr ON mv.es_id = vvr.es_id
        """)
    else:
        cur.execute("""
            SELECT mv.es_id, mv.affected_products,
                   vvr.product_id, vvr.min_code, vvr.max_code,
                   vvr.confidence, vvr.version_text, vvr.extractor_ver, vvr.updated_at
            FROM merged_vulnerabilities_view mv
            LEFT JOIN vuln_version_range vvr ON mv.es_id = vvr.es_id
            WHERE mv.updated_at > %s OR vvr.updated_at > %s
        """, (last_sync_time, last_sync_time))

    data_map = {}
    for row in cur:
        es_id = row["es_id"]
        if es_id not in data_map:
            data_map[es_id] = {
                "es_id": es_id,
                "affected_products": row["affected_products"],
                "version_ranges": []
            }
        if row["product_id"]:
            data_map[es_id]["version_ranges"].append({
                "product_id": row["product_id"],
                "min_code": row["min_code"],
                "max_code": row["max_code"],
                "confidence": row["confidence"],
                "version_text": row["version_text"],
                "extractor_ver": row["extractor_ver"],
                "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None
            })

    actions = []
    for doc in data_map.values():
        actions.append({
            "_index": ES_INDEX,
            "_id": doc["es_id"],
            "_source": doc
        })

    if actions:
        helpers.bulk(es, actions)
        print(f"已同步 {len(actions)} 条记录到 ES 索引 {ES_INDEX}")
    else:
        print("没有需要同步的数据")

    cur.close()
    conn.close()

if __name__ == "__main__":
    # 全量导入
    sync_to_es(full_import=True)
    # 增量导入示例：
    # sync_to_es(full_import=False, last_sync_time="2025-08-01 00:00:00")
