import psycopg2
import psycopg2.extras as pg_extras
from elasticsearch import Elasticsearch, helpers
import json
import logging
import traceback
import os

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

PG_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'vul',
    'user': 'test',
    'password': 'test'
}

ES_URL = os.getenv("ES_URL", "http://localhost:9200")
ES_INDEX = 'vuln_index'

# 映射：包含 ranges(nested) + version_std_text
ES_MAPPING = {
    "mappings": {
        "properties": {
            "es_id": {"type": "keyword"},
            "cve_id": {"type": "keyword"},
            "cnvd_number": {"type": "keyword"},
            "cnnvd_number": {"type": "keyword"},
            "description": {"type": "text"},
            "affected_products": {"type": "text"},
            "solution": {"type": "text"},
            "risk_display": {"type": "keyword"},
            "risk_level": {"type": "integer"},
            "version_std_text": {"type": "keyword"},
            "ranges": {
                "type": "nested",
                "properties": {
                    "product_id": {"type": "keyword"},
                    "min_code":   {"type": "integer"},
                    "max_code":   {"type": "integer"},
                    "confidence": {"type": "float"}
                }
            }
        }
    }
}

# 用“导出视图”
PG_QUERY = """
SELECT 
    es_id,
    cve_id,
    cnvd_number,
    cnnvd_number,
    description,
    affected_products,
    solution,
    risk_display,
    risk_level,
    version_std_text,
    ranges_json
FROM merged_vulnerabilities_export
"""

def create_index(es: Elasticsearch):
    """创建索引（不存在时）"""
    try:
        if es.indices.exists(index=ES_INDEX):
            logging.info(f"索引 '{ES_INDEX}' 已存在")
            return
        es.indices.create(index=ES_INDEX, body=ES_MAPPING)
        logging.info(f"索引 '{ES_INDEX}' 创建成功")
    except Exception:
        logging.error("创建索引时出错")
        traceback.print_exc()
        raise

def fetch_rows():
    """从 Postgres 流式读取（server-side cursor，避免 fetchall 占内存）"""
    conn = psycopg2.connect(**PG_CONFIG)
    # server-side cursor：name 不为 None 即可；RealDictCursor 返回 dict
    cur = conn.cursor(name="vuln_export_cursor", cursor_factory=pg_extras.RealDictCursor)
    cur.itersize = 1000  # 每批返回行数
    cur.execute(PG_QUERY)
    count = 0
    try:
        for row in cur:
            count += 1
            if count % 5000 == 0:
                logging.info(f"已读取 {count} 条")
            yield dict(row)
    finally:
        cur.close()
        conn.close()
        logging.info(f"总计读取 {count} 条")

def transform(row: dict) -> dict:
    """把视图行转为 ES 文档（含 nested ranges）"""
    doc = {k: row.get(k) for k in [
        "es_id","cve_id","cnvd_number","cnnvd_number","description",
        "affected_products","solution","risk_display","risk_level",
        "version_std_text"
    ]}
    # ranges_json -> ranges（确保是 list[dict]）
    rj = row.get("ranges_json")
    if rj is None:
        doc["ranges"] = []
    elif isinstance(rj, (list, tuple)):
        doc["ranges"] = list(rj)
    else:
        # 可能从 psycopg2 读出来是 str
        try:
            doc["ranges"] = json.loads(rj)
        except Exception:
            logging.warning("ranges_json 解析失败，置空；es_id=%s", row.get("es_id"))
            doc["ranges"] = []
    return doc

def bulk_index(es: Elasticsearch, gen, chunk_size=1000):
    """批量写 ES（带简单容错）"""
    actions = []
    total = 0
    for row in gen:
        doc = transform(row)
        es_id = doc.get("es_id")
        if not es_id:
            continue
        actions.append({
            "_index": ES_INDEX,
            "_id": es_id,
            "_source": doc
        })
        if len(actions) >= chunk_size:
            helpers.bulk(es, actions, raise_on_error=False)
            total += len(actions)
            logging.info("已导入 %d 条", total)
            actions.clear()
    if actions:
        helpers.bulk(es, actions, raise_on_error=False)
        total += len(actions)
        logging.info("已导入 %d 条（最终批次）", total)

def main():
    es = Elasticsearch(ES_URL)
    create_index(es)
    bulk_index(es, fetch_rows(), chunk_size=1000)

if __name__ == "__main__":
    main()
