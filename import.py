import psycopg2
from elasticsearch import Elasticsearch, helpers
import logging
logging.basicConfig(level=logging.DEBUG)


# PostgreSQL 配置
pg_config = {
    'host': 'localhost',
    'port': 5432,
    'database': 'vul',
    'user': 'test',
    'password': 'test'
}

# Elasticsearch 配置
es = Elasticsearch("http://localhost:9200")

# ES 索引名称
es_index = 'vuln_index'

# 创建索引及 Mapping
es_mapping = {
    "mappings": {
        "properties": {
            "doc_id": {"type": "keyword"},
            "cve_id": {"type": "keyword"},
            "cnvd_number": {"type": "keyword"},
            "title": {"type": "text"},
            "products": {"type": "text"},
            "cnvd_severity": {"type": "keyword"},
            "submit_time": {"type": "date"},
            "open_time": {"type": "date"},
            "description": {"type": "text"},
            "vuln_id": {"type": "keyword"},
            "name": {"type": "text"},
            "cnnvd_severity": {"type": "keyword"},
            "vuln_type": {"type": "keyword"},
            "published": {"type": "date"},
            "modified": {"type": "date"},
            "vuln_descript": {"type": "text"},
            "vuln_solution": {"type": "text"},
            "all_products": {"type": "text"},
            "all_description": {"type": "text"}
        }
    }
}


def create_index():
    try:
        print(f"索引名是: {repr(es_index)}")  # 查看是否有换行、空格
        if not es.indices.exists(index=es_index):
            print("索引不存在，尝试创建...")
            es.indices.create(index=es_index, body=es_mapping)
            print(f"索引 '{es_index}' 创建成功")
        else:
            print(f"索引 '{es_index}' 已存在，跳过创建")
    except Exception as e:
        import traceback
        traceback.print_exc()


# PostgreSQL 查询语句
pg_query = """
SELECT doc_id, cve_id, cnvd_number, title, products, cnvd_severity,
       submit_time, open_time, description, vuln_id, name, cnnvd_severity,
       vuln_type, published, modified, vuln_descript, vuln_solution,
       all_products, all_description
FROM merged_vulnerabilities_index
"""

def fetch_data_from_postgres():
    conn = psycopg2.connect(**pg_config)
    cursor = conn.cursor()
    cursor.execute(pg_query)
    columns = [desc[0] for desc in cursor.description]
    for row in cursor.fetchall():
        record = dict(zip(columns, row))
        # 日期字段转字符串
        for date_field in ['submit_time', 'open_time', 'published', 'modified']:
            if record.get(date_field):
                record[date_field] = record[date_field].isoformat()
        yield record
    cursor.close()
    conn.close()

def bulk_index_to_es(data_generator):
    actions = [
        {
            "_index": es_index,
            "_id": item['doc_id'],  # 使用 doc_id 作为文档 ID
            "_source": item
        }
        for item in data_generator
    ]
    helpers.bulk(es, actions)

if __name__ == '__main__':
    create_index()
    data = fetch_data_from_postgres()
    bulk_index_to_es(data)
    print("数据已成功导入 Elasticsearch")
