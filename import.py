import psycopg2
from elasticsearch import Elasticsearch, helpers
import logging
import traceback

# 日志设置
logging.basicConfig(level=logging.INFO)

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

# ES 映射配置（根据你的视图字段调整）
es_mapping = {
    "mappings": {
        "properties": {
            "es_id": {"type": "keyword"},  # 用作 ES _id
            "cve_id": {"type": "keyword"},
            "cnvd_number": {"type": "keyword"},
            "cnnvd_number": {"type": "keyword"},
            "description": {"type": "text"},
            "affected_products": {"type": "text"},
            "solution": {"type": "text"},
            "risk_display": {"type": "keyword"},
            "risk_level": {"type": "integer"}
        }
    }
}


def create_index():
    """创建 Elasticsearch 索引（如不存在）"""
    try:
        if es.indices.exists(index=es_index):
            logging.info(f"索引 '{es_index}' 已存在，跳过创建")
        else:
            es.indices.create(index=es_index, body=es_mapping)
            logging.info(f"索引 '{es_index}' 创建成功")
    except Exception:
        logging.error("创建索引时出错")
        traceback.print_exc()


# 查询视图的 SQL
pg_query = """
SELECT 
    es_id,
    cve_id,
    cnvd_number,
    cnnvd_number,
    description,
    affected_products,
    solution,
    risk_display,
    risk_level
FROM merged_vulnerabilities_view
"""


def fetch_data_from_postgres():
    """从 PostgreSQL 视图中读取数据"""
    try:
        conn = psycopg2.connect(**pg_config)
        cursor = conn.cursor()
        cursor.execute(pg_query)
        columns = [desc[0] for desc in cursor.description]

        count = 0
        for row in cursor.fetchall():
            count += 1
            if count % 1000 == 0:
                logging.info(f"已读取 {count} 条记录")
            record = dict(zip(columns, row))
            yield record

        logging.info(f"总共读取 {count} 条记录")
        cursor.close()
        conn.close()

    except Exception:
        logging.error("从 PostgreSQL 获取数据失败")
        traceback.print_exc()



def bulk_index_to_es(data_generator):
    try:
        actions = []
        count = 0

        for item in data_generator:
            count += 1
            actions.append({
                "_index": es_index,
                "_id": item['es_id'],
                "_source": item
            })

            # 每 1000 条提交一次批量写入
            if len(actions) == 1000:
                helpers.bulk(es, actions)
                logging.info(f"已导入 {count} 条数据")
                actions = []

        # 剩余不足 1000 的部分也写入
        if actions:
            helpers.bulk(es, actions)
            logging.info(f"已导入 {count} 条数据（最终批次）")

    except Exception:
        logging.error("导入 Elasticsearch 失败")
        traceback.print_exc()



if __name__ == '__main__':
    create_index()
    data = fetch_data_from_postgres()
    bulk_index_to_es(data)
