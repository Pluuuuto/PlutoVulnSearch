from __future__ import annotations
import os
from elasticsearch import Elasticsearch

ES_HOST = os.getenv('ES_HOST', 'http://localhost:9200')
ES_INDEX = os.getenv('ES_INDEX', 'vulnerabilities')

def search_by_keyword(q: str, limit: int = 20):
    """关键词搜索（ES multi_match）。

    参数：
      q      查询串
      limit  最大返回条数
    返回：文档 _source 数组；索引不存在或错误返回空列表。"""
    es = Elasticsearch(ES_HOST)
    try:
        if not es.indices.exists(index=ES_INDEX):  # type: ignore
            return []
    except Exception:
        return []
    query = {
        'size': limit,
        'query': {
            'multi_match': {
                'query': q,
                'fields': ['es_id^2', 'affected_products', 'version_ranges.version_text']
            }
        }
    }
    res = es.search(index=ES_INDEX, body=query)
    return [h['_source'] for h in res.get('hits', {}).get('hits', [])]
