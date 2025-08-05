from elasticsearch import Elasticsearch

# 初始化 ES 客户端
es = Elasticsearch("http://localhost:9200")

def search_vulns(query_string, index_name="vuln_index", size=10):
    """
    根据关键词查询漏洞信息（软件名、版本号、CVE编号等）

    :param query_string: 查询关键词，如 "Apache 2.4.57 CVE-2023-1234"
    :param index_name: 索引名称，默认 vuln_index
    :param size: 返回结果条数，默认10条
    :return: 查询结果列表，每项是 dict
    """
    query_body = {
        "query": {
            "multi_match": {
                "query": query_string,
                "fields": [
                    "title^3",
                    "products^2",
                    "all_products",
                    "description",
                    "all_description",
                    "cve_id"
                ],
                "operator": "or"
            }
        }
    }

    # 执行查询
    try:
        response = es.search(index=index_name, body=query_body, size=size)
        hits = response['hits']['hits']
        results = []

        for hit in hits:
            results.append({
                "id": hit["_id"],
                "score": hit["_score"],
                "title": hit["_source"].get("title"),
                "cve_id": hit["_source"].get("cve_id"),
                "products": hit["_source"].get("products"),
                "description": hit["_source"].get("description"),
            })

        return results

    except Exception as e:
        print("查询出错：", e)
        return []
