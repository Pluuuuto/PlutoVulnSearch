from elasticsearch import Elasticsearch
es = Elasticsearch("http://localhost:9200")
mapping = {
  "mappings": {
    "properties": {
      "es_id": {
        "type": "keyword"
      },
      "affected_products": {
        "type": "text",
        "analyzer": "standard"
      },
      "version_ranges": {
        "type": "nested", 
        "properties": {
          "product_id": { "type": "keyword" },
          "min_code": { "type": "long" },
          "max_code": { "type": "long" },
          "confidence": { "type": "float" },
          "version_text": { "type": "keyword" },
          "extractor_ver": { "type": "integer" },
          "updated_at": { "type": "date" }
        }
      }
    }
  }
}
es.indices.create(index="vulnerabilities", body=mapping)
