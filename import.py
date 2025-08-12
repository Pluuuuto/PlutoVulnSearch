"""(Deprecated) 早期用于手动同步 PostgreSQL → Elasticsearch。

功能已被 pipeline_daily.py 中的 ensure_index + bulk_upsert_es 取代。
保留文件仅为兼容历史文档引用，可安全删除。
"""

if __name__ == "__main__":
    print("import.py 已弃用：请使用 pipeline_daily.py 运行全流程同步。")
