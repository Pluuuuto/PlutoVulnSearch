import logging
from db import get_conn, ensure_schema  # unified schema / connection

logger = logging.getLogger(__name__)

def connect_db():  # backward compatible name
    """返回全局连接（兼容旧调用）。"""
    return get_conn()

def create_table_if_not_exists(conn):  # kept for compatibility, now delegates
    """兼容旧接口：内部调用 ensure_schema()。"""
    ensure_schema()

def insert_vulnerabilities(conn, vulnerabilities, source_file=None):
    """批量插入 CVE 记录（逐条执行）。

    返回: (success_count, skipped_logs, failed_logs)
    说明:
      - ON CONFLICT DO NOTHING 保障幂等。
      - 每条提交（可后续优化批量事务）。"""
    success_count = 0
    skipped_logs = []
    failed_logs = []

    for vuln in vulnerabilities:
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO CVE (
                        cve_id, published_date, affected_products, solution, cvss_score, vuln_description
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id) DO NOTHING
                    RETURNING id
                """, (
                    vuln['cve_id'],
                    vuln['published_date'],
                    vuln['affected_products'],
                    vuln['solution'],
                    vuln['cvss_score'],
                    vuln['vuln_description']
                ))

                inserted_id = cur.fetchone()
                if inserted_id:
                    success_count += 1
                else:
                    skipped_logs.append({
                        'cve_id': vuln.get('cve_id', '未知'),
                        'file': source_file or '未知文件',
                        'reason': '已存在或插入被忽略'
                    })

                conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"[插入失败] file={source_file}, cve_id={vuln.get('cve_id', '未知')}，错误：{e}")
            failed_logs.append({
                'cve_id': vuln.get('cve_id', '未知'),
                'file': source_file or '未知文件',
                'error': str(e)
            })

    return success_count, skipped_logs, failed_logs


