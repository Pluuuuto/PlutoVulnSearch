import logging
from db import get_conn, ensure_schema

logger = logging.getLogger(__name__)

def connect_db():
    """返回全局连接。"""
    return get_conn()

def create_table_if_not_exists(conn):
    """兼容旧接口：内部调用 ensure_schema()。"""
    ensure_schema()

def insert_vulnerabilities(conn, vulnerabilities, source_file=None):
    """批量插入 CNVD 记录。

    同步返回成功/跳过/失败明细。"""
    success_count = 0
    skipped_logs = []
    failed_logs = []

    for vuln in vulnerabilities:
        try:
            with conn.cursor() as cur:
                # logger.debug(f"[调试] 正在插入 vuln_id={vuln['cnvd_number']}, 所有字段：{vuln}")
                cur.execute("""
                    INSERT INTO CNVD (
                        cnvd_number, title, severity, products, cveNumber, cveUrl,
                        is_event, submit_time, open_time, reference_link,
                        discoverer_name, formal_way, description,
                        patch_name, patch_description
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cnvd_number) DO NOTHING
                    RETURNING id
                """, (
                    vuln['cnvd_number'], vuln['title'], vuln['severity'],
                    ', '.join(vuln['products']),
                    vuln['cveNumber'], vuln['cveUrl'], vuln['is_Event'],
                    vuln['submit_time'], vuln['open_time'], vuln['reference_link'],
                    vuln['discoverer_name'], vuln['formal_way'], vuln['description'],
                    vuln['patch_name'], vuln['patch_description']
                ))
                
                inserted_id = cur.fetchone()
                if inserted_id:
                    success_count += 1
                else:
                    skipped_logs.append({
                        'cnvd_number': vuln.get('cnvd_number', '未知'),
                        'file': source_file or '未知文件',
                        'reason': '已存在或插入被忽略'
                    })

                conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"[插入失败] file={source_file}, cnvd_number={vuln.get('cnvd_number', '未知')}，错误：{e}")
            failed_logs.append({
                'cnvd_number': vuln.get('cnvd_number', '未知'),
                'file': source_file or '未知文件',
                'error': str(e)
            })

    return success_count, skipped_logs, failed_logs


