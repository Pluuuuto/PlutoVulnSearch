import psycopg2
import configparser
import logging

logger = logging.getLogger(__name__)

def connect_db(config_file='../db_config.ini'):
    config = configparser.ConfigParser()
    config.read(config_file)

    db_params = config['postgresql']
    conn = psycopg2.connect(**db_params)
    return conn

def create_table_if_not_exists(conn):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS CVE (
                id SERIAL PRIMARY KEY,
                cve_id TEXT UNIQUE,
                published_date DATE,
                affected_products TEXT,
                solution TEXT,
                cvss_score NUMERIC(3,1),
                vuln_description TEXT
            );
        """)
        conn.commit()

def insert_vulnerabilities(conn, vulnerabilities, source_file=None):
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


