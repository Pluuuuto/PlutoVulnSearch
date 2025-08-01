import psycopg2
import configparser
import logging

logger = logging.getLogger(__name__)

def connect_db(config_file='config/db_config.ini'):
    config = configparser.ConfigParser()
    config.read(config_file)
    db_params = config['postgresql']
    conn = psycopg2.connect(**db_params)
    return conn

def create_table_if_not_exists(conn):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS CNNVD (
                id SERIAL PRIMARY KEY,
                name TEXT,
                vuln_id TEXT UNIQUE,  -- ✅ 设置唯一键，支持 ON CONFLICT
                published DATE,
                modified DATE,
                source TEXT,
                severity TEXT,
                vuln_type TEXT,
                vuln_descript TEXT,
                cve_id TEXT,
                bugtraq_id TEXT,
                vuln_solution TEXT
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
                    INSERT INTO CNNVD (
                        name, vuln_id, published, modified, source, severity,
                        vuln_type, vuln_descript, cve_id, bugtraq_id, vuln_solution
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (vuln_id) DO NOTHING
                    RETURNING id
                """, (
                    vuln['name'], vuln['vuln_id'], vuln['published'], vuln['modified'],
                    vuln['source'], vuln['severity'], vuln['vuln_type'], vuln['vuln_descript'],
                    vuln['cve_id'], vuln['bugtraq_id'], vuln['vuln_solution']
                ))

                inserted_id = cur.fetchone()
                if inserted_id:
                    success_count += 1
                else:
                    skipped_logs.append({
                        'vuln_id': vuln.get('vuln_id', '未知'),
                        'file': source_file or '未知文件',
                        'reason': '已存在，跳过插入'
                    })

                conn.commit()

        except Exception as e:
            conn.rollback()
            logger.error(f"[插入失败] file={source_file}, vuln_id={vuln.get('vuln_id', '未知')}，错误：{e}")
            failed_logs.append({
                'vuln_id': vuln.get('vuln_id', '未知'),
                'file': source_file or '未知文件',
                'error': str(e)
            })

    return success_count, skipped_logs, failed_logs
