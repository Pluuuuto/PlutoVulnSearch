"""CVE data ingestion script (renamed from main.py)."""
import os, sys, pathlib, logging
from parser import parse_vulnerabilities
from db_handler import connect_db, insert_vulnerabilities, create_table_if_not_exists
from db import ensure_schema

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.makedirs('log', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('log/import.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def run():
    # 数据目录位于当前模块同级: CVE/data
    data_dir = pathlib.Path(__file__).resolve().parent / 'data'
    if not data_dir.is_dir():
        logger.warning("数据目录不存在: %s (跳过 CVE 导入)", data_dir)
        return {"inserted": 0, "skipped": 0, "failed": 0}
    json_files = []
    for root, _, files in os.walk(str(data_dir)):
        for file in files:
            if file.lower().endswith('.json'):
                json_files.append(os.path.join(root, file))
    json_files.sort()

    all_success = 0
    all_failed_logs = []
    all_skipped_logs = []

    ensure_schema()
    conn = connect_db()

    for json_file in json_files:
        logger.info(f"解析文件: {json_file}")
        vulns = parse_vulnerabilities(json_file)
        logger.info(f"  → 解析 {len(vulns)} 条")
        success_count, skipped_logs, failed_logs = insert_vulnerabilities(conn, vulns, source_file=json_file)
        all_success += success_count
        all_skipped_logs.extend(skipped_logs)
        all_failed_logs.extend(failed_logs)
        logger.info(f"  → 成功 {success_count} 跳过 {len(skipped_logs)} 失败 {len(failed_logs)}")

    conn.close()
    logger.info(f"✅ CVE 导入完成，总计 {all_success}")

    if all_skipped_logs:
        with open('log/import_skipped.log', 'w', encoding='utf-8') as f:
            for log in all_skipped_logs:
                f.write(f"[{log['file']}] cve_id={log['cve_id']} 原因:{log['reason']}\n")
    if all_failed_logs:
        with open('log/import_errors.log', 'w', encoding='utf-8') as f:
            for log in all_failed_logs:
                f.write(f"[{log['file']}] cve_id={log['cve_id']} 错误:{log['error']}\n")
    return {"inserted": all_success, "skipped": len(all_skipped_logs), "failed": len(all_failed_logs)}

if __name__ == '__main__':
    run()
