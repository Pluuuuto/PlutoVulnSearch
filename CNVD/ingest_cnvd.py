"""CNVD data ingestion script (renamed from main.py)."""
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
    # 数据目录位于当前模块同级: CNVD/data
    data_dir = pathlib.Path(__file__).resolve().parent / 'test'
    if not data_dir.is_dir():
        logger.warning("数据目录不存在: %s (跳过 CNVD 导入)", data_dir)
        return {"inserted": 0, "skipped": 0, "failed": 0}
    xml_files = [f for f in os.listdir(str(data_dir)) if f.lower().endswith('.xml')]
    xml_files.sort()

    all_success = 0
    all_failed_logs = []
    all_skipped_logs = []

    ensure_schema()
    conn = connect_db()

    for xml_file in xml_files:
        xml_path = os.path.join(str(data_dir), xml_file)
        logger.info(f"解析文件: {xml_file}")
        vulns = parse_vulnerabilities(xml_path)
        logger.info(f"  → 解析 {len(vulns)} 条")
        success_count, skipped_logs, failed_logs = insert_vulnerabilities(conn, vulns, source_file=xml_file)
        all_success += success_count
        all_skipped_logs.extend(skipped_logs)
        all_failed_logs.extend(failed_logs)
        logger.info(f"  → 成功 {success_count} 跳过 {len(skipped_logs)} 失败 {len(failed_logs)}")

    conn.close()
    logger.info(f"✅ CNVD 导入完成，总计 {all_success}")

    if all_skipped_logs:
        with open('log/import_skipped.log', 'w', encoding='utf-8') as f:
            for log in all_skipped_logs:
                f.write(f"[{log['file']}] cnvd_number={log['cnvd_number']} 原因:{log['reason']}\n")
    if all_failed_logs:
        with open('log/import_errors.log', 'w', encoding='utf-8') as f:
            for log in all_failed_logs:
                f.write(f"[{log['file']}] cnvd_number={log['cnvd_number']} 错误:{log['error']}\n")
    return {"inserted": all_success, "skipped": len(all_skipped_logs), "failed": len(all_failed_logs)}

if __name__ == '__main__':
    run()
