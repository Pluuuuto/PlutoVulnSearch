import os
import logging
from parser import parse_vulnerabilities
from db_handler import connect_db, insert_vulnerabilities, create_table_if_not_exists

# 日志配置
os.makedirs('log', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,   # 可改为 DEBUG 查看详细调试信息
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("log/import.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def main():
    data_dir = 'data'
    xml_files = [f for f in os.listdir(data_dir) if f.lower().endswith('.xml')]
    xml_files.sort()

    all_success = 0
    all_failed_logs = []
    all_skipped_logs = []

    conn = connect_db()
    create_table_if_not_exists(conn)

    for xml_file in xml_files:
        xml_path = os.path.join(data_dir, xml_file)
        logger.info(f"正在解析文件：{xml_file}")
        vulns = parse_vulnerabilities(xml_path)
        logger.info(f"  → 解析出 {len(vulns)} 条漏洞信息。")

        success_count, skipped_logs, failed_logs = insert_vulnerabilities(conn, vulns, source_file=xml_file)
        all_success += success_count
        all_skipped_logs.extend(skipped_logs)
        all_failed_logs.extend(failed_logs)

        logger.info(f"  → 成功导入 {success_count} 条，已存在跳过 {len(skipped_logs)} 条，失败 {len(failed_logs)} 条。")

    conn.close()

    logger.info(f"\n✅ 共成功导入 {all_success} 条漏洞信息。")

    if all_skipped_logs:
        logger.warning(f"⚠️ 有 {len(all_skipped_logs)} 条数据因已存在被跳过，详情见 import_skipped.log")
        with open('log/import_skipped.log', 'w', encoding='utf-8') as f:
            for log in all_skipped_logs:
                f.write(f"[{log['file']}] cnvd_number={log['cnvd_number']}，原因: {log['reason']}\n")

    if all_failed_logs:
        logger.error(f"❌ 有 {len(all_failed_logs)} 条数据导入失败，详情见 import_errors.log")
        with open('log/import_errors.log', 'w', encoding='utf-8') as f:
            for log in all_failed_logs:
                f.write(f"[{log['file']}] cnvd_number={log['cnvd_number']}，错误原因: {log['error']}\n")

if __name__ == '__main__':
    main()
