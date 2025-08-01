import requests
import os
import logging
from bs4 import BeautifulSoup

# ==== 参数配置 ====
html_path = 'source.html'                   # 本地 HTML 文件
save_dir = 'data'                           # 下载目录
name_log_file = 'data/xml_file_names.txt'        # 文件名记录
log_file = 'log/download.log'                   # 日志输出

os.makedirs(save_dir, exist_ok=True)

# ==== 配置日志 ====
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    filemode='a',
    encoding='utf-8'
)
log = logging.getLogger()

# ==== 请求头和 Cookie ====
headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'accept-language': 'en-US,en;q=0.9',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
    'referer': 'https://www.cnvd.org.cn/',
}
cookie_str = '__jsluid_s=f84703043c4298d7f06c05d99218849c; JSESSIONID=3709A5D7E75648E2CB171B5EAB768A67; __jsl_clearance_s=1753953587.05|0|vSHUSdjeGD2XntR%2F1iKa4JEGYWU%3D'
cookies = {i.split('=', 1)[0].strip(): i.split('=', 1)[1] for i in cookie_str.split('; ')}

# ==== 加载已有文件名记录 ====
existing_names = set()
if os.path.exists(name_log_file):
    with open(name_log_file, 'r', encoding='utf-8') as f:
        existing_names = set(line.strip() for line in f if line.strip())

# ==== 读取 HTML ====
try:
    with open(html_path, 'r', encoding='utf-8') as f:
        html = f.read()
except Exception as e:
    log.error(f"❌ 无法读取 HTML 文件：{e}")
    exit(1)

# ==== 解析 HTML 中的 XML 链接 ====
soup = BeautifulSoup(html, 'html.parser')
xml_links = []

for a in soup.find_all('a', href=True):
    href = a['href']
    if href.startswith('/shareData/download/') and a.text.strip().endswith('.xml'):
        download_id = href.split('/')[-1]
        file_name = a.text.strip()
        xml_links.append((download_id, file_name))

log.info(f"共解析到 {len(xml_links)} 个 XML 文件")

# ==== 下载新增文件 ====
try:
    with open(name_log_file, 'a', encoding='utf-8') as name_log:
        for download_id, file_name in xml_links:
            if file_name in existing_names:
                log.info(f"⏭️ 已存在，跳过：{file_name}")
                continue

            url = f"https://www.cnvd.org.cn/shareData/download/{download_id}"
            log.info(f"⬇️ 准备下载：{url}")

            try:
                res = requests.get(url, headers=headers, cookies=cookies, timeout=30)
                if res.status_code == 200 and 'text/html' not in res.headers.get('Content-Type', ''):
                    path = os.path.join(save_dir, file_name)
                    with open(path, 'wb') as f:
                        f.write(res.content)
                    name_log.write(file_name + '\n')
                    name_log.flush()
                    log.info(f"✅ 下载成功：{file_name}")
                else:
                    log.warning(f"⚠️ 下载失败（状态码 {res.status_code}）：{file_name}")
            except Exception as e:
                log.error(f"❌ 请求出错：{file_name} - {e}")
except Exception as e:
    log.error(f"❌ 文件名记录写入失败：{e}")
