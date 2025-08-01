import requests
import time
import os

# 下载参数
start_id = 259
step = 1
interval = 5  # 秒
save_dir = 'data'
os.makedirs(save_dir, exist_ok=True)

# 构造请求头和 cookie（从你提供的 curl 提取）
headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en-CN;q=0.9,en;q=0.8,zh-CN;q=0.7,zh;q=0.6,ja-CN;q=0.5,ja;q=0.4',
    'priority': 'u=0, i',
    'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
    'referer': 'https://www.cnvd.org.cn/',
}

# 手动提取的 cookie 字符串
cookie_str = '__jsluid_s=f84703043c4298d7f06c05d99218849c; JSESSIONID=3709A5D7E75648E2CB171B5EAB768A67; __jsl_clearance_s=1753949880.368|0|l7B7iqU4jkaw2mrvuhEIYqOkmz4%3D'

# 转换为字典形式
cookies = {i.split('=')[0].strip(): i.split('=')[1] for i in cookie_str.split('; ')}

# 开始下载循环
current_id = start_id
while current_id > 0:
    url = f"https://www.cnvd.org.cn/shareData/download/{current_id}"
    print(f"正在下载：{url}")
    try:
        response = requests.get(url, headers=headers, cookies=cookies, timeout=30)

        if response.status_code == 200 and 'text/html' not in response.headers.get('Content-Type', ''):
            filename = os.path.join(save_dir, f"{current_id}.xml")
            with open(filename, 'wb') as f:
                f.write(response.content)
            print(f"✅ 成功保存为：{filename}")
        else:
            print(f"⚠️ 下载失败，状态码：{response.status_code}，可能是 cookie 失效")

    except Exception as e:
        print(f"❌ 错误：{e}")

    time.sleep(interval)
    current_id -= step
