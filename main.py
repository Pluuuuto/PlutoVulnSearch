"""本地辅助脚本：

两种模式：
	1) 指定 --file ：对该单个文件做【增量】上传（走 FastAPI /upload，快速更新）。
	2) 不指定 --file ：直接在本地执行 pipeline_daily 全量流程（扫描各源 data 目录、采集+多轮 LLM + 全量 ES）。

示例：
	增量: python main.py --file CVE/data/2025-08-14.json --src cve
	全量: python main.py
"""

import argparse, os, sys, requests

DEFAULT_URL = os.environ.get("API_BASE", "http://127.0.0.1:8000")

def upload(file_path: str, src: str, run_llm: bool = True, sync_es: bool = True, mode: str = "incremental"):
	url = f"{DEFAULT_URL}/upload"
	with open(file_path, 'rb') as f:
		files = {"file": (os.path.basename(file_path), f)}
		params = {"src": src, "run_llm": str(run_llm).lower(), "sync_es": str(sync_es).lower(), "mode": mode}
		resp = requests.post(url, files=files, params=params, timeout=120)
	try:
		data = resp.json()
	except Exception:
		print("响应非 JSON:", resp.text[:500])
		return
	print("状态:", resp.status_code)
	print("结果:", data)

def main():
	p = argparse.ArgumentParser()
	p.add_argument('--file', required=False, help='单文件增量上传路径 (CVE json / CNVD xml / CNNVD xml)。不提供则执行全量。')
	p.add_argument('--src', required=False, choices=['cve','cnvd','cnnvd'], help='来源，不传则根据扩展名推断 (json->cve)')
	p.add_argument('--no-llm', action='store_true', help='(增量模式) 禁用 LLM 抽取')
	p.add_argument('--no-es', action='store_true', help='(增量模式) 禁用 ES 同步')
	# --mode 仅在增量上传时允许覆盖，默认 incremental；全量模式由是否提供 --file 决定
	p.add_argument('--mode', choices=['incremental','full'], default='incremental', help='仅在 --file 提供时生效；默认 incremental')
	args = p.parse_args()

	if not args.file:
		print('未指定 --file，执行全量更新 (pipeline_daily)...')
		# 直接调用本地全量流水线（含锁），等价于独立运行 python pipeline_daily.py
		from pipeline_daily import main as pipeline_main
		pipeline_main()
		return

	# ===== 单文件增量上传 =====
	if not os.path.isfile(args.file):
		print('文件不存在:', args.file)
		sys.exit(1)
	src = args.src
	if not src:
		lower = args.file.lower()
		if lower.endswith('.json'):
			src = 'cve'
		elif lower.endswith('.xml'):
			print('XML 文件必须显式指定 --src cnvd|cnnvd')
			sys.exit(1)
		else:
			print('无法推断 src, 请添加 --src')
			sys.exit(1)
	# 强制增量：如果用户传了 --mode full 也允许（表示上传后立即触发全量 LLM+ES）
	upload(args.file, src, run_llm=not args.no_llm, sync_es=not args.no_es, mode=args.mode)

if __name__ == '__main__':
	main()

