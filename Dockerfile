# PlutoVulnSearch Dockerfile
# 基础镜像
FROM python:3.10-slim

# 环境变量（可根据实际需要调整）
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PG_DSN="host=pg01 port=5432 dbname=test user=test password=test" \
    ES_URL="http://es01:9200" \
    ES_INDEX="test_vulnerabilities"

# 工作目录
WORKDIR /app

# 安装依赖
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 拷贝项目代码
COPY . .

# 暴露端口（如需 API 服务）
EXPOSE 8000

# 默认启动命令
CMD ["tail", "-f", "/dev/null"]

# 如需定时任务或批处理，可改为：
# CMD ["python", "pipeline_daily.py"]
