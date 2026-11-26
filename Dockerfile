FROM python:3.12-slim-bookworm
WORKDIR /app
ENV BIND_HOST=0.0.0.0 PORT=8787 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt
COPY app.py dns_mcp.py godaddy.py database.py migrate_sqlite.py ./
COPY web/ ./web/
RUN mkdir /data && chown 65532:65532 /data
USER 65532:65532
EXPOSE 8787
CMD ["python", "app.py"]
