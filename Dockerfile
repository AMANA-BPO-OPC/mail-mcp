FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd -m appuser && mkdir -p /data && chown appuser /data
USER appuser
ENV DB_PATH=/data/gmail_mcp.sqlite3 PORT=8000
EXPOSE 8000
VOLUME ["/data"]
CMD ["python", "-m", "app.main"]
