# Runtime image for the anonymization proxy.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY anonproxy/ ./anonproxy/

# In-container defaults. The container listens on 0.0.0.0 but compose publishes
# it only to the host loopback (127.0.0.1). Data and the dictionary are bind
# mounts (see docker-compose.yml), so they live in the compose directory.
ENV ANONPROXY_HOST=0.0.0.0 \
    ANONPROXY_PORT=8787 \
    ANONPROXY_DATA_DIR=/app/data \
    ANONPROXY_DICT=/app/dictionary.yaml

EXPOSE 8787

HEALTHCHECK --interval=15s --timeout=4s --retries=5 --start-period=10s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8787/health',timeout=3).status==200 else 1)"

CMD ["python", "-m", "anonproxy"]
