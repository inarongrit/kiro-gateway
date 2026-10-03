# Guardrail Console: FastAPI behind uvicorn TLS. Runs as the host user (uid 1000) so files it
# writes in the bind-mounted repo keep their normal ownership.
FROM python:3.12.15-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends jq gettext-base curl git ca-certificates grep \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /console
COPY requirements.lock requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY web ./web
USER 1000:1000
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
EXPOSE 9200
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9200", \
     "--ssl-certfile", "/tls/admin.crt", "--ssl-keyfile", "/tls/admin.key", \
     "--no-server-header", "--no-proxy-headers"]
