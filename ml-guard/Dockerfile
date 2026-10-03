# syntax=docker/dockerfile:1.7
# ML guard (Bedrock Guardrails second layer). Credentials come from the instance role / standard
# AWS credential chain; nothing secret is baked into the image. Base image pinned by digest.
FROM python:3.12.15-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
WORKDIR /app
COPY requirements.lock requirements.txt
# Hash-pinned lock (uv pip compile --generate-hashes ml-guard/requirements.in).
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.txt
COPY app.py .
USER 65534:65534
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["python3", "-c", "import socket; socket.create_connection(('127.0.0.1', 8080), 2)"]
CMD ["python3", "app.py"]
