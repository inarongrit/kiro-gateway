# ML guard (Bedrock Guardrails second layer). Credentials come from the EC2 instance role
# (IMDSv2, hop limit 2 so containers can reach it); nothing secret is baked into the image.
FROM python:3.12.15-slim-bookworm
WORKDIR /app
COPY requirements.lock requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER 65534:65534
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python3 -c "import socket; socket.create_connection(('127.0.0.1', 8080), 2)"
CMD ["python3", "app.py"]
