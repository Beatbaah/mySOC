# mySOC API and sensor (same image, different command).
FROM python:3.12.8-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

# Live capture needs libpcap; harmless for the API.
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-capture.txt ./
RUN pip install -r requirements-capture.txt

COPY mysoc ./mysoc

# Run as an unprivileged user. Capture mode adds only NET_RAW/NET_ADMIN
# (see docker-compose.capture.yml), never full root.
RUN useradd --system --uid 10001 --home /app mysoc && chown -R mysoc /app
USER mysoc

EXPOSE 8000
# The API port isn't published: only the web (nginx) container can reach
# it, and nginx overwrites X-Forwarded-For with the real client address, so
# trusting forwarded headers here can't be abused to spoof audit-log IPs.
CMD ["uvicorn", "mysoc.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
