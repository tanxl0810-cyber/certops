FROM node:22-bookworm-slim AS frontend
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
COPY ops/frontend-notices.mjs /ops/frontend-notices.mjs
RUN npm run build

FROM python:3.12-slim-bookworm
LABEL org.opencontainers.image.title="CertOps" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=Asia/Shanghai
WORKDIR /app
COPY requirements.txt ./
COPY ops/collect-notices.py /tmp/certops-collect-notices.py
RUN pip install --no-cache-dir -r requirements.txt \
    && python /tmp/certops-collect-notices.py --output /usr/share/doc/certops/PYTHON_NOTICES.txt \
    && rm /tmp/certops-collect-notices.py \
    && useradd --uid 10001 --create-home certops
COPY app/ ./app/
COPY --from=frontend /app/static/ ./app/static/
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/doc/certops/
USER 10001:10001
EXPOSE 8090
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090", "--proxy-headers"]
