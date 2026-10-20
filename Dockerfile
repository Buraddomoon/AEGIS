FROM node:24-alpine AS web
WORKDIR /web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci
COPY apps/web/ ./
RUN npm run build

FROM python:3.13-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 aegis && useradd --uid 10001 --gid aegis --no-create-home aegis \
    && python -m pip install --no-cache-dir pip==26.2.2
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.lock
COPY pyproject.toml alembic.ini ./
COPY apps/api/ apps/api/
COPY fixtures/ fixtures/
RUN pip install --no-cache-dir --no-deps .
COPY --from=web /web/dist apps/web/dist
USER 10001:10001
EXPOSE 8080
CMD ["uvicorn", "aegis.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-proxy-headers"]
