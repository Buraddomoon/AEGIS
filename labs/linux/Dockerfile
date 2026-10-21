FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN groupadd --gid 10001 aegis && useradd --uid 10001 --gid aegis --no-create-home aegis \
    && mkdir /state /work /observation-log \
    && chown 10001:10001 /state /work /observation-log \
    && chmod 700 /state /work /observation-log \
    && python -m pip install --no-cache-dir pip==26.2.2
COPY requirements.lock pyproject.toml ./
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.lock
COPY apps/api/ apps/api/
RUN pip install --no-cache-dir --no-deps .
USER 10001:10001
ENTRYPOINT ["python", "-m", "aegis.lab_runner.server"]
