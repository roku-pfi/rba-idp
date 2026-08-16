# Build from the polyrepo root (develop/):
#   docker build -f rba-idp/Dockerfile -t rba-idp:dev .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN pip install --no-cache-dir -U pip setuptools wheel

COPY rba-contracts /opt/rba-contracts
COPY rba-idp /app

RUN pip install --no-cache-dir /opt/rba-contracts /app \
    && useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app

USER appuser
EXPOSE 8001
CMD ["uvicorn", "rba_idp.main:app", "--host", "0.0.0.0", "--port", "8001"]
