FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VULNFLOW_CONTROL_DB=/app/data/control.db \
    VULNFLOW_DEFAULT_PROJECT_DB=/app/data/projects/default/vulnflow.db \
    VULNFLOW_DEMO_MODE=0 \
    VULNFLOW_ALLOW_LOCAL_ADMIN_FALLBACK=0 \
    FORWARDED_ALLOW_IPS=127.0.0.1

WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock \
    && useradd --create-home --uid 10001 vulnflow

# Copy only runtime inputs.  Never copy the repository wholesale because the
# build directory may contain .env files, customer databases, evidence, or keys.
COPY app ./app
# The runtime image carries only the offline administration commands required
# to initialize accounts, prepare split storage, and recover the control plane.
# Test, release, browser, scanner-collection, and network rehearsal scripts stay
# outside the production image.
COPY scripts/__init__.py scripts/manage_users.py scripts/manage_control_recovery.py \
     scripts/prepare_storage.py scripts/generate_integrity_proof_key.py \
     scripts/verify_integrity_proof.py ./scripts/
COPY rules ./rules
COPY data/sample_findings.csv ./data/sample_findings.csv
COPY data/sample_product_release.cdx.json ./data/sample_product_release.cdx.json
COPY data/sample_sbom.cdx.json ./data/sample_sbom.cdx.json
COPY data/sample_sbom_v2.cdx.json ./data/sample_sbom_v2.cdx.json
COPY VERSION LICENSE README.md ./

RUN mkdir -p /app/data/projects/default /app/external-backups \
    && chown -R vulnflow:vulnflow /app
USER vulnflow
VOLUME ["/app/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=3)" || exit 1
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
