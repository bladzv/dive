FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/bladzv/dive"
LABEL org.opencontainers.image.description="Self-hosted security news aggregator and repository scanner"
LABEL org.opencontainers.image.licenses="MIT"

# Create non-root user before anything else
RUN addgroup --system appuser && adduser --system --ingroup appuser appuser

# System deps + gitleaks (layer cached independently from Python deps)
# gitleaks binary is ~30 MB; pinned to a specific release for reproducibility.
RUN apt-get update && apt-get install -y --no-install-recommends git curl && \
    rm -rf /var/lib/apt/lists/* && \
    ARCH=$(uname -m) && \
    case "$ARCH" in \
      x86_64)  GL_ARCH="x64"   ;; \
      aarch64) GL_ARCH="arm64" ;; \
      armv7l)  GL_ARCH="armv7" ;; \
      *) echo "Unsupported arch for gitleaks: $ARCH" && exit 1 ;; \
    esac && \
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_${GL_ARCH}.tar.gz" \
         -o /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz && \
    chmod +x /usr/local/bin/gitleaks

WORKDIR /app

# Dependencies in a separate layer — only rebuilds when requirements.txt changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application source
COPY . .

# Ensure config.yaml was not accidentally included in the build context
# (.dockerignore is the primary guard; this is a second line of defence)
RUN rm -f config.yaml .env

# Persistent directories — owned by appuser so the process can write to them
RUN mkdir -p data logs && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Health check using stdlib only — no extra packages needed
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

CMD ["uvicorn", "dive.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
