FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/YOUR_USERNAME/security-automation"
LABEL org.opencontainers.image.description="Self-hosted security news aggregator and repository scanner"
LABEL org.opencontainers.image.licenses="MIT"

# Create non-root user before anything else
RUN addgroup --system appuser && adduser --system --ingroup appuser appuser

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

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
