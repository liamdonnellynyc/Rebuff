# Rebuff Web UI
# Lightweight frontend for prompt injection detection

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install base dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt uvicorn[standard] fastapi

# Copy application code
COPY adapters /app/adapters
COPY core /app/core
COPY cli /app/cli
COPY integrations /app/integrations
COPY config /app/config

# Copy Puppetry Detector
COPY vendor/puppetry-detector /app/vendor/puppetry-detector

# Copy pyproject.toml for package metadata
COPY pyproject.toml .
COPY README.md .

# Install the package
RUN pip install --no-cache-dir -e .

# Copy web service
COPY services/web/main.py /app/services/web/main.py

# Environment
ENV PYTHONPATH=/app:/app/vendor/puppetry-detector
ENV PYTECTOR_SERVICE_URL=http://pytector:8081
ENV PIGUARD_SERVICE_URL=http://piguard:8082
ENV LLMGUARD_SERVICE_URL=http://llmguard:8083

EXPOSE 8080

CMD ["uvicorn", "services.web.main:app", "--host", "0.0.0.0", "--port", "8080"]
