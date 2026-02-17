# Rebuff - Prompt Injection Detector Suite
# Lightweight container with Puppetry detector

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install base dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY adapters /app/adapters
COPY core /app/core
COPY cli /app/cli
COPY integrations /app/integrations
COPY config /app/config

# Copy Puppetry Detector (pure Python, no install needed)
COPY vendor/puppetry-detector /app/vendor/puppetry-detector

# Copy pyproject.toml for package metadata
COPY pyproject.toml .
COPY README.md .

# Install the package
RUN pip install --no-cache-dir -e .

# Environment
ENV PYTHONPATH=/app:/app/vendor/puppetry-detector
ENV PYTECTOR_SERVICE_URL=http://pytector:8081

# Default command - run CLI
ENTRYPOINT ["rebuff"]
CMD ["--help"]
