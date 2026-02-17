# Pytector Service - ML-based prompt injection detection
# Separate container to isolate heavy transformer dependencies

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
# Note: torch CPU-only version is ~200MB instead of ~2GB
RUN pip install --no-cache-dir \
    fastapi>=0.100.0 \
    uvicorn>=0.23.0 \
    transformers>=4.35.0 \
    validators>=0.22.0 \
    pydantic>=2.0.0 \
    groq>=0.4.0 \
    && pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Copy pytector source
COPY vendor/pytector/src /app/vendor/pytector/src

# Copy service
COPY services/pytector/main.py /app/main.py

# Environment
ENV PYTECTOR_MODEL=distilbert
ENV PYTECTOR_THRESHOLD=0.5

# Expose port
EXPOSE 8081

# Pre-download model on build (optional, makes startup faster)
# RUN python -c "from transformers import AutoTokenizer, AutoModelForSequenceClassification; AutoTokenizer.from_pretrained('protectai/deberta-v3-base-prompt-injection'); AutoModelForSequenceClassification.from_pretrained('protectai/deberta-v3-base-prompt-injection')"

# Run service
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8081"]
