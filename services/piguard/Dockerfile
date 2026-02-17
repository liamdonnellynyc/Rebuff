# PIGuard Service - HuggingFace model for prompt injection detection
FROM python:3.11-slim

WORKDIR /app

# Install PyTorch (CPU version to keep image smaller)
RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu

# Install transformers and FastAPI
RUN pip install --no-cache-dir \
    transformers>=4.35.0 \
    fastapi>=0.100.0 \
    uvicorn>=0.23.0

COPY services/piguard/main.py /app/main.py

EXPOSE 8082

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8082"]
