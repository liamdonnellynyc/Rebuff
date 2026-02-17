# LLM-Guard Service - ML-based prompt injection detection
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi>=0.100.0 \
    uvicorn>=0.23.0 \
    llm-guard>=0.3.0

COPY services/llmguard/main.py /app/main.py

EXPOSE 8083

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8083"]
