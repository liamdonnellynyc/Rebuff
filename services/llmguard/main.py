"""LLM-Guard Service - Prompt injection detection via LLM-Guard library."""

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="LLM-Guard Service", version="0.1.0")

# Lazy load to avoid startup delay
scanner = None

def get_scanner():
    global scanner
    if scanner is None:
        from llm_guard.input_scanners import PromptInjection
        scanner = PromptInjection(threshold=0.5)
    return scanner


class DetectRequest(BaseModel):
    text: str


class DetectResponse(BaseModel):
    is_injection: bool
    confidence: float
    category: str | None = None
    explanation: str | None = None


@app.get("/health")
async def health():
    return {"status": "ok", "ready": True}


@app.post("/detect", response_model=DetectResponse)
async def detect(request: DetectRequest):
    scanner = get_scanner()
    sanitized, is_valid, risk_score = scanner.scan(request.text)

    # Clamp risk_score to [0.0, 1.0] - LLM-Guard can return negative values for benign content
    confidence = max(0.0, min(1.0, risk_score))

    return DetectResponse(
        is_injection=not is_valid,
        confidence=confidence,
        category="prompt_injection" if not is_valid else None,
        explanation=f"LLM-Guard risk score: {risk_score:.2%}",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8083)
