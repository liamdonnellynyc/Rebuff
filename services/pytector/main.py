"""
Pytector Service - Containerized ML-based prompt injection detection.

This service wraps Pytector's transformer-based detection in a lightweight
FastAPI server for isolation from the main Rebuff application.
"""

import os
import sys

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Add pytector to path
sys.path.insert(0, "/app/vendor/pytector/src")

from pytector import PromptInjectionDetector

app = FastAPI(
    title="Pytector Service",
    description="ML-based prompt injection detection",
    version="0.1.0",
)

# Initialize detector (will load model on startup)
MODEL_NAME = os.environ.get("PYTECTOR_MODEL", "deberta")
THRESHOLD = float(os.environ.get("PYTECTOR_THRESHOLD", "0.5"))

detector: PromptInjectionDetector | None = None


class DetectRequest(BaseModel):
    text: str


class DetectResponse(BaseModel):
    is_injection: bool
    confidence: float
    category: str | None = None
    explanation: str | None = None


class HealthResponse(BaseModel):
    status: str
    model: str
    ready: bool


@app.on_event("startup")
async def startup():
    """Load model on startup."""
    global detector
    print(f"Loading Pytector model: {MODEL_NAME}")
    try:
        detector = PromptInjectionDetector(
            model_name_or_url=MODEL_NAME,
            default_threshold=THRESHOLD,
            enable_keyword_blocking=True,  # Enable keyword blocking for extra coverage
        )
        print(f"Model loaded successfully: {MODEL_NAME}")
    except Exception as e:
        print(f"Failed to load model: {e}")
        raise


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse(
        status="ok" if detector else "error",
        model=MODEL_NAME,
        ready=detector is not None,
    )


@app.post("/detect", response_model=DetectResponse)
async def detect(request: DetectRequest):
    """Detect prompt injection in text."""
    if not detector:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        result = detector.detect_injection(request.text)

        # Pytector returns: (is_injection: bool, probability: float)
        # or dict with more details depending on version
        if isinstance(result, tuple):
            is_injection, probability = result
            return DetectResponse(
                is_injection=is_injection,
                confidence=probability,
                category="prompt_injection" if is_injection else None,
                explanation=f"ML confidence: {probability:.2%}",
            )
        elif isinstance(result, dict):
            # Handle dict response format
            is_injection = result.get("is_unsafe", result.get("is_injection", False))
            confidence = result.get("probability", result.get("confidence", 0.0))
            hazard = result.get("hazard_code")
            return DetectResponse(
                is_injection=is_injection,
                confidence=confidence,
                category=hazard if is_injection else None,
                explanation=f"Hazard: {hazard}" if hazard else None,
            )
        else:
            # Fallback
            return DetectResponse(
                is_injection=bool(result),
                confidence=1.0 if result else 0.0,
                category=None,
                explanation=None,
            )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)
