"""PIGuard Service - Prompt injection detection via PIGuard HuggingFace model."""

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="PIGuard Service", version="0.1.0")

# Lazy load to avoid startup delay
classifier = None

def get_classifier():
    global classifier
    if classifier is None:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline

        tokenizer = AutoTokenizer.from_pretrained("leolee99/PIGuard", trust_remote_code=True)
        model = AutoModelForSequenceClassification.from_pretrained("leolee99/PIGuard", trust_remote_code=True)
        classifier = pipeline(
            "text-classification",
            model=model,
            tokenizer=tokenizer,
            truncation=True,
            max_length=512,
        )
    return classifier


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
    clf = get_classifier()
    result = clf(request.text)[0]

    # PIGuard returns labels like "INJECTION" or "BENIGN"
    label = result.get("label", "").upper()
    score = result.get("score", 0.0)

    is_injection = "INJECTION" in label or label == "LABEL_1"

    # If it's an injection, confidence is the score
    # If it's benign, confidence should be low (1 - score)
    confidence = score if is_injection else (1.0 - score)

    return DetectResponse(
        is_injection=is_injection,
        confidence=confidence,
        category="prompt_injection" if is_injection else None,
        explanation=f"PIGuard: {label} (score: {score:.2%})",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8082)
