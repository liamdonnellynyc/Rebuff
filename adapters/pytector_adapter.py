"""
Pytector detector adapter.

Wraps Pytector ML-based prompt injection detection.
Designed to call a separate containerized Pytector service for isolation
of heavy ML dependencies (transformers, torch).
"""

import os
import time

from adapters.base import DetectionResult, Detector, TrustLevel

# Default service endpoint (containerized pytector)
PYTECTOR_SERVICE_URL = os.environ.get("PYTECTOR_SERVICE_URL", "http://localhost:8081")


class PytectorDetector(Detector):
    """Prompt injection detector using Pytector ML models.

    Pytector uses fine-tuned transformer models (DeBERTa, DistilBERT) to detect
    prompt injection attacks with semantic understanding.

    This adapter calls a separate containerized Pytector service to isolate
    the heavy ML dependencies. The service must be running for detection to work.

    Falls back to stub mode if the service is unavailable.
    """

    def __init__(
        self,
        stub_mode: bool | None = None,
        service_url: str | None = None,
        timeout_ms: float = 5000,
    ) -> None:
        """Initialize the Pytector detector.

        Args:
            stub_mode: Force stub mode (True) or real mode (False).
                If None, auto-detect based on service availability.
            service_url: URL of the Pytector service container.
                Defaults to PYTECTOR_SERVICE_URL env var or localhost:8081.
            timeout_ms: Timeout for service calls in milliseconds.
        """
        self._service_url = service_url or PYTECTOR_SERVICE_URL
        self._timeout_ms = timeout_ms
        self._stub_mode = stub_mode if stub_mode is not None else False
        self._warmed_up = False
        self._service_available: bool | None = None

    @property
    def id(self) -> str:
        """Return detector identifier."""
        return "pytector"

    def _check_service(self) -> bool:
        """Check if Pytector service is available."""
        import requests
        try:
            resp = requests.get(
                f"{self._service_url}/health",
                timeout=self._timeout_ms / 1000
            )
            return bool(resp.status_code == 200)
        except Exception:
            return False

    def detect(self, text: str, trust_level: TrustLevel = TrustLevel.USER) -> DetectionResult:
        """Analyze text for prompt injection using Pytector ML models.

        Args:
            text: The input text to analyze.
            trust_level: Trust level of the input source.

        Returns:
            DetectionResult with analysis outcome.
        """
        import requests

        start_time = time.perf_counter()

        if self._stub_mode:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return DetectionResult(
                is_injection=False,
                confidence=0.0,
                category=None,
                explanation="Stub mode: Pytector disabled",
                latency_ms=latency_ms,
                detector_id=self.id,
            )

        # Check service availability on first call
        if self._service_available is None:
            self._service_available = self._check_service()

        if not self._service_available:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return DetectionResult(
                is_injection=False,
                confidence=0.0,
                category=None,
                explanation="Pytector service unavailable (container not running?)",
                latency_ms=latency_ms,
                detector_id=self.id,
            )

        try:
            resp = requests.post(
                f"{self._service_url}/detect",
                json={"text": text},
                timeout=self._timeout_ms / 1000
            )
            latency_ms = (time.perf_counter() - start_time) * 1000

            if resp.status_code != 200:
                return DetectionResult(
                    is_injection=False,
                    confidence=0.0,
                    category="error",
                    explanation=f"Service error: {resp.status_code}",
                    latency_ms=latency_ms,
                    detector_id=self.id,
                )

            result = resp.json()
            return DetectionResult(
                is_injection=result.get("is_injection", False),
                confidence=result.get("confidence", 0.0),
                category=result.get("category"),
                explanation=result.get("explanation"),
                latency_ms=latency_ms,
                detector_id=self.id,
            )

        except requests.exceptions.Timeout:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return DetectionResult(
                is_injection=False,
                confidence=0.0,
                category="timeout",
                explanation=f"Pytector service timeout ({self._timeout_ms}ms)",
                latency_ms=latency_ms,
                detector_id=self.id,
            )

        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return DetectionResult(
                is_injection=False,
                confidence=0.0,
                category="error",
                explanation=f"Detection error: {e}",
                latency_ms=latency_ms,
                detector_id=self.id,
            )

    def warmup(self) -> None:
        """Warm up by checking service availability."""
        self._service_available = self._check_service()
        self._warmed_up = True

    def health_check(self) -> bool:
        """Check if detector service is operational."""
        if self._stub_mode:
            return True
        return self._check_service()

    @property
    def stub_mode(self) -> bool:
        """Return whether detector is running in stub mode."""
        return self._stub_mode

    @property
    def service_available(self) -> bool:
        """Return whether the Pytector service is available."""
        if self._service_available is None:
            self._service_available = self._check_service()
        return self._service_available
