"""
PIGuard detector adapter.

Calls containerized PIGuard service for ML-based prompt injection detection.
Uses the leolee99/PIGuard HuggingFace model.
"""

import os
import time

from adapters.base import DetectionResult, Detector, TrustLevel

PIGUARD_SERVICE_URL = os.environ.get("PIGUARD_SERVICE_URL", "http://localhost:8082")


class PIGuardDetector(Detector):
    """Prompt injection detector using PIGuard HuggingFace model.

    Calls a containerized PIGuard service to isolate heavy ML dependencies.
    """

    def __init__(
        self,
        stub_mode: bool | None = None,
        service_url: str | None = None,
        timeout_ms: float = 30000,
    ) -> None:
        self._service_url = service_url or PIGUARD_SERVICE_URL
        self._timeout_ms = timeout_ms
        self._stub_mode = stub_mode if stub_mode is not None else False
        self._warmed_up = False
        self._service_available: bool | None = None

    @property
    def id(self) -> str:
        return "piguard"

    def _check_service(self) -> bool:
        import requests
        try:
            resp = requests.get(f"{self._service_url}/health", timeout=self._timeout_ms / 1000)
            if resp.status_code != 200:
                return False
            return resp.json().get("ready", False)
        except Exception:
            return False

    def detect(self, text: str, trust_level: TrustLevel = TrustLevel.USER) -> DetectionResult:
        import requests
        start_time = time.perf_counter()

        if self._stub_mode:
            return DetectionResult(
                is_injection=False,
                confidence=0.0,
                category=None,
                explanation="Stub mode: PIGuard disabled",
                latency_ms=(time.perf_counter() - start_time) * 1000,
                detector_id=self.id,
            )

        if self._service_available is None:
            self._service_available = self._check_service()

        if not self._service_available:
            return DetectionResult(
                is_injection=False,
                confidence=0.0,
                category=None,
                explanation="Stub mode: PIGuard service unavailable",
                latency_ms=(time.perf_counter() - start_time) * 1000,
                detector_id=self.id,
            )

        try:
            resp = requests.post(
                f"{self._service_url}/detect",
                json={"text": text},
                timeout=self._timeout_ms / 1000
            )
            if resp.status_code != 200:
                return DetectionResult(
                    is_injection=False,
                    confidence=0.0,
                    category="error",
                    explanation=f"Service error: {resp.status_code}",
                    latency_ms=(time.perf_counter() - start_time) * 1000,
                    detector_id=self.id,
                )

            data = resp.json()
            return DetectionResult(
                is_injection=data.get("is_injection", False),
                confidence=data.get("confidence", 0.0),
                category=data.get("category"),
                explanation=data.get("explanation"),
                latency_ms=(time.perf_counter() - start_time) * 1000,
                detector_id=self.id,
            )
        except Exception as e:
            return DetectionResult(
                is_injection=False,
                confidence=0.0,
                category="error",
                explanation=f"Service call failed: {e}",
                latency_ms=(time.perf_counter() - start_time) * 1000,
                detector_id=self.id,
            )

    def warmup(self) -> None:
        if not self._stub_mode:
            self._service_available = self._check_service()
        self._warmed_up = True

    def health_check(self) -> bool:
        if self._stub_mode:
            return True
        return self._check_service()

    @property
    def stub_mode(self) -> bool:
        return self._stub_mode or not (self._service_available if self._service_available is not None else self._check_service())
