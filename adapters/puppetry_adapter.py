"""
Puppetry Detector adapter.

Wraps the Puppetry Detector for policy/role injection detection.
Pure regex-based, extremely lightweight with no ML dependencies.
"""

import time

from adapters.base import DetectionResult, Detector, TrustLevel

# Try to import vendor library
_PUPPETRY_AVAILABLE = False
try:
    from puppetry_detector import PuppetryDetector as PuppetryDetectorLib
    _PUPPETRY_AVAILABLE = True
except ImportError:
    # Try vendor path
    try:
        import sys
        from pathlib import Path
        vendor_path = Path(__file__).parent.parent / "vendor" / "puppetry-detector"
        if vendor_path.exists():
            sys.path.insert(0, str(vendor_path))
            from puppetry_detector import PuppetryDetector as PuppetryDetectorLib
            _PUPPETRY_AVAILABLE = True
    except ImportError:
        PuppetryDetectorLib = None


class PuppetryDetector(Detector):
    """Prompt injection detector using Puppetry Detector library.

    Puppetry Detector uses pure regex patterns to identify policy puppetry
    attempts - structured attacks that try to override LLM behavior through
    XML tags, role assignments, and permission declarations.

    Extremely lightweight with no ML dependencies. Typical latency <1ms.

    Falls back to stub mode when the vendor library is not available.
    """

    def __init__(self, stub_mode: bool | None = None) -> None:
        """Initialize the Puppetry detector.

        Args:
            stub_mode: Force stub mode (True) or real mode (False).
                If None, auto-detect based on vendor availability.
        """
        if stub_mode is None:
            self._stub_mode = not _PUPPETRY_AVAILABLE
        else:
            self._stub_mode = stub_mode

        self._detector = None
        if not self._stub_mode and _PUPPETRY_AVAILABLE:
            self._detector = PuppetryDetectorLib()

        self._warmed_up = False

    @property
    def id(self) -> str:
        """Return detector identifier."""
        return "puppetry"

    def detect(self, text: str, trust_level: TrustLevel = TrustLevel.USER) -> DetectionResult:
        """Analyze text for policy puppetry injection patterns.

        Args:
            text: The input text to analyze.
            trust_level: Trust level of the input source.

        Returns:
            DetectionResult with analysis outcome.
        """
        start_time = time.perf_counter()

        if self._stub_mode:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return DetectionResult(
                is_injection=False,
                confidence=0.0,
                category=None,
                explanation="Stub mode: vendor library not available",
                latency_ms=latency_ms,
                detector_id=self.id,
            )

        try:
            assert self._detector is not None  # Guaranteed by not being in stub mode
            result = self._detector.detect(text)
            latency_ms = (time.perf_counter() - start_time) * 1000

            # Determine if this is an injection
            # policy_like alone isn't necessarily malicious
            # malicious patterns are definitely concerning
            is_injection = result.get("malicious", False)

            # If both policy_like AND malicious, high confidence
            # If just malicious, medium confidence
            # If just policy_like, low confidence (might be legitimate)
            if result.get("malicious") and result.get("policy_like"):
                confidence = 0.95
                category = "policy_puppetry"
                explanation = "Detected malicious policy structure with role/permission manipulation"
            elif result.get("malicious"):
                confidence = 0.75
                category = "malicious_pattern"
                explanation = "Detected malicious patterns (role override, permission escalation)"
            elif result.get("policy_like"):
                # Policy-like structure alone is suspicious but not definitive
                is_injection = False
                confidence = 0.3
                category = "suspicious_structure"
                explanation = "Detected policy-like XML structure (may be legitimate)"
            else:
                confidence = 0.0
                category = None
                explanation = None

            return DetectionResult(
                is_injection=is_injection,
                confidence=confidence,
                category=category,
                explanation=explanation,
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
        """Warm up the detector.

        For Puppetry Detector, regex patterns are compiled on first use.
        Running a dummy detection pre-compiles them.
        """
        if self._stub_mode:
            self._warmed_up = True
            return

        try:
            self.detect("warmup test")
            self._warmed_up = True
        except Exception:
            self._warmed_up = True

    def health_check(self) -> bool:
        """Check if detector is operational.

        Returns:
            True if detector is ready, False on error.
        """
        if self._stub_mode:
            return True

        try:
            result = self.detect("health check")
            return result.category != "error"
        except Exception:
            return False

    @property
    def stub_mode(self) -> bool:
        """Return whether detector is running in stub mode."""
        return self._stub_mode
