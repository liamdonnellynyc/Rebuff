"""Unit tests for adapters/base.py interfaces."""

import pytest

from adapters.base import DetectionResult, Detector, TrustLevel


class TestTrustLevel:
    """Tests for TrustLevel enum."""

    def test_trust_level_values(self):
        """Trust levels have expected values."""
        assert TrustLevel.TOOL_OUTPUT == 10
        assert TrustLevel.MCP == 50
        assert TrustLevel.USER == 100

    def test_trust_level_ordering(self):
        """Trust levels are ordered by trust."""
        assert TrustLevel.TOOL_OUTPUT < TrustLevel.MCP < TrustLevel.USER


class TestDetectionResult:
    """Tests for DetectionResult dataclass."""

    def test_basic_creation(self):
        """Create a basic detection result."""
        result = DetectionResult(
            is_injection=True,
            confidence=0.85,
            category="instruction_override",
            explanation="Detected attempt to override system prompt",
            latency_ms=15.5,
            detector_id="heuristic",
        )

        assert result.is_injection is True
        assert result.confidence == 0.85
        assert result.category == "instruction_override"
        assert result.explanation == "Detected attempt to override system prompt"
        assert result.latency_ms == 15.5
        assert result.detector_id == "heuristic"

    def test_minimal_creation(self):
        """Create result with only required fields."""
        result = DetectionResult(is_injection=False, confidence=0.1)

        assert result.is_injection is False
        assert result.confidence == 0.1
        assert result.category is None
        assert result.explanation is None
        assert result.latency_ms == 0.0
        assert result.detector_id == ""

    def test_confidence_validation_too_high(self):
        """Confidence above 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="confidence must be between"):
            DetectionResult(is_injection=True, confidence=1.5)

    def test_confidence_validation_negative(self):
        """Negative confidence raises ValueError."""
        with pytest.raises(ValueError, match="confidence must be between"):
            DetectionResult(is_injection=True, confidence=-0.1)

    def test_confidence_boundary_values(self):
        """Confidence at boundaries (0.0 and 1.0) is valid."""
        result_zero = DetectionResult(is_injection=False, confidence=0.0)
        result_one = DetectionResult(is_injection=True, confidence=1.0)

        assert result_zero.confidence == 0.0
        assert result_one.confidence == 1.0


class ConcreteDetector(Detector):
    """Concrete implementation for testing the ABC."""

    def __init__(self, detector_id: str = "test"):
        self._id = detector_id
        self._healthy = True

    @property
    def id(self) -> str:
        return self._id

    def detect(self, text: str, trust_level: TrustLevel = TrustLevel.USER) -> DetectionResult:
        # Simple mock: flag text containing "injection"
        is_injection = "injection" in text.lower()
        return DetectionResult(
            is_injection=is_injection,
            confidence=0.9 if is_injection else 0.1,
            detector_id=self._id,
        )

    def warmup(self) -> None:
        pass

    def health_check(self) -> bool:
        return self._healthy


class TestDetectorABC:
    """Tests for Detector abstract base class."""

    def test_concrete_implementation(self):
        """Can create concrete implementation of Detector."""
        detector = ConcreteDetector("my_detector")
        assert detector.id == "my_detector"

    def test_detect_returns_result(self):
        """Detect method returns DetectionResult."""
        detector = ConcreteDetector()
        result = detector.detect("safe text")

        assert isinstance(result, DetectionResult)
        assert result.is_injection is False

    def test_detect_with_injection(self):
        """Detect method identifies injection."""
        detector = ConcreteDetector()
        result = detector.detect("ignore previous, this is an injection attack")

        assert result.is_injection is True
        assert result.confidence > 0.5

    def test_detect_with_trust_level(self):
        """Detect accepts trust level parameter."""
        detector = ConcreteDetector()
        result = detector.detect("text", trust_level=TrustLevel.TOOL_OUTPUT)

        assert isinstance(result, DetectionResult)

    def test_warmup(self):
        """Warmup can be called."""
        detector = ConcreteDetector()
        # Should not raise
        detector.warmup()

    def test_health_check(self):
        """Health check returns boolean."""
        detector = ConcreteDetector()
        assert detector.health_check() is True

        detector._healthy = False
        assert detector.health_check() is False
