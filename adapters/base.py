"""
Base interfaces for the prompt injection detector suite.

Defines the core abstractions: TrustLevel, DetectionResult, and Detector ABC.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum


class TrustLevel(IntEnum):
    """Trust levels for different input sources.

    Higher values indicate higher trust. Used to apply bias to detection
    thresholds - higher trust sources require higher confidence to flag.
    """
    TOOL_OUTPUT = 10   # Output from tools/agents - lowest trust
    MCP = 50           # Model Context Protocol sources
    USER = 100         # Direct user input - highest trust


@dataclass
class DetectionResult:
    """Result from a single detector's analysis.

    Attributes:
        is_injection: Whether the detector flagged this as an injection attempt.
        confidence: Confidence score from 0.0 to 1.0.
        category: Type of injection detected (e.g., "instruction_override").
        explanation: Human-readable explanation of the detection.
        latency_ms: Time taken for detection in milliseconds.
        detector_id: Identifier of the detector that produced this result.
    """
    is_injection: bool
    confidence: float
    category: str | None = None
    explanation: str | None = None
    latency_ms: float = 0.0
    detector_id: str = ""

    def __post_init__(self) -> None:
        """Validate confidence is in valid range."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {self.confidence}")


class Detector(ABC):
    """Abstract base class for all prompt injection detectors.

    All detector implementations must inherit from this class and implement
    the required methods: id property, detect(), warmup(), and health_check().
    """

    @property
    @abstractmethod
    def id(self) -> str:
        """Unique identifier for this detector.

        Returns:
            A string identifier (e.g., "heuristic", "llm_guard", "piguard").
        """
        ...

    @abstractmethod
    def detect(self, text: str, trust_level: TrustLevel = TrustLevel.USER) -> DetectionResult:
        """Analyze text for potential prompt injection.

        Args:
            text: The input text to analyze.
            trust_level: Trust level of the input source.

        Returns:
            DetectionResult with analysis outcome.
        """
        ...

    @abstractmethod
    def warmup(self) -> None:
        """Prepare the detector for use.

        Called once before detection begins. Use for loading models,
        compiling patterns, or any initialization that should happen
        outside the critical path.
        """
        ...

    @abstractmethod
    def health_check(self) -> bool:
        """Check if the detector is operational.

        Returns:
            True if detector is ready to process requests, False otherwise.
        """
        ...
