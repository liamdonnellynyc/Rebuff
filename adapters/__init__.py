"""
Adapter layer for prompt injection detectors.

This module provides the base interfaces and implementations for
various prompt injection detection engines.
"""

from typing import Any

from adapters.base import DetectionResult, Detector, TrustLevel
from adapters.llmguard_adapter import LLMGuardDetector
from adapters.piguard_adapter import PIGuardDetector
from adapters.puppetry_adapter import PuppetryDetector
from adapters.pytector_adapter import PytectorDetector

# Registry of available detector classes by ID
_DETECTOR_REGISTRY = {
    "puppetry": PuppetryDetector,
    "pytector": PytectorDetector,
    "piguard": PIGuardDetector,
    "llmguard": LLMGuardDetector,
}


def get_detector(detector_id: str, **kwargs: Any) -> Detector:
    """Factory function to get a detector instance by ID.

    Args:
        detector_id: Unique identifier for the detector type.
            Supported: "puppetry", "pytector", "piguard", "llmguard"
        **kwargs: Additional arguments passed to the detector constructor.

    Returns:
        A Detector instance of the requested type.

    Raises:
        ValueError: If detector_id is not recognized.

    Example:
        >>> detector = get_detector("puppetry")
        >>> detector = get_detector("piguard", stub_mode=True)
        >>> detector = get_detector("llmguard")
    """
    detector_class = _DETECTOR_REGISTRY.get(detector_id.lower())
    if detector_class is None:
        available = ", ".join(sorted(_DETECTOR_REGISTRY.keys()))
        raise ValueError(
            f"Unknown detector ID: {detector_id!r}. Available: {available}"
        )
    detector: Detector = detector_class(**kwargs)
    return detector


def list_detectors() -> list[str]:
    """Return list of available detector IDs.

    Returns:
        List of detector ID strings.
    """
    return sorted(_DETECTOR_REGISTRY.keys())


__all__ = [
    # Base interfaces
    "Detector",
    "DetectionResult",
    "TrustLevel",
    # Concrete adapters (lightweight)
    "PuppetryDetector",
    # Concrete adapters (ML-based, containerized)
    "PytectorDetector",
    "PIGuardDetector",
    "LLMGuardDetector",
    # Factory functions
    "get_detector",
    "list_detectors",
]
