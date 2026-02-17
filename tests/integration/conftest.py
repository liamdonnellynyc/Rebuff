"""
Pytest fixtures for integration tests.

All integration tests use stub mode detectors for consistent, predictable results
that don't depend on ML model behavior or external services.
"""

import pytest

from adapters import get_detector, list_detectors
from core.pipeline import Pipeline as _OriginalPipeline
from core.pipeline import PipelineConfig
from core.trust import TrustLevelsConfig


def create_stub_detectors():
    """Create all detectors in stub mode for testing."""
    detectors = []
    for detector_id in list_detectors():
        try:
            detector = get_detector(detector_id, stub_mode=True)
            detectors.append(detector)
        except Exception:
            pass
    return detectors


class Pipeline(_OriginalPipeline):
    """Pipeline wrapper that defaults to stub mode detectors for tests."""

    def __init__(
        self,
        config: PipelineConfig = None,
        trust_config: TrustLevelsConfig = None,
        detectors=None,
    ):
        # Default to stub detectors if none provided
        if detectors is None:
            detectors = create_stub_detectors()
        super().__init__(config=config, trust_config=trust_config, detectors=detectors)


@pytest.fixture
def pipeline():
    """Provide a pipeline with stub mode detectors."""
    pipe = Pipeline()
    pipe.warmup()
    return pipe


@pytest.fixture
def warm_pipeline():
    """Provide a warmed-up pipeline with stub mode detectors."""
    pipe = Pipeline()
    pipe.warmup()
    return pipe
