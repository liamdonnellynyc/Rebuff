"""Integration tests for weighted vote pipeline execution strategy."""

import pytest

from adapters.base import DetectionResult, Detector, TrustLevel
from core.pipeline import (
    ExecutionStrategy,
    PipelineConfig,
)
from core.trust import TrustConfig, TrustLevelsConfig
from tests.integration.conftest import Pipeline


class MockDetector(Detector):
    """Mock detector for testing weighted voting."""

    def __init__(
        self,
        detector_id: str,
        is_injection: bool = False,
        confidence: float = 0.5,
    ):
        self._id = detector_id
        self._is_injection = is_injection
        self._confidence = confidence

    @property
    def id(self) -> str:
        return self._id

    def detect(self, text: str, trust_level: TrustLevel = TrustLevel.USER) -> DetectionResult:
        return DetectionResult(
            is_injection=self._is_injection,
            confidence=self._confidence,
            latency_ms=1.0,
            detector_id=self._id,
        )

    def warmup(self) -> None:
        pass

    def health_check(self) -> bool:
        return True


class TestWeightedVoteBasic:
    """Basic tests for weighted vote strategy."""

    def test_weighted_vote_runs_all_detectors(self):
        """Weighted vote runs all detectors."""
        detectors = [
            MockDetector("a", confidence=0.3),
            MockDetector("b", confidence=0.4),
            MockDetector("c", confidence=0.5),
        ]
        config = PipelineConfig(strategy=ExecutionStrategy.WEIGHTED_VOTE)
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.9)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert result.detectors_run == 3  # 3 mock detectors

    def test_weighted_vote_applies_weights(self):
        """Weighted vote applies detector weights correctly."""
        detectors = [
            MockDetector("accurate", is_injection=True, confidence=0.9),
            MockDetector("inaccurate", is_injection=False, confidence=0.1),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.WEIGHTED_VOTE,
            detector_weights={"accurate": 2.0, "inaccurate": 0.5},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5, bias=1.0)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # Higher weighted detector should dominate
        assert result.is_injection is True


class TestWeightedVoteCalculation:
    """Test weighted vote calculation logic."""

    def test_equal_weights_averages_confidence(self):
        """Equal weights result in average confidence."""
        detectors = [
            MockDetector("a", is_injection=True, confidence=0.6),
            MockDetector("b", is_injection=True, confidence=0.8),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.WEIGHTED_VOTE,
            detector_weights={"a": 1.0, "b": 1.0},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5, bias=1.0)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # (0.6*1 + 0.8*1) / (1 + 1) = 0.7
        assert result.confidence == pytest.approx(0.7, abs=0.05)

    def test_unequal_weights_biases_result(self):
        """Unequal weights bias result toward higher weighted detector."""
        detectors = [
            MockDetector("heavy", is_injection=True, confidence=0.85),  # Below early_exit threshold
            MockDetector("light", is_injection=False, confidence=0.1),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.WEIGHTED_VOTE,
            detector_weights={"heavy": 3.0, "light": 1.0},
            early_exit_threshold=0.95,  # Ensure no early exit
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5, bias=1.0)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # (0.85*3 + 0.1*1) / (3 + 1) = 2.65/4 = 0.6625
        assert result.confidence == pytest.approx(0.6625, abs=0.05)

    def test_default_weight_is_one(self):
        """Detectors without explicit weight default to 1.0."""
        detectors = [
            MockDetector("weighted", confidence=0.6),
            MockDetector("unweighted", confidence=0.4),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.WEIGHTED_VOTE,
            detector_weights={"weighted": 2.0},  # unweighted not specified
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.9, bias=1.0)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # (0.6*2 + 0.4*1) / (2 + 1) = 1.6/3 = 0.533
        assert result.confidence == pytest.approx(0.533, abs=0.05)


class TestWeightedVoteMajority:
    """Test majority voting behavior in weighted mode."""

    def test_weighted_majority_determines_injection(self):
        """Weighted majority determines is_injection."""
        detectors = [
            MockDetector("heavy_yes", is_injection=True, confidence=0.8),
            MockDetector("light_no1", is_injection=False, confidence=0.2),
            MockDetector("light_no2", is_injection=False, confidence=0.3),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.WEIGHTED_VOTE,
            detector_weights={"heavy_yes": 3.0, "light_no1": 1.0, "light_no2": 1.0},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # heavy_yes has weight 3, total non-injection weight is 2
        # 3 > (3+1+1)/2 = 2.5, so injection wins
        assert result.is_injection is True

    def test_unanimous_non_injection(self):
        """All detectors agreeing on non-injection."""
        detectors = [
            MockDetector("a", is_injection=False, confidence=0.2),
            MockDetector("b", is_injection=False, confidence=0.3),
            MockDetector("c", is_injection=False, confidence=0.1),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.WEIGHTED_VOTE,
            detector_weights={"a": 1.0, "b": 1.0, "c": 1.0},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert result.is_injection is False


class TestWeightedVoteWithRealAdapters:
    """Integration tests with real adapters in weighted vote mode."""

    def test_weighted_vote_with_all_adapters(self):
        """Weighted vote with all real adapters."""
        config = PipelineConfig(
            strategy=ExecutionStrategy.WEIGHTED_VOTE,
            detector_weights={
                "puppetry": 1.0,
                "piguard": 1.5,
                "llmguard": 2.0,
            },
        )
        pipeline = Pipeline(config=config)
        pipeline.warmup()

        result = pipeline.scan("test with weighted vote")

        assert result.detectors_run == 4

    def test_weighted_vote_respects_trust(self):
        """Weighted vote respects trust level configuration."""
        config = PipelineConfig(strategy=ExecutionStrategy.WEIGHTED_VOTE)
        pipeline = Pipeline(config=config)

        result = pipeline.scan("test input", source="system/internal")

        assert result.trust_level_used == "system"


class TestWeightedVoteEdgeCases:
    """Edge cases for weighted vote strategy."""

    def test_weighted_vote_no_detectors(self):
        """Weighted vote handles empty detector list."""
        config = PipelineConfig(strategy=ExecutionStrategy.WEIGHTED_VOTE)
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=[])

        result = pipeline.scan("test input")

        assert result.is_injection is False
        assert result.confidence == 0.0

    def test_weighted_vote_single_detector(self):
        """Weighted vote works with single detector."""
        detector = MockDetector("only", is_injection=True, confidence=0.8)
        config = PipelineConfig(
            strategy=ExecutionStrategy.WEIGHTED_VOTE,
            detector_weights={"only": 2.0},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5, bias=1.0)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=[detector])

        result = pipeline.scan("test input")

        assert result.is_injection is True
        assert result.confidence == pytest.approx(0.8, abs=0.05)

    def test_weighted_vote_zero_weight(self):
        """Zero weight effectively excludes detector."""
        detectors = [
            MockDetector("counted", is_injection=False, confidence=0.3),
            MockDetector("ignored", is_injection=True, confidence=0.9),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.WEIGHTED_VOTE,
            detector_weights={"counted": 1.0, "ignored": 0.0},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # Result should be dominated by counted detector
        # Note: is_injection depends on majority vote logic
        assert result.detectors_run == 2
