"""Integration tests for sequential pipeline execution strategy."""

import time

from adapters.base import DetectionResult, Detector, TrustLevel
from core.pipeline import (
    ExecutionStrategy,
    PipelineConfig,
)
from core.trust import TrustConfig, TrustLevelsConfig
from tests.integration.conftest import Pipeline


class MockDetector(Detector):
    """Mock detector for testing sequential execution."""

    def __init__(
        self,
        detector_id: str,
        is_injection: bool = False,
        confidence: float = 0.5,
        latency_ms: float = 1.0,
    ):
        self._id = detector_id
        self._is_injection = is_injection
        self._confidence = confidence
        self._latency_ms = latency_ms
        self.call_count = 0

    @property
    def id(self) -> str:
        return self._id

    def detect(self, text: str, trust_level: TrustLevel = TrustLevel.USER) -> DetectionResult:
        self.call_count += 1
        time.sleep(self._latency_ms / 1000)
        return DetectionResult(
            is_injection=self._is_injection,
            confidence=self._confidence,
            latency_ms=self._latency_ms,
            detector_id=self._id,
        )

    def warmup(self) -> None:
        pass

    def health_check(self) -> bool:
        return True


class TestSequentialExecutionBasic:
    """Basic tests for sequential execution strategy."""

    def test_sequential_runs_in_order(self):
        """Sequential strategy runs detectors in order."""
        detectors = [
            MockDetector("first", confidence=0.3),
            MockDetector("second", confidence=0.4),
            MockDetector("third", confidence=0.5),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            ordering={"first": 1, "second": 2, "third": 3},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.9)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # All 3 mock detectors should run since no detection
        assert result.detectors_run == 3

    def test_sequential_respects_ordering(self):
        """Sequential strategy respects ordering configuration."""
        slow = MockDetector("slow", confidence=0.2)
        fast = MockDetector("fast", confidence=0.2)

        detectors = [slow, fast]  # Add in reverse order
        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            ordering={"fast": 1, "slow": 2},  # fast should run first
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.9)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        pipeline.scan("test input")

        # Both should be called
        assert fast.call_count == 1
        assert slow.call_count == 1


class TestSequentialEarlyExit:
    """Test early exit behavior in sequential mode."""

    def test_sequential_early_exit_on_detection(self):
        """Sequential exits early on detection."""
        first = MockDetector("first", is_injection=True, confidence=0.8)
        second = MockDetector("second", is_injection=False, confidence=0.2)

        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            threshold=0.7,
            ordering={"first": 1, "second": 2},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=[first, second])

        result = pipeline.scan("test input")

        assert result.early_exit is True
        assert result.detectors_run == 1
        assert second.call_count == 0

    def test_sequential_continues_on_low_confidence(self):
        """Sequential continues when confidence below threshold."""
        first = MockDetector("first", is_injection=True, confidence=0.4)
        second = MockDetector("second", is_injection=True, confidence=0.6)

        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            threshold=0.7,
            ordering={"first": 1, "second": 2},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.7)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=[first, second])

        pipeline.scan("test input")

        # Both should run since neither exceeds threshold
        assert first.call_count == 1
        assert second.call_count == 1

    def test_sequential_no_early_exit_on_non_injection(self):
        """Sequential continues when first detector returns non-injection."""
        first = MockDetector("first", is_injection=False, confidence=0.9)
        second = MockDetector("second", is_injection=True, confidence=0.8)

        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            threshold=0.5,
            ordering={"first": 1, "second": 2},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=[first, second])

        pipeline.scan("test input")

        # Both should run since first was non-injection
        assert first.call_count == 1
        assert second.call_count == 1


class TestSequentialLatency:
    """Test latency characteristics of sequential execution."""

    def test_sequential_latency_is_cumulative(self):
        """Sequential execution latency is sum of detector latencies."""
        detectors = [
            MockDetector("a", latency_ms=10),
            MockDetector("b", latency_ms=10),
            MockDetector("c", latency_ms=10),
        ]
        config = PipelineConfig(strategy=ExecutionStrategy.SEQUENTIAL)
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.9)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # Should be at least 30ms total
        assert result.total_latency_ms >= 30

    def test_sequential_early_exit_saves_time(self):
        """Early exit in sequential mode saves execution time."""
        fast = MockDetector("fast", is_injection=True, confidence=0.9, latency_ms=5)
        slow = MockDetector("slow", is_injection=False, confidence=0.2, latency_ms=100)

        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            threshold=0.7,
            ordering={"fast": 1, "slow": 2},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=[fast, slow])

        result = pipeline.scan("test input")

        # Should exit before slow detector
        assert result.total_latency_ms < 50


class TestSequentialErrorHandling:
    """Test error handling in sequential mode."""

    def test_sequential_continues_on_error(self):
        """Sequential continues after detector error."""

        class FailingDetector(Detector):
            @property
            def id(self) -> str:
                return "failing"

            def detect(self, text: str, trust_level: TrustLevel = TrustLevel.USER) -> DetectionResult:
                raise RuntimeError("Detector failure")

            def warmup(self) -> None:
                pass

            def health_check(self) -> bool:
                return False

        good = MockDetector("good", is_injection=True, confidence=0.8)

        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            continue_on_error=True,
            ordering={"failing": 1, "good": 2},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=[FailingDetector(), good])

        pipeline.scan("test input")

        # Should still get result from good detector
        assert good.call_count == 1


class TestSequentialWithRealAdapters:
    """Integration tests with real adapters in sequential mode."""

    def test_sequential_with_all_adapters(self):
        """Sequential execution with all real adapters."""
        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            ordering={"puppetry": 1, "piguard": 2, "llmguard": 3},
        )
        pipeline = Pipeline(config=config)
        pipeline.warmup()

        result = pipeline.scan("test with all adapters")

        assert result.strategy_used == "sequential"
        assert result.detectors_run == 4  # All run since no detection in stub mode

    def test_sequential_reports_strategy(self):
        """Sequential mode correctly reports strategy used."""
        config = PipelineConfig(strategy=ExecutionStrategy.SEQUENTIAL)
        pipeline = Pipeline(config=config)

        result = pipeline.scan("test input")

        assert result.strategy_used == "sequential"


class TestSequentialEdgeCases:
    """Edge cases for sequential execution."""

    def test_sequential_no_detectors(self):
        """Sequential handles empty detector list."""
        config = PipelineConfig(strategy=ExecutionStrategy.SEQUENTIAL)
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=[])

        result = pipeline.scan("test input")

        assert result.is_injection is False
        assert result.detectors_run == 0

    def test_sequential_single_detector(self):
        """Sequential works with single detector."""
        detector = MockDetector("only", is_injection=True, confidence=0.7)
        config = PipelineConfig(strategy=ExecutionStrategy.SEQUENTIAL)
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=[detector])

        result = pipeline.scan("test input")

        assert result.detectors_run == 1

    def test_sequential_default_ordering(self):
        """Sequential uses default ordering when not specified."""
        detectors = [
            MockDetector("a"),
            MockDetector("b"),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            ordering={},  # No explicit ordering
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.9)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert result.detectors_run == 2
