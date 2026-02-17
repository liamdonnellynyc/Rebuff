"""Integration tests for parallel pipeline execution strategy."""


from adapters.base import DetectionResult, Detector, TrustLevel
from core.pipeline import (
    ExecutionStrategy,
    PipelineConfig,
)
from core.trust import TrustConfig, TrustLevelsConfig
from tests.integration.conftest import Pipeline


class MockDetector(Detector):
    """Mock detector for testing parallel execution."""

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

    @property
    def id(self) -> str:
        return self._id

    def detect(self, text: str, trust_level: TrustLevel = TrustLevel.USER) -> DetectionResult:
        import time
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


class TestParallelExecutionBasic:
    """Basic tests for parallel execution strategy."""

    def test_parallel_runs_all_detectors(self):
        """Parallel strategy runs all detectors."""
        detectors = [
            MockDetector("a", confidence=0.3),
            MockDetector("b", confidence=0.4),
            MockDetector("c", confidence=0.5),
        ]
        config = PipelineConfig(strategy=ExecutionStrategy.PARALLEL)
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.9)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert result.detectors_run == 3  # 3 mock detectors
        assert len(result.detector_results) == 3

    def test_parallel_aggregates_results(self):
        """Parallel strategy aggregates results from all detectors."""
        detectors = [
            MockDetector("a", is_injection=True, confidence=0.8),
            MockDetector("b", is_injection=False, confidence=0.2),
        ]
        config = PipelineConfig(strategy=ExecutionStrategy.PARALLEL)
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5, bias=1.0)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert result.is_injection is True
        assert result.detectors_flagged == 1


class TestParallelConcurrency:
    """Test concurrent execution in parallel mode."""

    def test_parallel_faster_than_sequential(self):
        """Parallel execution should be faster than total detector time."""
        detectors = [
            MockDetector("a", latency_ms=20),
            MockDetector("b", latency_ms=20),
            MockDetector("c", latency_ms=20),
        ]
        config = PipelineConfig(strategy=ExecutionStrategy.PARALLEL)
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # Sequential would be 60ms minimum, parallel should be ~20ms + overhead
        assert result.total_latency_ms < 50


class TestParallelEarlyExit:
    """Test early exit behavior in parallel mode."""

    def test_parallel_early_exit_on_high_confidence(self):
        """Parallel exits early on high confidence detection."""
        detectors = [
            MockDetector("fast", is_injection=True, confidence=0.95, latency_ms=1),
            MockDetector("slow", is_injection=False, confidence=0.2, latency_ms=100),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.PARALLEL,
            early_exit_threshold=0.90,
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert result.early_exit is True
        assert result.is_injection is True

    def test_parallel_no_early_exit_below_threshold(self):
        """Parallel continues when detection below early exit threshold."""
        detectors = [
            MockDetector("medium", is_injection=True, confidence=0.75),
            MockDetector("low", is_injection=False, confidence=0.3),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.PARALLEL,
            early_exit_threshold=0.90,
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert result.detectors_run == 2


class TestParallelErrorHandling:
    """Test error handling in parallel mode."""

    def test_parallel_continues_on_detector_error(self):
        """Parallel continues when one detector fails."""

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

        detectors = [
            MockDetector("good", is_injection=True, confidence=0.8),
            FailingDetector(),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.PARALLEL,
            continue_on_error=True,
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # Should still have result from good detector
        assert result.detectors_run == 2
        assert result.is_injection is True


class TestParallelWithRealAdapters:
    """Integration tests with real adapters in stub mode."""

    def test_parallel_with_all_adapters(self):
        """Parallel execution with all real adapters."""
        pipeline = Pipeline()
        pipeline.warmup()

        result = pipeline.scan("test with all adapters")

        assert result.detectors_run == 4
        assert result.strategy_used == "parallel"

    def test_parallel_with_trust_source(self):
        """Parallel execution respects trust source."""
        pipeline = Pipeline()

        result = pipeline.scan("test input", source="user/123")

        assert result.trust_level_used == "user"

    def test_parallel_health_check(self):
        """All detectors report healthy in parallel mode."""
        pipeline = Pipeline()
        health = pipeline.health_check()

        assert all(health.values())


class TestParallelEmptyAndEdgeCases:
    """Edge cases for parallel execution."""

    def test_parallel_no_detectors(self):
        """Parallel handles empty detector list."""
        config = PipelineConfig(strategy=ExecutionStrategy.PARALLEL)
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=[])

        result = pipeline.scan("test input")

        assert result.is_injection is False
        assert result.detectors_run == 0

    def test_parallel_single_detector(self):
        """Parallel works with single detector."""
        detectors = [MockDetector("only", is_injection=True, confidence=0.7)]
        config = PipelineConfig(strategy=ExecutionStrategy.PARALLEL)
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert result.detectors_run == 1
        assert result.is_injection is True

    def test_parallel_empty_input(self):
        """Parallel handles empty input."""
        pipeline = Pipeline()
        result = pipeline.scan("")

        assert result is not None
