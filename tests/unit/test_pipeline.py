"""Unit tests for core/pipeline.py."""

import time

import pytest

from adapters.base import DetectionResult, Detector, TrustLevel
from core.pipeline import (
    AggregationMethod,
    ExecutionStrategy,
    Pipeline,
    PipelineConfig,
    PipelineResult,
    load_pipeline_config,
)
from core.trust import TrustConfig, TrustLevelsConfig


class MockDetector(Detector):
    """Mock detector for testing."""

    def __init__(
        self,
        detector_id: str = "mock",
        is_injection: bool = False,
        confidence: float = 0.5,
        latency_ms: float = 1.0,
        should_fail: bool = False,
    ) -> None:
        self._id = detector_id
        self._is_injection = is_injection
        self._confidence = confidence
        self._latency_ms = latency_ms
        self._should_fail = should_fail
        self._detect_count = 0

    @property
    def id(self) -> str:
        return self._id

    def detect(self, text: str, trust_level: TrustLevel = TrustLevel.USER) -> DetectionResult:
        self._detect_count += 1
        if self._should_fail:
            raise RuntimeError("Mock detector failure")
        time.sleep(self._latency_ms / 1000)  # Simulate latency
        return DetectionResult(
            is_injection=self._is_injection,
            confidence=self._confidence,
            category="mock",
            explanation="Mock detection",
            latency_ms=self._latency_ms,
            detector_id=self._id,
        )

    def warmup(self) -> None:
        pass

    def health_check(self) -> bool:
        return not self._should_fail


class TestPipelineConfig:
    """Tests for PipelineConfig dataclass."""

    def test_default_values(self):
        """Default values are set correctly."""
        config = PipelineConfig()

        assert config.strategy == ExecutionStrategy.PARALLEL
        assert config.timeout_seconds == 30.0
        assert config.detector_timeout_seconds == 10.0
        assert config.continue_on_error is True
        assert config.aggregation_method == AggregationMethod.WEIGHTED
        assert config.threshold == 0.7
        assert config.early_exit_threshold == 0.90

    def test_custom_values(self):
        """Custom values are preserved."""
        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            timeout_seconds=60.0,
            threshold=0.8,
            ordering={"heuristic": 1, "ml": 2},
        )

        assert config.strategy == ExecutionStrategy.SEQUENTIAL
        assert config.timeout_seconds == 60.0
        assert config.threshold == 0.8
        assert config.ordering == {"heuristic": 1, "ml": 2}


class TestLoadPipelineConfig:
    """Tests for load_pipeline_config function."""

    def test_load_default_config(self):
        """Load config from default location."""
        config = load_pipeline_config()

        assert isinstance(config, PipelineConfig)
        assert config.strategy == ExecutionStrategy.PARALLEL
        assert config.threshold == 0.7

    def test_load_specific_path(self, tmp_path):
        """Load config from specific path."""
        config_content = """
[pipeline]
strategy = "sequential"
timeout_seconds = 60

[aggregation]
method = "max"
threshold = 0.9

[defaults]
detector_timeout_seconds = 5
continue_on_error = false

[ordering]
fast = 1
slow = 2
"""
        config_file = tmp_path / "test_pipeline.toml"
        config_file.write_text(config_content)

        config = load_pipeline_config(config_file)

        assert config.strategy == ExecutionStrategy.SEQUENTIAL
        assert config.timeout_seconds == 60.0
        assert config.aggregation_method == AggregationMethod.MAX
        assert config.threshold == 0.9
        assert config.detector_timeout_seconds == 5.0
        assert config.continue_on_error is False
        assert config.ordering == {"fast": 1, "slow": 2}

    def test_file_not_found(self, tmp_path):
        """FileNotFoundError when config doesn't exist."""
        with pytest.raises(FileNotFoundError):
            load_pipeline_config(tmp_path / "nonexistent.toml")


class TestPipelineResult:
    """Tests for PipelineResult dataclass."""

    def test_basic_creation(self):
        """Create a basic pipeline result."""
        result = PipelineResult(
            is_injection=True,
            confidence=0.85,
            flagged=True,
        )

        assert result.is_injection is True
        assert result.confidence == 0.85
        assert result.flagged is True
        assert result.detectors_run == 0
        assert result.detectors_flagged == 0
        assert result.errors == []

    def test_with_detector_results(self):
        """Create result with detector results."""
        detector_results = [
            DetectionResult(is_injection=True, confidence=0.9, detector_id="a"),
            DetectionResult(is_injection=False, confidence=0.2, detector_id="b"),
        ]

        result = PipelineResult(
            is_injection=True,
            confidence=0.55,
            flagged=True,
            detector_results=detector_results,
            detectors_run=2,
            detectors_flagged=1,
        )

        assert len(result.detector_results) == 2
        assert result.detectors_run == 2
        assert result.detectors_flagged == 1


class TestPipeline:
    """Tests for Pipeline class."""

    def test_initialization_with_config(self):
        """Initialize pipeline with custom config."""
        config = PipelineConfig(strategy=ExecutionStrategy.SEQUENTIAL)
        pipeline = Pipeline(config=config, detectors=[])

        assert pipeline.config.strategy == ExecutionStrategy.SEQUENTIAL

    def test_initialization_with_detectors(self):
        """Initialize pipeline with custom detectors."""
        detectors = [MockDetector("a"), MockDetector("b")]
        pipeline = Pipeline(detectors=detectors)

        assert len(pipeline.detectors) == 2
        assert pipeline.detectors[0].id == "a"

    def test_warmup(self):
        """Warmup calls warmup on all detectors."""
        mock = MockDetector()
        pipeline = Pipeline(detectors=[mock])

        pipeline.warmup()

        # Verify detector was called
        assert pipeline._warmed_up is True

    def test_health_check(self):
        """Health check returns status for all detectors."""
        healthy = MockDetector("healthy", should_fail=False)
        unhealthy = MockDetector("unhealthy", should_fail=True)
        pipeline = Pipeline(detectors=[healthy, unhealthy])

        health = pipeline.health_check()

        assert health["healthy"] is True
        assert health["unhealthy"] is False


class TestPipelineParallelExecution:
    """Tests for parallel execution strategy."""

    def test_parallel_runs_all_detectors(self):
        """Parallel strategy runs all detectors."""
        detectors = [
            MockDetector("a", is_injection=False, confidence=0.3),
            MockDetector("b", is_injection=True, confidence=0.8),
            MockDetector("c", is_injection=False, confidence=0.2),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.PARALLEL,
            threshold=0.5,
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert result.detectors_run == 3  # 3 mock detectors
        assert result.is_injection is True
        assert len(result.detector_results) == 3

    def test_parallel_early_exit_high_confidence(self):
        """Parallel strategy exits early on high confidence detection."""
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

    def test_parallel_continues_on_error(self):
        """Parallel strategy continues when detector fails."""
        detectors = [
            MockDetector("good", is_injection=True, confidence=0.8),
            MockDetector("bad", should_fail=True),
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

        # Should still get result from good detector
        assert result.detectors_run == 2  # Both attempted
        assert result.is_injection is True


class TestPipelineSequentialExecution:
    """Tests for sequential execution strategy."""

    def test_sequential_respects_ordering(self):
        """Sequential strategy respects detector ordering."""
        detectors = [
            MockDetector("slow", is_injection=False, confidence=0.2),
            MockDetector("fast", is_injection=False, confidence=0.3),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            ordering={"fast": 1, "slow": 2},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.9)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # Both should run since no detection
        assert result.detectors_run == 2

    def test_sequential_early_exit_on_detection(self):
        """Sequential strategy exits on first detection."""
        detectors = [
            MockDetector("first", is_injection=True, confidence=0.8),
            MockDetector("second", is_injection=False, confidence=0.2),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            threshold=0.7,
            ordering={"first": 1, "second": 2},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert result.early_exit is True
        assert result.detectors_run == 1


class TestPipelineWeightedVote:
    """Tests for weighted voting strategy."""

    def test_weighted_vote_uses_weights(self):
        """Weighted voting applies detector weights."""
        detectors = [
            MockDetector("accurate", is_injection=True, confidence=0.9),
            MockDetector("inaccurate", is_injection=False, confidence=0.1),
        ]
        config = PipelineConfig(
            strategy=ExecutionStrategy.WEIGHTED_VOTE,
            detector_weights={"accurate": 2.0, "inaccurate": 0.5},
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # Weighted average: (0.9*2 + 0.1*0.5) / (2 + 0.5) = 1.85/2.5 = 0.74
        assert result.is_injection is True  # accurate has higher weight


class TestPipelineAggregation:
    """Tests for result aggregation methods."""

    def test_max_aggregation(self):
        """MAX aggregation takes highest confidence."""
        detectors = [
            MockDetector("low", is_injection=True, confidence=0.3),
            MockDetector("high", is_injection=True, confidence=0.9),
        ]
        config = PipelineConfig(
            aggregation_method=AggregationMethod.MAX,
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5, bias=1.0)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert result.confidence == pytest.approx(0.9)

    def test_average_aggregation(self):
        """AVERAGE aggregation averages confidences."""
        detectors = [
            MockDetector("a", is_injection=True, confidence=0.4),
            MockDetector("b", is_injection=True, confidence=0.6),
        ]
        config = PipelineConfig(
            aggregation_method=AggregationMethod.AVERAGE,
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.4, bias=1.0)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert result.confidence == pytest.approx(0.5)

    def test_voting_aggregation(self):
        """VOTING aggregation uses majority vote."""
        detectors = [
            MockDetector("a", is_injection=True, confidence=0.8),
            MockDetector("b", is_injection=True, confidence=0.7),
            MockDetector("c", is_injection=False, confidence=0.3),
        ]
        config = PipelineConfig(
            aggregation_method=AggregationMethod.VOTING,
        )
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5, bias=1.0)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # 2/3 flagged = 0.667 confidence
        assert result.confidence == pytest.approx(2/3)
        assert result.is_injection is True


class TestPipelineTrustThreshold:
    """Tests for trust-based threshold application."""

    def test_trust_threshold_applied(self):
        """Trust threshold is applied correctly."""
        detectors = [MockDetector("test", is_injection=True, confidence=0.6)]
        config = PipelineConfig()
        trust_config = TrustLevelsConfig(
            levels={"high_trust": TrustConfig(threshold=0.9)},
            source_mapping={"system/*": "high_trust"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input", source="system/internal")

        # 0.6 < 0.9 threshold, so should not flag
        assert result.flagged is False
        assert result.trust_level_used == "high_trust"

    def test_low_trust_easier_to_flag(self):
        """Lower trust sources are easier to flag."""
        detectors = [MockDetector("test", is_injection=True, confidence=0.5)]
        config = PipelineConfig()
        trust_config = TrustLevelsConfig(
            levels={"low_trust": TrustConfig(threshold=0.3)},
            source_mapping={"external/*": "low_trust"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input", source="external/api")

        # 0.5 > 0.3 threshold, should flag
        assert result.flagged is True
        assert result.trust_level_used == "low_trust"

    def test_min_detectors_requirement(self):
        """Min detectors requirement is enforced."""
        detectors = [
            MockDetector("a", is_injection=True, confidence=0.8),
            MockDetector("b", is_injection=False, confidence=0.2),
        ]
        config = PipelineConfig()
        trust_config = TrustLevelsConfig(
            levels={"strict": TrustConfig(threshold=0.5, min_detectors=2)},
            source_mapping={"*": "strict"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        # Only 1 detector flagged, need 2
        assert result.flagged is False
        assert result.detectors_flagged == 1


class TestPipelineLatency:
    """Tests for latency tracking."""

    def test_total_latency_tracked(self):
        """Total latency is recorded."""
        detectors = [MockDetector("test", latency_ms=10)]
        config = PipelineConfig()
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert result.total_latency_ms > 0

    def test_detector_latency_tracked(self):
        """Individual detector latency is recorded."""
        detectors = [MockDetector("test", latency_ms=5)]
        config = PipelineConfig()
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("test input")

        assert len(result.detector_results) == 1
        assert result.detector_results[0].latency_ms >= 5


class TestPipelineEmptyInput:
    """Tests for edge cases with empty or minimal input."""

    def test_empty_content(self):
        """Handle empty content."""
        detectors = [MockDetector("test")]
        config = PipelineConfig()
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=detectors)

        result = pipeline.scan("")

        assert result is not None
        assert result.detectors_run == 1

    def test_no_detectors(self):
        """Handle no detectors configured."""
        config = PipelineConfig()
        trust_config = TrustLevelsConfig(
            levels={"unknown": TrustConfig(threshold=0.5)},
            source_mapping={"*": "unknown"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config, detectors=[])

        result = pipeline.scan("test input")

        assert result.is_injection is False
        assert result.confidence == 0.0
        assert result.detectors_run == 0
