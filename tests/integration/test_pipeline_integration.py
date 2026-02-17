"""Integration tests for pipeline with real adapters (in stub mode)."""

from core.pipeline import (
    ExecutionStrategy,
    PipelineConfig,
    load_pipeline_config,
)
from core.trust import load_trust_config
from tests.integration.conftest import Pipeline


class TestPipelineWithRealAdapters:
    """Integration tests using real detector adapters (in stub mode)."""

    def test_pipeline_loads_all_adapters(self):
        """Pipeline loads all available adapters."""
        pipeline = Pipeline()

        # Should have all four adapters
        detector_ids = [d.id for d in pipeline.detectors]
        assert "puppetry" in detector_ids
        assert "piguard" in detector_ids
        assert "llmguard" in detector_ids
        assert "pytector" in detector_ids

    def test_pipeline_scan_benign_input(self):
        """Scan benign input returns no injection."""
        pipeline = Pipeline()
        pipeline.warmup()

        result = pipeline.scan("Hello, how are you today?")

        assert result.is_injection is False
        assert result.detectors_run == 4

    def test_pipeline_scan_with_source(self):
        """Scan with different sources applies correct trust levels."""
        pipeline = Pipeline()
        pipeline.warmup()

        # System source should have high trust threshold
        result = pipeline.scan("Test input", source="system/internal")
        assert result.trust_level_used == "system"

        # User source should have lower threshold
        result = pipeline.scan("Test input", source="user/123")
        assert result.trust_level_used == "user"

        # Unknown source should have lowest threshold
        result = pipeline.scan("Test input", source="random/unknown")
        assert result.trust_level_used == "unknown"

    def test_pipeline_health_check(self):
        """Health check reports status of all detectors."""
        pipeline = Pipeline()

        health = pipeline.health_check()

        # All detectors should be healthy (even in stub mode)
        assert health["puppetry"] is True
        assert health["piguard"] is True
        assert health["llmguard"] is True

    def test_pipeline_parallel_latency(self):
        """Parallel execution completes within reasonable time."""
        pipeline = Pipeline()
        pipeline.warmup()

        result = pipeline.scan("Test latency measurement")

        # Stub mode should be very fast (<100ms)
        assert result.total_latency_ms < 100

    def test_pipeline_sequential_strategy(self):
        """Sequential strategy works with real adapters."""
        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            ordering={"puppetry": 1, "piguard": 2, "llmguard": 3},
        )
        pipeline = Pipeline(config=config)
        pipeline.warmup()

        result = pipeline.scan("Test sequential execution")

        assert result.strategy_used == "sequential"
        assert result.detectors_run == 4  # All run since no detection

    def test_pipeline_weighted_vote_strategy(self):
        """Weighted vote strategy works with real adapters."""
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

        result = pipeline.scan("Test weighted voting")

        assert result.detectors_run == 4


class TestPipelineConfigIntegration:
    """Tests for config loading integration."""

    def test_load_real_pipeline_config(self):
        """Load real pipeline.toml configuration."""
        config = load_pipeline_config()

        assert config.strategy == ExecutionStrategy.PARALLEL
        assert config.threshold == 0.7
        assert config.timeout_seconds == 30

    def test_load_real_trust_config(self):
        """Load real trust_levels.toml configuration."""
        config = load_trust_config()

        assert "user" in config.levels
        assert "system" in config.levels
        assert "unknown" in config.levels


class TestPipelineBenchmark:
    """Benchmark tests for pipeline performance."""

    def test_parallel_latency_under_100ms(self):
        """Parallel execution should complete under 100ms."""
        pipeline = Pipeline()
        pipeline.warmup()

        # Run multiple times and check latency
        for _ in range(5):
            result = pipeline.scan("Benchmark test input")
            assert result.total_latency_ms < 100, f"Latency exceeded 100ms: {result.total_latency_ms}ms"

    def test_warmup_improves_latency(self):
        """Warmup should ensure consistent latency."""
        pipeline = Pipeline()

        # First call without warmup
        pipeline.scan("First call")

        # Subsequent calls should be fast
        result2 = pipeline.scan("Second call")
        result3 = pipeline.scan("Third call")

        # All should be under 100ms
        assert result2.total_latency_ms < 100
        assert result3.total_latency_ms < 100
