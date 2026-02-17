"""Integration tests for full end-to-end scan workflows."""

import pytest

from core.pipeline import ExecutionStrategy, PipelineConfig
from core.trust import TrustConfig, TrustLevelsConfig
from tests.integration.conftest import Pipeline


class TestFullScanWorkflow:
    """Test complete scan workflows from input to result."""

    @pytest.fixture
    def pipeline(self):
        """Provide a fully configured pipeline (stub mode)."""
        pipe = Pipeline()
        pipe.warmup()
        return pipe

    def test_full_scan_benign_input(self, pipeline):
        """Complete scan of benign input returns expected result."""
        result = pipeline.scan("Hello, what is the weather like today?")

        assert result.is_injection is False
        assert result.detectors_run == 4
        assert result.total_latency_ms > 0
        assert result.strategy_used in ["parallel", "sequential", "weighted"]

    def test_full_scan_with_source_context(self, pipeline):
        """Scan with source context applies correct trust level."""
        # User source
        user_result = pipeline.scan(
            "Tell me about Python programming",
            source="user/authenticated/123"
        )
        assert user_result.trust_level_used == "user"

        # External source
        external_result = pipeline.scan(
            "API request data",
            source="api/external/webhook"
        )
        assert external_result.trust_level_used == "external"

    def test_full_scan_returns_all_detector_results(self, pipeline):
        """Full scan returns individual results from all detectors."""
        result = pipeline.scan("Test all detector results")

        detector_ids = [r.detector_id for r in result.detector_results]
        assert "puppetry" in detector_ids
        assert "piguard" in detector_ids
        assert "llmguard" in detector_ids
        assert "pytector" in detector_ids

    def test_full_scan_tracks_flagging(self, pipeline):
        """Full scan correctly tracks which detectors flagged."""
        result = pipeline.scan("Test input")

        # In stub mode, no detectors should flag
        assert result.detectors_flagged == 0
        assert result.flagged is False


class TestFullScanTrustLevels:
    """Test full scans with different trust level configurations."""

    def test_scan_system_source_high_threshold(self):
        """System sources have high threshold (hard to flag)."""
        pipeline = Pipeline()
        result = pipeline.scan("System message", source="system/internal")

        # System trust level has 0.95 threshold
        assert result.trust_level_used == "system"
        assert result.flagged is False  # Hard to flag system sources

    def test_scan_unknown_source_low_threshold(self):
        """Unknown sources have low threshold (easy to flag)."""
        pipeline = Pipeline()
        result = pipeline.scan("Unknown input", source="random/untrusted")

        # Unknown trust level has 0.3 threshold
        assert result.trust_level_used == "unknown"

    def test_scan_external_source(self):
        """External sources have appropriate threshold."""
        pipeline = Pipeline()
        result = pipeline.scan("Webhook data", source="webhook/external")

        assert result.trust_level_used == "external"


class TestFullScanEdgeCases:
    """Test full scans with edge case inputs."""

    @pytest.fixture
    def pipeline(self):
        """Provide a fully configured pipeline."""
        return Pipeline()

    def test_scan_empty_string(self, pipeline):
        """Scan handles empty string."""
        result = pipeline.scan("")

        assert result is not None
        assert result.detectors_run > 0

    def test_scan_whitespace_only(self, pipeline):
        """Scan handles whitespace-only input."""
        result = pipeline.scan("   \n\t   ")

        assert result is not None

    def test_scan_very_long_input(self, pipeline):
        """Scan handles very long input."""
        long_text = "x" * 10_000
        result = pipeline.scan(long_text)

        assert result is not None
        assert result.detectors_run > 0

    def test_scan_unicode_input(self, pipeline):
        """Scan handles unicode input."""
        unicode_text = "Hello 世界 مرحبا 🌍"
        result = pipeline.scan(unicode_text)

        assert result is not None

    def test_scan_multiline_input(self, pipeline):
        """Scan handles multiline input."""
        multiline = """Line 1
        Line 2
        Line 3 with special chars: <>&"'
        """
        result = pipeline.scan(multiline)

        assert result is not None


class TestFullScanWithCustomConfig:
    """Test full scans with custom pipeline configurations."""

    def test_scan_with_sequential_strategy(self):
        """Scan with sequential strategy."""
        config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            ordering={"puppetry": 1, "piguard": 2, "llmguard": 3},
        )
        pipeline = Pipeline(config=config)

        result = pipeline.scan("Sequential test")

        assert result.strategy_used == "sequential"

    def test_scan_with_weighted_vote_strategy(self):
        """Scan with weighted vote strategy."""
        config = PipelineConfig(
            strategy=ExecutionStrategy.WEIGHTED_VOTE,
            detector_weights={"puppetry": 1.0, "piguard": 1.5, "llmguard": 2.0},
        )
        pipeline = Pipeline(config=config)

        result = pipeline.scan("Weighted vote test")

        assert result.detectors_run == 4

    def test_scan_with_custom_threshold(self):
        """Scan with custom threshold configuration."""
        config = PipelineConfig(threshold=0.9)
        trust_config = TrustLevelsConfig(
            levels={"strict": TrustConfig(threshold=0.9)},
            source_mapping={"*": "strict"},
        )
        pipeline = Pipeline(config=config, trust_config=trust_config)

        result = pipeline.scan("High threshold test")

        assert result.trust_level_used == "strict"


class TestFullScanHealthAndWarmup:
    """Test warmup and health check in full scan context."""

    def test_scan_after_warmup(self):
        """Scan works correctly after warmup."""
        pipeline = Pipeline()
        pipeline.warmup()

        result = pipeline.scan("Post-warmup test")

        assert result.detectors_run == 4

    def test_scan_without_warmup(self):
        """Scan triggers auto-warmup."""
        pipeline = Pipeline()
        # No explicit warmup

        result = pipeline.scan("Auto-warmup test")

        # Should still work (auto-warmup)
        assert result.detectors_run == 4

    def test_health_check_before_scan(self):
        """Health check shows all detectors healthy."""
        pipeline = Pipeline()
        health = pipeline.health_check()

        assert all(status is True for status in health.values())

        # Scan should still work
        result = pipeline.scan("Post-health-check test")
        assert result.detectors_run == 4


class TestFullScanResultIntegrity:
    """Test integrity of full scan results."""

    def test_result_fields_present(self):
        """All expected result fields are present."""
        pipeline = Pipeline()
        result = pipeline.scan("Field check test")

        # Check all fields exist
        assert hasattr(result, "is_injection")
        assert hasattr(result, "confidence")
        assert hasattr(result, "flagged")
        assert hasattr(result, "detector_results")
        assert hasattr(result, "detectors_run")
        assert hasattr(result, "detectors_flagged")
        assert hasattr(result, "total_latency_ms")
        assert hasattr(result, "trust_level_used")
        assert hasattr(result, "strategy_used")
        assert hasattr(result, "early_exit")
        assert hasattr(result, "errors")

    def test_confidence_in_valid_range(self):
        """Confidence is always in valid range [0, 1]."""
        pipeline = Pipeline()

        for _ in range(5):
            result = pipeline.scan("Range test")
            assert 0.0 <= result.confidence <= 1.0

    def test_latency_is_positive(self):
        """Latency measurement is always positive."""
        pipeline = Pipeline()
        result = pipeline.scan("Latency test")

        assert result.total_latency_ms > 0
        for detector_result in result.detector_results:
            assert detector_result.latency_ms >= 0
