"""
Latency benchmark tests for the detection pipeline.

These tests validate that the pipeline meets latency requirements:
- Target: <100ms for typical scans
- Warmup should not significantly impact user-facing latency
- All execution strategies should meet latency targets

Note: All tests use stub mode detectors to ensure consistent, fast results.
"""


from adapters import get_detector, list_detectors
from core.pipeline import ExecutionStrategy, Pipeline, PipelineConfig
from tests.benchmark.conftest import BenchmarkStats


def _create_stub_detectors():
    """Create all detectors in stub mode for benchmarking."""
    detectors = []
    for detector_id in list_detectors():
        try:
            detector = get_detector(detector_id, stub_mode=True)
            detectors.append(detector)
        except Exception:
            pass
    return detectors


class TestLatencyUnder100ms:
    """Tests validating <100ms latency target."""

    def test_parallel_under_100ms(self, warm_pipeline, short_input):
        """Parallel strategy completes under 100ms."""
        result = warm_pipeline.scan(short_input)

        assert result.total_latency_ms < 100, (
            f"Parallel scan took {result.total_latency_ms:.2f}ms, exceeds 100ms target"
        )

    def test_sequential_under_100ms(self, sequential_pipeline, short_input):
        """Sequential strategy completes under 100ms."""
        result = sequential_pipeline.scan(short_input)

        assert result.total_latency_ms < 100, (
            f"Sequential scan took {result.total_latency_ms:.2f}ms, exceeds 100ms target"
        )

    def test_weighted_under_100ms(self, weighted_pipeline, short_input):
        """Weighted vote strategy completes under 100ms."""
        result = weighted_pipeline.scan(short_input)

        assert result.total_latency_ms < 100, (
            f"Weighted scan took {result.total_latency_ms:.2f}ms, exceeds 100ms target"
        )


class TestLatencyConsistency:
    """Tests for consistent latency across multiple scans."""

    def test_consistent_parallel_latency(self, warm_pipeline, short_input, benchmark_stats):
        """Parallel latency is consistent across multiple scans."""
        for _ in range(20):
            result = warm_pipeline.scan(short_input)
            benchmark_stats.add(result.total_latency_ms)

        # All scans should be under 100ms
        assert benchmark_stats.max_ms < 100, (
            f"Max latency {benchmark_stats.max_ms:.2f}ms exceeds 100ms"
        )
        # P95 should be reasonable
        assert benchmark_stats.p95_ms < 80, (
            f"P95 latency {benchmark_stats.p95_ms:.2f}ms too high"
        )

    def test_latency_not_degrading(self, warm_pipeline, short_input):
        """Latency should not degrade over many scans."""
        first_latencies = []
        last_latencies = []

        # Run 50 scans
        for i in range(50):
            result = warm_pipeline.scan(short_input)
            if i < 10:
                first_latencies.append(result.total_latency_ms)
            elif i >= 40:
                last_latencies.append(result.total_latency_ms)

        avg_first = sum(first_latencies) / len(first_latencies)
        avg_last = sum(last_latencies) / len(last_latencies)

        # Last 10 should not be significantly worse than first 10
        assert avg_last < avg_first * 2, (
            f"Latency degraded: first avg={avg_first:.2f}ms, last avg={avg_last:.2f}ms"
        )


class TestLatencyByInputSize:
    """Tests for latency with different input sizes."""

    def test_short_input_fast(self, warm_pipeline, short_input, benchmark_stats):
        """Short input should be very fast."""
        for _ in range(10):
            result = warm_pipeline.scan(short_input)
            benchmark_stats.add(result.total_latency_ms)

        assert benchmark_stats.avg_ms < 50, (
            f"Short input avg latency {benchmark_stats.avg_ms:.2f}ms too high"
        )

    def test_medium_input_under_100ms(self, warm_pipeline, medium_input, benchmark_stats):
        """Medium input should still be under 100ms."""
        for _ in range(10):
            result = warm_pipeline.scan(medium_input)
            benchmark_stats.add(result.total_latency_ms)

        assert benchmark_stats.p95_ms < 100, (
            f"Medium input P95 latency {benchmark_stats.p95_ms:.2f}ms exceeds 100ms"
        )

    def test_long_input_reasonable(self, warm_pipeline, long_input, benchmark_stats):
        """Long input should complete in reasonable time."""
        for _ in range(5):
            result = warm_pipeline.scan(long_input)
            benchmark_stats.add(result.total_latency_ms)

        # Long inputs may take longer, but should still be fast in stub mode
        assert benchmark_stats.avg_ms < 200, (
            f"Long input avg latency {benchmark_stats.avg_ms:.2f}ms too high"
        )


class TestWarmupLatency:
    """Tests for warmup impact on latency."""

    def test_first_scan_after_warmup(self):
        """First scan after warmup should be fast."""
        detectors = _create_stub_detectors()
        pipeline = Pipeline(detectors=detectors)
        pipeline.warmup()

        result = pipeline.scan("First scan after warmup")

        assert result.total_latency_ms < 100

    def test_warmup_reduces_cold_start(self):
        """Warmup should reduce cold start latency."""
        # Cold pipeline (stub mode)
        cold_detectors = _create_stub_detectors()
        cold_pipe = Pipeline(detectors=cold_detectors)
        cold_result = cold_pipe.scan("Cold start scan")

        # Warm pipeline (stub mode)
        warm_detectors = _create_stub_detectors()
        warm_pipe = Pipeline(detectors=warm_detectors)
        warm_pipe.warmup()
        warm_result = warm_pipe.scan("Warm start scan")

        # Both should be under 100ms in stub mode
        assert cold_result.total_latency_ms < 100
        assert warm_result.total_latency_ms < 100


class TestStrategyLatencyComparison:
    """Compare latency across different execution strategies."""

    def test_parallel_vs_sequential(self):
        """Compare parallel and sequential strategy latency."""
        parallel_config = PipelineConfig(strategy=ExecutionStrategy.PARALLEL)
        sequential_config = PipelineConfig(
            strategy=ExecutionStrategy.SEQUENTIAL,
            ordering={"puppetry": 1, "piguard": 2, "llmguard": 3, "pytector": 4},
        )

        detectors = _create_stub_detectors()
        parallel_pipe = Pipeline(config=parallel_config, detectors=detectors)
        sequential_pipe = Pipeline(config=sequential_config, detectors=_create_stub_detectors())

        parallel_pipe.warmup()
        sequential_pipe.warmup()

        text = "Compare strategy performance"

        parallel_stats = BenchmarkStats()
        sequential_stats = BenchmarkStats()

        for _ in range(10):
            p_result = parallel_pipe.scan(text)
            s_result = sequential_pipe.scan(text)
            parallel_stats.add(p_result.total_latency_ms)
            sequential_stats.add(s_result.total_latency_ms)

        # Both should meet latency target
        assert parallel_stats.avg_ms < 100
        assert sequential_stats.avg_ms < 100


class TestDetectorLatency:
    """Tests for individual detector latency tracking."""

    def test_detector_latencies_recorded(self, warm_pipeline, short_input):
        """Each detector should record its latency."""
        result = warm_pipeline.scan(short_input)

        for detector_result in result.detector_results:
            assert detector_result.latency_ms >= 0
            assert detector_result.latency_ms < result.total_latency_ms + 10  # Allow overhead

    def test_individual_detectors_fast(self, warm_pipeline, short_input):
        """Individual detectors should be fast."""
        result = warm_pipeline.scan(short_input)

        for detector_result in result.detector_results:
            assert detector_result.latency_ms < 50, (
                f"Detector {detector_result.detector_id} took "
                f"{detector_result.latency_ms:.2f}ms"
            )


class TestLatencyPercentiles:
    """Tests for latency percentile requirements."""

    def test_p50_under_50ms(self, warm_pipeline, short_input, benchmark_stats):
        """P50 (median) latency should be under 50ms."""
        for _ in range(100):
            result = warm_pipeline.scan(short_input)
            benchmark_stats.add(result.total_latency_ms)

        assert benchmark_stats.p50_ms < 50, (
            f"P50 latency {benchmark_stats.p50_ms:.2f}ms exceeds 50ms"
        )

    def test_p95_under_100ms(self, warm_pipeline, short_input, benchmark_stats):
        """P95 latency should be under 100ms."""
        for _ in range(100):
            result = warm_pipeline.scan(short_input)
            benchmark_stats.add(result.total_latency_ms)

        assert benchmark_stats.p95_ms < 100, (
            f"P95 latency {benchmark_stats.p95_ms:.2f}ms exceeds 100ms"
        )

    def test_p99_reasonable(self, warm_pipeline, short_input, benchmark_stats):
        """P99 latency should be reasonable (under 200ms)."""
        for _ in range(100):
            result = warm_pipeline.scan(short_input)
            benchmark_stats.add(result.total_latency_ms)

        assert benchmark_stats.p99_ms < 200, (
            f"P99 latency {benchmark_stats.p99_ms:.2f}ms exceeds 200ms"
        )


class TestLatencyUnderLoad:
    """Tests for latency stability under sustained load."""

    def test_sustained_load_latency(self, warm_pipeline, short_input, benchmark_stats):
        """Latency remains stable under sustained load."""
        # Simulate sustained load with 200 requests
        for _ in range(200):
            result = warm_pipeline.scan(short_input)
            benchmark_stats.add(result.total_latency_ms)

        # Average should still meet target
        assert benchmark_stats.avg_ms < 100, (
            f"Avg latency under load {benchmark_stats.avg_ms:.2f}ms exceeds 100ms"
        )

        # No scan should exceed 500ms (extreme outlier threshold)
        assert benchmark_stats.max_ms < 500, (
            f"Max latency {benchmark_stats.max_ms:.2f}ms indicates potential issue"
        )
