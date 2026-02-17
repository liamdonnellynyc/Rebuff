"""Unit tests for pipeline configuration loading."""



from core.pipeline import (
    AggregationMethod,
    ExecutionStrategy,
    PipelineConfig,
    load_pipeline_config,
)


class TestPipelineConfigValidation:
    """Tests for PipelineConfig validation."""

    def test_default_config_is_valid(self):
        """Default config should pass validation."""
        config = PipelineConfig()

        assert config.strategy in ExecutionStrategy
        assert config.aggregation_method in AggregationMethod
        assert 0.0 <= config.threshold <= 1.0
        assert config.timeout_seconds > 0
        assert config.detector_timeout_seconds > 0

    def test_early_exit_threshold_above_threshold(self):
        """Early exit threshold should be above base threshold."""
        config = PipelineConfig(
            threshold=0.7,
            early_exit_threshold=0.90,
        )

        assert config.early_exit_threshold >= config.threshold

    def test_detector_timeout_less_than_pipeline(self):
        """Detector timeout should be less than pipeline timeout."""
        config = PipelineConfig(
            timeout_seconds=30.0,
            detector_timeout_seconds=10.0,
        )

        assert config.detector_timeout_seconds <= config.timeout_seconds


class TestLoadPipelineConfigFromToml:
    """Tests for loading pipeline config from TOML files."""

    def test_load_with_all_sections(self, tmp_path):
        """Load TOML with all config sections."""
        config_content = """
[pipeline]
strategy = "sequential"
timeout_seconds = 45
early_exit_threshold = 0.95

[aggregation]
method = "voting"
threshold = 0.65

[defaults]
detector_timeout_seconds = 8
continue_on_error = true

[ordering]
heuristic = 1
ml_fast = 2
ml_slow = 3

[detector_weights]
heuristic = 0.8
ml_fast = 1.0
ml_slow = 1.5
"""
        config_file = tmp_path / "pipeline.toml"
        config_file.write_text(config_content)

        config = load_pipeline_config(config_file)

        assert config.strategy == ExecutionStrategy.SEQUENTIAL
        assert config.timeout_seconds == 45.0
        assert config.early_exit_threshold == 0.95
        assert config.aggregation_method == AggregationMethod.VOTING
        assert config.threshold == 0.65
        assert config.detector_timeout_seconds == 8.0
        assert config.continue_on_error is True
        assert config.ordering == {"heuristic": 1, "ml_fast": 2, "ml_slow": 3}
        assert config.detector_weights == {"heuristic": 0.8, "ml_fast": 1.0, "ml_slow": 1.5}

    def test_load_with_minimal_config(self, tmp_path):
        """Load TOML with minimal config uses defaults."""
        config_content = """
[pipeline]
strategy = "parallel"
"""
        config_file = tmp_path / "pipeline.toml"
        config_file.write_text(config_content)

        config = load_pipeline_config(config_file)

        assert config.strategy == ExecutionStrategy.PARALLEL
        assert config.timeout_seconds == 30.0  # default
        assert config.threshold == 0.7  # default

    def test_load_with_weighted_strategy(self, tmp_path):
        """Load TOML with weighted vote strategy."""
        config_content = """
[pipeline]
strategy = "weighted"

[detector_weights]
puppetry = 1.0
piguard = 1.5
llmguard = 2.0
"""
        config_file = tmp_path / "pipeline.toml"
        config_file.write_text(config_content)

        config = load_pipeline_config(config_file)

        assert config.strategy == ExecutionStrategy.WEIGHTED_VOTE
        assert config.detector_weights["puppetry"] == 1.0
        assert config.detector_weights["piguard"] == 1.5
        assert config.detector_weights["llmguard"] == 2.0

    def test_load_with_invalid_strategy_uses_default(self, tmp_path):
        """Invalid strategy string falls back to parallel."""
        config_content = """
[pipeline]
strategy = "invalid_strategy_name"
"""
        config_file = tmp_path / "pipeline.toml"
        config_file.write_text(config_content)

        config = load_pipeline_config(config_file)

        assert config.strategy == ExecutionStrategy.PARALLEL

    def test_load_with_invalid_aggregation_uses_default(self, tmp_path):
        """Invalid aggregation method falls back to weighted."""
        config_content = """
[aggregation]
method = "invalid_method"
"""
        config_file = tmp_path / "pipeline.toml"
        config_file.write_text(config_content)

        config = load_pipeline_config(config_file)

        assert config.aggregation_method == AggregationMethod.WEIGHTED


class TestLoadPipelineConfigFromDefaultLocation:
    """Tests for loading config from default location."""

    def test_load_default_config_exists(self):
        """Default config file exists and loads."""
        config = load_pipeline_config()

        assert isinstance(config, PipelineConfig)
        assert config.strategy == ExecutionStrategy.PARALLEL

    def test_default_config_values(self):
        """Default config has expected values."""
        config = load_pipeline_config()

        assert config.threshold == 0.7
        assert config.timeout_seconds == 30
        assert config.detector_timeout_seconds == 10


class TestPipelineConfigOrdering:
    """Tests for detector ordering configuration."""

    def test_ordering_as_dict(self):
        """Ordering is stored as detector_id -> priority dict."""
        config = PipelineConfig(
            ordering={"fast": 1, "medium": 2, "slow": 3}
        )

        assert config.ordering["fast"] == 1
        assert config.ordering["medium"] == 2
        assert config.ordering["slow"] == 3

    def test_empty_ordering_is_valid(self):
        """Empty ordering dict is valid (use default order)."""
        config = PipelineConfig(ordering={})

        assert config.ordering == {}

    def test_ordering_priority_values(self, tmp_path):
        """Ordering priority values are integers."""
        config_content = """
[ordering]
first = 1
second = 2
third = 3
"""
        config_file = tmp_path / "pipeline.toml"
        config_file.write_text(config_content)

        config = load_pipeline_config(config_file)

        assert isinstance(config.ordering["first"], int)
        assert config.ordering["first"] == 1


class TestPipelineConfigDetectorWeights:
    """Tests for detector weights configuration."""

    def test_weights_as_floats(self):
        """Weights should be stored as floats."""
        config = PipelineConfig(
            detector_weights={"accurate": 2.0, "fast": 1.0, "inaccurate": 0.5}
        )

        assert isinstance(config.detector_weights["accurate"], float)
        assert config.detector_weights["accurate"] == 2.0

    def test_empty_weights_is_valid(self):
        """Empty weights dict uses default weight of 1.0."""
        config = PipelineConfig(detector_weights={})

        assert config.detector_weights == {}
