"""Unit tests for core/trust.py."""


import pytest

from core.trust import (
    TrustConfig,
    TrustLevelsConfig,
    apply_trust_bias,
    get_trust_level_for_source,
    load_trust_config,
    should_flag,
)


class TestTrustConfig:
    """Tests for TrustConfig dataclass."""

    def test_basic_creation(self):
        """Create a basic trust config."""
        config = TrustConfig(
            threshold=0.7,
            min_detectors=2,
            bias=1.2,
            description="Test trust level",
            allow_override=False,
        )

        assert config.threshold == 0.7
        assert config.min_detectors == 2
        assert config.bias == 1.2
        assert config.description == "Test trust level"
        assert config.allow_override is False

    def test_defaults(self):
        """Default values are applied."""
        config = TrustConfig(threshold=0.5)

        assert config.min_detectors == 1
        assert config.bias == 1.0
        assert config.description == ""
        assert config.allow_override is True

    def test_threshold_validation_too_high(self):
        """Threshold above 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="threshold must be between"):
            TrustConfig(threshold=1.5)

    def test_threshold_validation_negative(self):
        """Negative threshold raises ValueError."""
        with pytest.raises(ValueError, match="threshold must be between"):
            TrustConfig(threshold=-0.1)

    def test_min_detectors_validation(self):
        """min_detectors below 1 raises ValueError."""
        with pytest.raises(ValueError, match="min_detectors must be at least 1"):
            TrustConfig(threshold=0.5, min_detectors=0)

    def test_bias_validation(self):
        """Non-positive bias raises ValueError."""
        with pytest.raises(ValueError, match="bias must be positive"):
            TrustConfig(threshold=0.5, bias=0)

        with pytest.raises(ValueError, match="bias must be positive"):
            TrustConfig(threshold=0.5, bias=-0.5)


class TestLoadTrustConfig:
    """Tests for load_trust_config function."""

    def test_load_default_config(self):
        """Load config from default location."""
        config = load_trust_config()

        assert isinstance(config, TrustLevelsConfig)
        assert len(config.levels) > 0
        assert "user" in config.levels
        assert "unknown" in config.levels

    def test_load_specific_path(self, tmp_path):
        """Load config from specific path."""
        config_content = """
[trust_levels.custom]
threshold = 0.6
description = "Custom level"
allow_override = true

[source_mapping]
"test/*" = "custom"

[policies]
log_below_threshold = false
default_action = "block"
"""
        config_file = tmp_path / "test_trust.toml"
        config_file.write_text(config_content)

        config = load_trust_config(config_file)

        assert "custom" in config.levels
        assert config.levels["custom"].threshold == 0.6
        assert config.levels["custom"].description == "Custom level"
        assert config.source_mapping.get("test/*") == "custom"
        assert config.log_below_threshold is False
        assert config.default_action == "block"

    def test_file_not_found(self, tmp_path):
        """FileNotFoundError when config doesn't exist."""
        with pytest.raises(FileNotFoundError):
            load_trust_config(tmp_path / "nonexistent.toml")


class TestGetTrustLevelForSource:
    """Tests for get_trust_level_for_source function."""

    def test_exact_pattern_match(self):
        """Match exact pattern."""
        config = TrustLevelsConfig(
            levels={"api": TrustConfig(threshold=0.5)},
            source_mapping={"api/*": "api"},
        )

        result = get_trust_level_for_source("api/webhook", config)
        assert result is not None
        assert result.threshold == 0.5

    def test_wildcard_fallback(self):
        """Fallback to wildcard pattern."""
        config = TrustLevelsConfig(
            levels={"default": TrustConfig(threshold=0.3)},
            source_mapping={"*": "default"},
        )

        result = get_trust_level_for_source("anything/here", config)
        assert result is not None
        assert result.threshold == 0.3

    def test_no_match(self):
        """Return None when no pattern matches."""
        config = TrustLevelsConfig(
            levels={"api": TrustConfig(threshold=0.5)},
            source_mapping={"api/*": "api"},  # No wildcard fallback
        )

        result = get_trust_level_for_source("user/123", config)
        assert result is None


class TestApplyTrustBias:
    """Tests for apply_trust_bias function."""

    def test_bias_increases_confidence(self):
        """Bias > 1 increases confidence."""
        config = TrustConfig(threshold=0.5, bias=1.5)
        result = apply_trust_bias(0.6, config)

        assert result == pytest.approx(0.9)  # 0.6 * 1.5 = 0.9

    def test_bias_decreases_confidence(self):
        """Bias < 1 decreases confidence."""
        config = TrustConfig(threshold=0.5, bias=0.5)
        result = apply_trust_bias(0.8, config)

        assert result == pytest.approx(0.4)  # 0.8 * 0.5 = 0.4

    def test_bias_clamps_to_max(self):
        """Result is clamped to 1.0."""
        config = TrustConfig(threshold=0.5, bias=2.0)
        result = apply_trust_bias(0.8, config)

        assert result == 1.0  # 0.8 * 2.0 = 1.6 -> clamped to 1.0

    def test_bias_clamps_to_min(self):
        """Result is clamped to 0.0 (edge case)."""
        # This shouldn't happen with valid bias, but test the clamp
        config = TrustConfig(threshold=0.5, bias=0.01)
        result = apply_trust_bias(0.0, config)

        assert result == 0.0


class TestShouldFlag:
    """Tests for should_flag function."""

    def test_above_threshold_flags(self):
        """Confidence above threshold should flag."""
        config = TrustConfig(threshold=0.7)
        assert should_flag(0.8, config) is True

    def test_below_threshold_no_flag(self):
        """Confidence below threshold should not flag."""
        config = TrustConfig(threshold=0.7)
        assert should_flag(0.5, config) is False

    def test_at_threshold_flags(self):
        """Confidence equal to threshold should flag."""
        config = TrustConfig(threshold=0.7)
        assert should_flag(0.7, config) is True

    def test_bias_affects_flag(self):
        """Bias is applied before threshold check."""
        config = TrustConfig(threshold=0.7, bias=0.5)
        # 0.8 * 0.5 = 0.4, which is below 0.7
        assert should_flag(0.8, config) is False

    def test_skip_bias(self):
        """Can skip bias application."""
        config = TrustConfig(threshold=0.7, bias=0.5)
        # Without bias, 0.8 > 0.7, so it flags
        assert should_flag(0.8, config, apply_bias=False) is True
