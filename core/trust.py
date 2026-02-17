"""
Trust configuration and bias application for detection thresholds.

Loads trust levels from trust_levels.toml and provides functions to
apply trust-based bias to detection confidence scores.
"""

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # Python < 3.11 fallback


@dataclass
class TrustConfig:
    """Configuration for a trust level.

    Attributes:
        threshold: Confidence threshold required to flag an injection.
                   Higher threshold = more permissive (harder to flag).
        min_detectors: Minimum number of detectors that must agree.
        bias: Multiplier applied to confidence scores. Values > 1 increase
              sensitivity, values < 1 decrease sensitivity.
        description: Human-readable description of this trust level.
        allow_override: Whether this trust level can be overridden per-request.
    """
    threshold: float
    min_detectors: int = 1
    bias: float = 1.0
    description: str = ""
    allow_override: bool = True

    def __post_init__(self) -> None:
        """Validate configuration values."""
        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError(f"threshold must be between 0.0 and 1.0, got {self.threshold}")
        if self.min_detectors < 1:
            raise ValueError(f"min_detectors must be at least 1, got {self.min_detectors}")
        if self.bias <= 0:
            raise ValueError(f"bias must be positive, got {self.bias}")


@dataclass
class TrustLevelsConfig:
    """Complete trust levels configuration loaded from TOML.

    Attributes:
        levels: Mapping of trust level name to TrustConfig.
        source_mapping: Mapping of source patterns to trust level names.
        log_below_threshold: Whether to log inputs below threshold.
        default_action: Action to take on detection (block, warn, log).
    """
    levels: dict[str, TrustConfig] = field(default_factory=dict)
    source_mapping: dict[str, str] = field(default_factory=dict)
    log_below_threshold: bool = True
    default_action: str = "warn"


def load_trust_config(config_path: Path | None = None) -> TrustLevelsConfig:
    """Load trust configuration from TOML file.

    Args:
        config_path: Path to trust_levels.toml. If None, looks for
                     config/trust_levels.toml relative to package root.

    Returns:
        Populated TrustLevelsConfig instance.

    Raises:
        FileNotFoundError: If config file doesn't exist.
        ValueError: If config file has invalid structure.
    """
    if config_path is None:
        # Default: look relative to this file's package
        package_root = Path(__file__).parent.parent
        config_path = package_root / "config" / "trust_levels.toml"

    if not config_path.exists():
        raise FileNotFoundError(f"Trust config not found: {config_path}")

    with open(config_path, "rb") as f:
        data = tomllib.load(f)

    config = TrustLevelsConfig()

    # Load trust levels
    trust_levels = data.get("trust_levels", {})
    for name, level_data in trust_levels.items():
        if isinstance(level_data, dict):
            config.levels[name] = TrustConfig(
                threshold=level_data.get("threshold", 0.5),
                min_detectors=level_data.get("min_detectors", 1),
                bias=level_data.get("bias", 1.0),
                description=level_data.get("description", ""),
                allow_override=level_data.get("allow_override", True),
            )

    # Load source mapping
    config.source_mapping = data.get("source_mapping", {})

    # Load policies
    policies = data.get("policies", {})
    config.log_below_threshold = policies.get("log_below_threshold", True)
    config.default_action = policies.get("default_action", "warn")

    return config


def get_trust_level_for_source(source: str, config: TrustLevelsConfig) -> TrustConfig | None:
    """Get the trust configuration for a given source.

    Matches source against patterns in source_mapping (in order) and
    returns the corresponding TrustConfig.

    Args:
        source: Source identifier (e.g., "user/verified/123", "api/webhook").
        config: Loaded trust levels configuration.

    Returns:
        TrustConfig for the matching trust level, or None if no match.
    """
    for pattern, level_name in config.source_mapping.items():
        if fnmatch(source, pattern):
            return config.levels.get(level_name)
    return None


def apply_trust_bias(
    confidence: float,
    trust_config: TrustConfig,
) -> float:
    """Apply trust-based bias to a detection confidence score.

    The bias adjusts how sensitive detection is for different trust levels.
    Higher trust sources have their confidence reduced (harder to flag),
    while lower trust sources have confidence increased (easier to flag).

    Args:
        confidence: Raw confidence score from detector (0.0 to 1.0).
        trust_config: Trust configuration with bias multiplier.

    Returns:
        Adjusted confidence score, clamped to [0.0, 1.0].

    Example:
        >>> config = TrustConfig(threshold=0.7, bias=0.8)
        >>> apply_trust_bias(0.6, config)  # 0.6 * 0.8 = 0.48
        0.48
    """
    adjusted = confidence * trust_config.bias
    return max(0.0, min(1.0, adjusted))


def should_flag(
    confidence: float,
    trust_config: TrustConfig,
    apply_bias: bool = True,
) -> bool:
    """Determine if a detection should be flagged based on trust level.

    Args:
        confidence: Detection confidence score (0.0 to 1.0).
        trust_config: Trust configuration with threshold.
        apply_bias: Whether to apply trust bias to confidence first.

    Returns:
        True if the adjusted confidence exceeds the threshold.
    """
    if apply_bias:
        confidence = apply_trust_bias(confidence, trust_config)
    return confidence >= trust_config.threshold
