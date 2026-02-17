"""
Core pipeline and trust logic for prompt injection detection.
"""

from core.pipeline import (
    AggregationMethod,
    ExecutionStrategy,
    Pipeline,
    PipelineConfig,
    PipelineResult,
    load_pipeline_config,
)
from core.sanitize import (
    mask_sensitive_patterns,
    normalize_unicode_homoglyphs,
    normalize_whitespace,
    sanitize_for_display,
    sanitize_input,
)
from core.trust import (
    TrustConfig,
    TrustLevelsConfig,
    apply_trust_bias,
    get_trust_level_for_source,
    load_trust_config,
    should_flag,
)

__all__ = [
    # Trust
    "TrustConfig",
    "TrustLevelsConfig",
    "apply_trust_bias",
    "get_trust_level_for_source",
    "load_trust_config",
    "should_flag",
    # Sanitize
    "mask_sensitive_patterns",
    "normalize_unicode_homoglyphs",
    "normalize_whitespace",
    "sanitize_for_display",
    "sanitize_input",
    # Pipeline
    "AggregationMethod",
    "ExecutionStrategy",
    "Pipeline",
    "PipelineConfig",
    "PipelineResult",
    "load_pipeline_config",
]
