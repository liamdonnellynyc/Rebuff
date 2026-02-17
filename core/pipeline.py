"""
Pipeline execution engine for prompt injection detection.

Provides configurable execution strategies for running multiple detectors
and aggregating their results with trust-based thresholds.
"""

import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # Python < 3.11 fallback

from adapters import get_detector, list_detectors
from adapters.base import DetectionResult, Detector, TrustLevel
from core.trust import (
    TrustConfig,
    TrustLevelsConfig,
    apply_trust_bias,
    get_trust_level_for_source,
    load_trust_config,
    should_flag,
)


class ExecutionStrategy(Enum):
    """Strategy for executing detectors."""
    PARALLEL = "parallel"         # Run all detectors concurrently
    SEQUENTIAL = "sequential"     # Run in order, stop on first detection
    WEIGHTED_VOTE = "weighted"    # Weighted voting by detector accuracy


class AggregationMethod(Enum):
    """Method for combining detector results."""
    MAX = "max"           # Take highest confidence
    AVERAGE = "average"   # Average all confidences
    WEIGHTED = "weighted" # Weight by detector reliability
    VOTING = "voting"     # Majority vote among detectors


@dataclass
class PipelineConfig:
    """Configuration for the detection pipeline.

    Attributes:
        strategy: Execution strategy (parallel, sequential, weighted).
        timeout_seconds: Maximum time for entire pipeline execution.
        detector_timeout_seconds: Timeout per individual detector.
        continue_on_error: Whether to continue if a detector fails.
        aggregation_method: How to combine multiple results.
        threshold: Minimum confidence threshold for flagging.
        ordering: Priority order for sequential execution.
        detector_weights: Accuracy weights for weighted voting.
        early_exit_threshold: Confidence threshold for early exit (>0.90).
    """
    strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL
    timeout_seconds: float = 30.0
    detector_timeout_seconds: float = 10.0
    continue_on_error: bool = True
    aggregation_method: AggregationMethod = AggregationMethod.WEIGHTED
    threshold: float = 0.7
    ordering: dict[str, int] = field(default_factory=dict)
    detector_weights: dict[str, float] = field(default_factory=dict)
    early_exit_threshold: float = 0.90


@dataclass
class PipelineResult:
    """Aggregated result from the detection pipeline.

    Attributes:
        is_injection: Final decision on whether input is an injection.
        confidence: Aggregated confidence score (0.0 to 1.0).
        flagged: Whether the result exceeds the trust-adjusted threshold.
        detector_results: Individual results from each detector.
        detectors_run: Number of detectors that executed.
        detectors_flagged: Number of detectors that flagged injection.
        total_latency_ms: Total time for pipeline execution.
        trust_level_used: Trust level applied for this scan.
        strategy_used: Execution strategy used.
        early_exit: Whether pipeline exited early on high confidence.
        errors: Any errors that occurred during execution.
    """
    is_injection: bool
    confidence: float
    flagged: bool
    detector_results: list[DetectionResult] = field(default_factory=list)
    detectors_run: int = 0
    detectors_flagged: int = 0
    total_latency_ms: float = 0.0
    trust_level_used: str | None = None
    strategy_used: str = "parallel"
    early_exit: bool = False
    errors: list[str] = field(default_factory=list)


def load_pipeline_config(config_path: Path | None = None) -> PipelineConfig:
    """Load pipeline configuration from TOML file.

    Args:
        config_path: Path to pipeline.toml. If None, looks for
                     config/pipeline.toml relative to package root.

    Returns:
        Populated PipelineConfig instance.

    Raises:
        FileNotFoundError: If config file doesn't exist.
    """
    if config_path is None:
        package_root = Path(__file__).parent.parent
        config_path = package_root / "config" / "pipeline.toml"

    if not config_path.exists():
        raise FileNotFoundError(f"Pipeline config not found: {config_path}")

    with open(config_path, "rb") as f:
        data = tomllib.load(f)

    # Parse pipeline section
    pipeline_data = data.get("pipeline", {})
    strategy_str = pipeline_data.get("strategy", "parallel")
    try:
        strategy = ExecutionStrategy(strategy_str)
    except ValueError:
        strategy = ExecutionStrategy.PARALLEL

    # Parse aggregation section
    aggregation_data = data.get("aggregation", {})
    method_str = aggregation_data.get("method", "weighted")
    try:
        aggregation_method = AggregationMethod(method_str)
    except ValueError:
        aggregation_method = AggregationMethod.WEIGHTED

    # Parse defaults section
    defaults_data = data.get("defaults", {})

    return PipelineConfig(
        strategy=strategy,
        timeout_seconds=pipeline_data.get("timeout_seconds", 30.0),
        detector_timeout_seconds=defaults_data.get("detector_timeout_seconds", 10.0),
        continue_on_error=defaults_data.get("continue_on_error", True),
        aggregation_method=aggregation_method,
        threshold=aggregation_data.get("threshold", 0.7),
        ordering=data.get("ordering", {}),
        detector_weights=data.get("detector_weights", {}),
        early_exit_threshold=pipeline_data.get("early_exit_threshold", 0.90),
    )


class Pipeline:
    """Detection pipeline that orchestrates multiple detectors.

    The pipeline loads detector adapters, executes them according to the
    configured strategy, and aggregates results with trust-based thresholds.

    Usage:
        >>> pipeline = Pipeline()
        >>> result = pipeline.scan("Please ignore previous instructions...")
        >>> if result.flagged:
        ...     print(f"Injection detected with {result.confidence:.2%} confidence")
    """

    def __init__(
        self,
        config: PipelineConfig | None = None,
        trust_config: TrustLevelsConfig | None = None,
        detectors: list[Detector] | None = None,
    ) -> None:
        """Initialize the pipeline.

        Args:
            config: Pipeline configuration. If None, loads from default TOML.
            trust_config: Trust levels configuration. If None, loads from default TOML.
            detectors: List of detector instances. If None, loads all available.
        """
        self._config = config or load_pipeline_config()
        self._trust_config = trust_config or load_trust_config()
        self._detectors = self._load_default_detectors() if detectors is None else detectors
        self._warmed_up = False

    def _load_default_detectors(self) -> list[Detector]:
        """Load all available detectors."""
        detectors = []
        for detector_id in list_detectors():
            try:
                detector = get_detector(detector_id)
                detectors.append(detector)
            except Exception:
                # Skip detectors that fail to load
                pass
        return detectors

    def warmup(self) -> None:
        """Warm up all detectors.

        Should be called before the first scan to ensure low latency.
        """
        for detector in self._detectors:
            try:
                detector.warmup()
            except Exception:
                # Continue warming up other detectors
                pass
        self._warmed_up = True

    def health_check(self) -> dict[str, bool]:
        """Check health of all detectors.

        Returns:
            Mapping of detector ID to health status.
        """
        return {d.id: d.health_check() for d in self._detectors}

    def scan(
        self,
        content: str,
        source: str = "user/*",
        timeout: float | None = None,
        trust_level: TrustLevel | None = None,
    ) -> PipelineResult:
        """Scan content for prompt injection.

        Args:
            content: The text content to analyze.
            source: Source identifier for trust level lookup.
            timeout: Override pipeline timeout (seconds).
            trust_level: Override trust level directly.

        Returns:
            PipelineResult with aggregated detection outcome.
        """
        start_time = time.perf_counter()

        # Ensure detectors are warmed up
        if not self._warmed_up:
            self.warmup()

        # Determine effective timeout
        effective_timeout = timeout or self._config.timeout_seconds

        # Get trust configuration for source
        trust_config = get_trust_level_for_source(source, self._trust_config)
        if trust_config is None:
            # Use default threshold if no trust config found
            trust_config = TrustConfig(threshold=self._config.threshold)

        # Execute based on strategy
        if self._config.strategy == ExecutionStrategy.SEQUENTIAL:
            result = self._execute_sequential(content, trust_level, effective_timeout)
        elif self._config.strategy == ExecutionStrategy.WEIGHTED_VOTE:
            result = self._execute_weighted_vote(content, trust_level, effective_timeout)
        else:
            result = self._execute_parallel(content, trust_level, effective_timeout)

        # Apply trust threshold for final flagging decision
        result = self._apply_trust_threshold(result, trust_config, source)

        # Record total latency
        result.total_latency_ms = (time.perf_counter() - start_time) * 1000
        result.strategy_used = self._config.strategy.value

        return result

    def _execute_parallel(
        self,
        content: str,
        trust_level: TrustLevel | None,
        timeout: float,
    ) -> PipelineResult:
        """Execute all detectors in parallel.

        Runs all detectors concurrently and aggregates results.
        Supports early exit on high-confidence detection.
        """
        results: list[DetectionResult] = []
        errors: list[str] = []
        early_exit = False

        effective_trust = trust_level or TrustLevel.USER

        # Handle empty detectors case
        if not self._detectors:
            return PipelineResult(
                is_injection=False,
                confidence=0.0,
                flagged=False,
                detector_results=[],
                detectors_run=0,
                detectors_flagged=0,
                total_latency_ms=0.0,
                trust_level_used=effective_trust.name.lower(),
                strategy_used="parallel",
                early_exit=False,
                errors=[],
            )

        detector_timeout = min(self._config.detector_timeout_seconds, timeout)

        with ThreadPoolExecutor(max_workers=len(self._detectors)) as executor:
            futures = {
                executor.submit(
                    self._run_detector_with_timeout,
                    detector,
                    content,
                    effective_trust,
                    detector_timeout,
                ): detector
                for detector in self._detectors
            }

            for future in futures:
                detector = futures[future]
                try:
                    result = future.result(timeout=timeout)
                    if result is not None:
                        results.append(result)

                        # Check for early exit on high confidence
                        if (result.is_injection and
                            result.confidence >= self._config.early_exit_threshold):
                            early_exit = True
                            # Cancel remaining futures
                            for f in futures:
                                f.cancel()
                            break
                except FuturesTimeoutError:
                    if self._config.continue_on_error:
                        errors.append(f"Detector {detector.id} timed out")
                    else:
                        raise
                except Exception as e:
                    if self._config.continue_on_error:
                        errors.append(f"Detector {detector.id} error: {e}")
                    else:
                        raise

        return self._aggregate_results(results, errors, early_exit)

    def _execute_sequential(
        self,
        content: str,
        trust_level: TrustLevel | None,
        timeout: float,
    ) -> PipelineResult:
        """Execute detectors sequentially with early exit.

        Runs detectors in priority order, stopping on first detection.
        """
        results: list[DetectionResult] = []
        errors: list[str] = []
        early_exit = False

        effective_trust = trust_level or TrustLevel.USER

        # Handle empty detectors case
        if not self._detectors:
            return PipelineResult(
                is_injection=False,
                confidence=0.0,
                flagged=False,
                detector_results=[],
                detectors_run=0,
                detectors_flagged=0,
                total_latency_ms=0.0,
                trust_level_used=effective_trust.name.lower(),
                strategy_used="sequential",
                early_exit=False,
                errors=[],
            )

        detector_timeout = min(self._config.detector_timeout_seconds, timeout)
        remaining_timeout = timeout

        # Sort detectors by ordering priority
        sorted_detectors = sorted(
            self._detectors,
            key=lambda d: self._config.ordering.get(d.id, 999),
        )

        for detector in sorted_detectors:
            if remaining_timeout <= 0:
                errors.append("Pipeline timeout exceeded")
                break

            start = time.perf_counter()
            try:
                result = self._run_detector_with_timeout(
                    detector,
                    content,
                    effective_trust,
                    min(detector_timeout, remaining_timeout),
                )
                if result is not None:
                    results.append(result)

                    # Early exit on detection for sequential strategy
                    if result.is_injection and result.confidence >= self._config.threshold:
                        early_exit = True
                        break
            except Exception as e:
                if self._config.continue_on_error:
                    errors.append(f"Detector {detector.id} error: {e}")
                else:
                    raise
            finally:
                elapsed = time.perf_counter() - start
                remaining_timeout -= elapsed

        return self._aggregate_results(results, errors, early_exit)

    def _execute_weighted_vote(
        self,
        content: str,
        trust_level: TrustLevel | None,
        timeout: float,
    ) -> PipelineResult:
        """Execute detectors with weighted voting.

        All detectors run, and their results are weighted by configured
        accuracy weights to produce a final confidence score.
        """
        # First, run all detectors in parallel
        parallel_result = self._execute_parallel(content, trust_level, timeout)

        # Apply weighted voting to the results
        if not parallel_result.detector_results:
            return parallel_result

        total_weight = 0.0
        weighted_confidence = 0.0
        weighted_injection_votes = 0.0

        for result in parallel_result.detector_results:
            weight = self._config.detector_weights.get(result.detector_id, 1.0)
            total_weight += weight
            weighted_confidence += result.confidence * weight
            if result.is_injection:
                weighted_injection_votes += weight

        if total_weight > 0:
            final_confidence = weighted_confidence / total_weight
            # Injection if weighted majority votes yes
            is_injection = weighted_injection_votes > (total_weight / 2)
        else:
            final_confidence = 0.0
            is_injection = False

        return PipelineResult(
            is_injection=is_injection,
            confidence=final_confidence,
            flagged=False,  # Will be set by _apply_trust_threshold
            detector_results=parallel_result.detector_results,
            detectors_run=parallel_result.detectors_run,
            detectors_flagged=parallel_result.detectors_flagged,
            total_latency_ms=parallel_result.total_latency_ms,
            early_exit=parallel_result.early_exit,
            errors=parallel_result.errors,
        )

    def _run_detector_with_timeout(
        self,
        detector: Detector,
        content: str,
        trust_level: TrustLevel,
        timeout: float,
    ) -> DetectionResult | None:
        """Run a single detector with timeout enforcement.

        Args:
            detector: The detector to run.
            content: Text to analyze.
            trust_level: Trust level for the input.
            timeout: Maximum time allowed.

        Returns:
            DetectionResult or None if timeout/error.
        """
        # Simple synchronous execution with timing
        # For true timeout enforcement, would need threading
        start_time = time.perf_counter()
        try:
            result = detector.detect(content, trust_level)
            elapsed = time.perf_counter() - start_time

            # If detection took too long, treat as timeout
            if elapsed > timeout:
                return DetectionResult(
                    is_injection=False,
                    confidence=0.0,
                    category="timeout",
                    explanation=f"Detector exceeded timeout ({elapsed:.2f}s > {timeout:.2f}s)",
                    latency_ms=elapsed * 1000,
                    detector_id=detector.id,
                )
            return result
        except Exception as e:
            elapsed = time.perf_counter() - start_time
            return DetectionResult(
                is_injection=False,
                confidence=0.0,
                category="error",
                explanation=f"Detection error: {e}",
                latency_ms=elapsed * 1000,
                detector_id=detector.id,
            )

    def _aggregate_results(
        self,
        results: list[DetectionResult],
        errors: list[str],
        early_exit: bool,
    ) -> PipelineResult:
        """Aggregate multiple detector results into a single pipeline result.

        Args:
            results: Individual detection results.
            errors: Any errors that occurred.
            early_exit: Whether pipeline exited early.

        Returns:
            Aggregated PipelineResult.
        """
        if not results:
            return PipelineResult(
                is_injection=False,
                confidence=0.0,
                flagged=False,
                detector_results=results,
                detectors_run=0,
                detectors_flagged=0,
                errors=errors,
                early_exit=early_exit,
            )

        # Count detectors that flagged
        detectors_flagged = sum(1 for r in results if r.is_injection)

        # Aggregate confidence based on method
        if self._config.aggregation_method == AggregationMethod.MAX:
            confidence = max(r.confidence for r in results)
        elif self._config.aggregation_method == AggregationMethod.AVERAGE:
            confidence = sum(r.confidence for r in results) / len(results)
        elif self._config.aggregation_method == AggregationMethod.VOTING:
            # Majority vote: confidence is proportion of flagging detectors
            confidence = detectors_flagged / len(results)
        else:  # WEIGHTED - default
            # For non-weighted-vote strategy, use average of flagging detectors
            if detectors_flagged > 0:
                flagging_results = [r for r in results if r.is_injection]
                confidence = sum(r.confidence for r in flagging_results) / len(flagging_results)
            else:
                confidence = max(r.confidence for r in results)

        # Determine if injection (any detector flagged)
        is_injection = any(r.is_injection for r in results)

        return PipelineResult(
            is_injection=is_injection,
            confidence=confidence,
            flagged=False,  # Will be set by _apply_trust_threshold
            detector_results=results,
            detectors_run=len(results),
            detectors_flagged=detectors_flagged,
            errors=errors,
            early_exit=early_exit,
        )

    def _apply_trust_threshold(
        self,
        result: PipelineResult,
        trust_config: TrustConfig,
        source: str,
    ) -> PipelineResult:
        """Apply trust-based threshold to determine final flagging.

        Args:
            result: Aggregated pipeline result.
            trust_config: Trust configuration for the source.
            source: Source identifier.

        Returns:
            Updated PipelineResult with flagged status set.
        """
        # Apply trust bias to confidence
        adjusted_confidence = apply_trust_bias(result.confidence, trust_config)

        # Determine if should flag
        flagged = should_flag(result.confidence, trust_config, apply_bias=True)

        # Also check min_detectors requirement
        if result.detectors_flagged < trust_config.min_detectors:
            flagged = False

        # Extract trust level name from source for reporting
        trust_level_name = None
        for pattern, level_name in self._trust_config.source_mapping.items():
            from fnmatch import fnmatch
            if fnmatch(source, pattern):
                trust_level_name = level_name
                break

        result.flagged = flagged
        result.confidence = adjusted_confidence
        result.trust_level_used = trust_level_name

        return result

    @property
    def config(self) -> PipelineConfig:
        """Return the pipeline configuration."""
        return self._config

    @property
    def detectors(self) -> list[Detector]:
        """Return the list of configured detectors."""
        return self._detectors
