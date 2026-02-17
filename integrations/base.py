"""
Base interface for platform integrations.

Defines the Integration ABC that all platform-specific adapters must implement,
as well as the AgenticIntegration ABC for agentic flow interception.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from adapters.base import TrustLevel


class ActionMode(Enum):
    """Action to take when injection is detected."""
    BLOCK = "block"   # Block the request entirely
    WARN = "warn"     # Allow but warn the user
    LOG = "log"       # Allow and only log the detection


class InterceptionAction(Enum):
    """Action to take after intercepting content in agentic flows."""
    ALLOW = "allow"      # Content passes through
    WARN = "warn"        # Content passes, model/user warned
    BLOCK = "block"      # Content blocked, model/user notified


@dataclass
class InterceptionResult:
    """Result from intercepting and analyzing content in agentic flows.

    Attributes:
        action: The action taken (ALLOW, WARN, BLOCK).
        content: The original content that was analyzed.
        confidence: Detection confidence score (0.0 to 1.0).
        reason: Explanation for why content was blocked/warned.
        model_context: Information to add to the model's context.
        user_message: Notification message for the user.
        detector_results: Detailed results from each detector.
    """
    action: InterceptionAction
    content: str
    confidence: float
    reason: str | None = None
    model_context: str | None = None
    user_message: str | None = None
    detector_results: dict[str, Any] | None = None


@dataclass
class HookConfig:
    """Configuration for an integration hook.

    Attributes:
        name: Hook identifier (e.g., "PreToolUse", "mail.before").
        enabled: Whether this hook is active.
        action: Action to take on detection.
        threshold: Confidence threshold for this hook.
    """
    name: str
    enabled: bool = True
    action: ActionMode = ActionMode.WARN
    threshold: float = 0.7


@dataclass
class IntegrationConfig:
    """Configuration for a platform integration.

    Attributes:
        enabled: Whether the integration is active.
        hooks: Configuration for each hook point.
        action_mode: Default action mode for this integration.
        warn_threshold: Confidence threshold for warnings.
        block_threshold: Confidence threshold for blocking.
        log_detections: Whether to log all detections.
        extra: Platform-specific configuration.
    """
    enabled: bool = False
    hooks: dict[str, HookConfig] = field(default_factory=dict)
    action_mode: ActionMode = ActionMode.WARN
    warn_threshold: float = 0.5
    block_threshold: float = 0.8
    log_detections: bool = True
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionEvent:
    """Event data when injection is detected.

    Attributes:
        content: The scanned content.
        confidence: Detection confidence score.
        source: Source of the content (e.g., "tool_output", "user_prompt").
        trust_level: Trust level applied.
        action_taken: Action that was taken.
        hook_name: Hook that triggered the detection.
        details: Additional detection details.
    """
    content: str
    confidence: float
    source: str
    trust_level: TrustLevel
    action_taken: ActionMode
    hook_name: str
    details: dict[str, Any] = field(default_factory=dict)


class Integration(ABC):
    """Abstract base class for platform integrations.

    Each integration connects the detection pipeline to a specific platform
    (Claude Code, multi-agent systems, Discord bot, etc.) by:
    1. Installing hooks at appropriate points
    2. Mapping platform sources to trust levels
    3. Taking appropriate action on detection
    """

    def __init__(self, config: IntegrationConfig | None = None) -> None:
        """Initialize the integration.

        Args:
            config: Integration configuration. Uses defaults if None.
        """
        self._config = config or IntegrationConfig()
        self._installed = False
        self._detection_callbacks: list[Callable[[DetectionEvent], None]] = []

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this integration.

        Returns:
            A string identifier (e.g., "claude_code", "multiagent").
        """
        ...

    @property
    def config(self) -> IntegrationConfig:
        """Return the integration configuration."""
        return self._config

    @property
    def is_installed(self) -> bool:
        """Return whether the integration is currently installed."""
        return self._installed

    @abstractmethod
    def install(self) -> bool:
        """Install hooks into the platform.

        Sets up the integration to intercept and scan content at
        configured hook points.

        Returns:
            True if installation was successful, False otherwise.
        """
        ...

    @abstractmethod
    def uninstall(self) -> bool:
        """Remove hooks from the platform.

        Removes all hooks and restores the platform to its original state.

        Returns:
            True if uninstallation was successful, False otherwise.
        """
        ...

    @abstractmethod
    def map_source_to_trust(self, source: str) -> TrustLevel:
        """Map a platform-specific source to a trust level.

        Each platform has different concepts of "source" - this method
        translates those platform-specific identifiers to the standard
        TrustLevel enum.

        Args:
            source: Platform-specific source identifier.

        Returns:
            Appropriate TrustLevel for the source.
        """
        ...

    def on_detection(self, callback: Callable[[DetectionEvent], None]) -> None:
        """Register a callback for detection events.

        Args:
            callback: Function to call with DetectionEvent on detection.
        """
        self._detection_callbacks.append(callback)

    def _notify_detection(self, event: DetectionEvent) -> None:
        """Notify all registered callbacks of a detection event.

        Args:
            event: The detection event to broadcast.
        """
        for callback in self._detection_callbacks:
            try:
                callback(event)
            except Exception:
                # Don't let callback errors break the detection flow
                pass

    def get_action_for_confidence(self, confidence: float) -> ActionMode:
        """Determine action based on confidence score.

        Args:
            confidence: Detection confidence from 0.0 to 1.0.

        Returns:
            Appropriate ActionMode based on configured thresholds.
        """
        if confidence >= self._config.block_threshold:
            return ActionMode.BLOCK
        elif confidence >= self._config.warn_threshold:
            return ActionMode.WARN
        else:
            return ActionMode.LOG

    @abstractmethod
    def get_supported_hooks(self) -> list[str]:
        """Return list of hook points this integration supports.

        Returns:
            List of hook identifiers (e.g., ["PreToolUse", "UserPromptSubmit"]).
        """
        ...

    def health_check(self) -> bool:
        """Check if the integration is healthy and operational.

        Returns:
            True if integration is ready, False otherwise.
        """
        return self._installed


class AgenticIntegration(ABC):
    """Abstract base class for agentic platform integrations.

    This class provides a specialized interface for integrating Rebuff
    into agentic flows where content must be intercepted and analyzed
    before entering an LLM's context. It handles:

    1. Content interception from multiple entry points
    2. Trust-aware detection thresholds
    3. Formatted responses for both model and user awareness
    4. Platform-specific hook installation

    Subclasses must implement the abstract methods to provide
    platform-specific behavior.

    Example:
        >>> class MyPlatformIntegration(AgenticIntegration):
        ...     @property
        ...     def name(self) -> str:
        ...         return "my_platform"
        ...
        ...     def get_content_sources(self) -> List[str]:
        ...         return ["user_input", "tool_output", "api_response"]
        ...
        ...     # ... implement other required methods
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Platform identifier.

        Returns:
            A unique string identifier for this platform
            (e.g., "claude_code", "multiagent").
        """
        ...

    @abstractmethod
    def get_content_sources(self) -> list[str]:
        """Return list of content entry points this platform has.

        These are the places where content can enter the LLM's context
        and should be scanned for potential injection attacks.

        Returns:
            List of source identifiers (e.g., ["user_prompt", "tool_output", "mcp_response"]).
        """
        ...

    @abstractmethod
    def install(self) -> bool:
        """Install hooks/interceptors into the platform.

        Sets up the integration to intercept content at all configured
        entry points. This may involve modifying configuration files,
        registering callbacks, or other platform-specific setup.

        Returns:
            True if installation was successful.
        """
        ...

    @abstractmethod
    def uninstall(self) -> bool:
        """Remove hooks/interceptors from the platform.

        Restores the platform to its original state before integration.

        Returns:
            True if uninstallation was successful.
        """
        ...

    @abstractmethod
    def handle_interception(
        self,
        source: str,
        content: str,
        metadata: dict[str, Any],
    ) -> InterceptionResult:
        """Process content and return interception decision.

        This is the main entry point for content analysis. It should:
        1. Determine the appropriate trust level for the source
        2. Run the Rebuff detection pipeline
        3. Decide on the appropriate action (ALLOW, WARN, BLOCK)
        4. Format messages for model and user awareness

        Args:
            source: Identifier for where the content came from
                   (e.g., "user_prompt", "mcp/filesystem").
            content: The content to analyze for injection attacks.
            metadata: Additional context about the content
                     (e.g., tool_name, mcp_server, file_path).

        Returns:
            InterceptionResult with the action decision and any
            messages for the model or user.
        """
        ...

    @abstractmethod
    def format_response(self, result: InterceptionResult) -> dict[str, Any]:
        """Format result into platform-specific response.

        Converts the InterceptionResult into the format expected by
        the platform's hook system.

        Args:
            result: The interception analysis result.

        Returns:
            Dictionary formatted for the platform's response protocol.
        """
        ...
