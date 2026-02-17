"""
ClawBot integration adapter stub.

Placeholder for future Discord/Slack bot integration.
Provides API endpoint mode and context-aware trust based on
message source (DM vs channel).
"""

import logging
from dataclasses import dataclass
from typing import Any

from adapters.base import TrustLevel
from core.pipeline import Pipeline, PipelineResult
from integrations.base import (
    ActionMode,
    DetectionEvent,
    Integration,
    IntegrationConfig,
)

logger = logging.getLogger(__name__)


# Message context types
CONTEXT_DM = "dm"           # Direct message - higher trust
CONTEXT_CHANNEL = "channel"  # Public channel - lower trust
CONTEXT_THREAD = "thread"    # Thread reply - medium trust
CONTEXT_WEBHOOK = "webhook"  # Webhook/bot - lowest trust

# All supported hooks
HOOK_MESSAGE = "message.before"
HOOK_COMMAND = "command.before"
HOOK_WEBHOOK = "webhook.incoming"

SUPPORTED_HOOKS = [HOOK_MESSAGE, HOOK_COMMAND, HOOK_WEBHOOK]


@dataclass
class ClawBotScanResult:
    """Result from scanning a ClawBot message.

    Attributes:
        safe: Whether the message is considered safe.
        confidence: Detection confidence if flagged.
        action: Action taken (if any).
        warning: Warning message to display (if applicable).
        metadata: Additional result metadata.
    """
    safe: bool = True
    confidence: float = 0.0
    action: ActionMode | None = None
    warning: str | None = None
    metadata: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API response."""
        result: dict[str, Any] = {
            "safe": self.safe,
            "confidence": self.confidence,
        }
        if self.action:
            result["action"] = self.action.value
        if self.warning:
            result["warning"] = self.warning
        if self.metadata:
            result["metadata"] = self.metadata
        return result


class ClawBotIntegration(Integration):
    """Integration stub for Discord/Slack bot.

    This integration is designed for future implementation of a chat bot
    that can scan messages for prompt injection attempts. It supports:
    - Context-aware trust levels (DM vs channel)
    - API endpoint mode for bot backends
    - Webhook scanning for incoming integrations

    Note: This is a stub implementation. Full Discord/Slack SDK integration
    will be added in a future release.

    Usage:
        >>> integration = ClawBotIntegration()
        >>> result = integration.scan_message(
        ...     content="Some message",
        ...     context_type=CONTEXT_CHANNEL,
        ...     user_id="user123",
        ... )
        >>> if not result.safe:
        ...     # Handle potentially malicious message
    """

    def __init__(
        self,
        config: IntegrationConfig | None = None,
        pipeline: Pipeline | None = None,
        bot_name: str = "clawbot",
    ) -> None:
        """Initialize ClawBot integration.

        Args:
            config: Integration configuration.
            pipeline: Detection pipeline to use. If None, creates default.
            bot_name: Name of the bot instance.
        """
        super().__init__(config)
        self._pipeline = pipeline or Pipeline()
        self._bot_name = bot_name
        self._is_stub = True  # Mark as stub implementation

    @property
    def name(self) -> str:
        """Return integration identifier."""
        return "clawbot"

    @property
    def is_stub(self) -> bool:
        """Return whether this is a stub implementation."""
        return self._is_stub

    def get_supported_hooks(self) -> list[str]:
        """Return supported ClawBot hooks."""
        return SUPPORTED_HOOKS.copy()

    def map_source_to_trust(self, source: str) -> TrustLevel:
        """Map ClawBot message context to trust level.

        Trust levels for chat contexts:
        - DM: Higher trust (user directly engaging)
        - Channel: Lower trust (could be prompted by others)
        - Webhook: Lowest trust (external source)

        Args:
            source: Source identifier with context type.

        Returns:
            Appropriate TrustLevel based on context.
        """
        # Direct messages have higher trust
        if source.startswith(f"{CONTEXT_DM}/"):
            return TrustLevel.USER

        # Thread replies have medium trust
        if source.startswith(f"{CONTEXT_THREAD}/"):
            return TrustLevel.MCP

        # Channel messages have lower trust
        if source.startswith(f"{CONTEXT_CHANNEL}/"):
            return TrustLevel.MCP

        # Webhooks and unknown sources have lowest trust
        if source.startswith(f"{CONTEXT_WEBHOOK}/"):
            return TrustLevel.TOOL_OUTPUT

        # Default to lowest trust
        return TrustLevel.TOOL_OUTPUT

    def install(self) -> bool:
        """Install bot hooks.

        Note: This is a stub. Full implementation would register
        event handlers with Discord/Slack SDK.

        Returns:
            True (stub always succeeds).
        """
        logger.info(f"ClawBot integration installed (stub mode): {self._bot_name}")
        self._installed = True
        return True

    def uninstall(self) -> bool:
        """Uninstall bot hooks.

        Note: This is a stub. Full implementation would unregister
        event handlers from Discord/Slack SDK.

        Returns:
            True (stub always succeeds).
        """
        logger.info(f"ClawBot integration uninstalled (stub mode): {self._bot_name}")
        self._installed = False
        return True

    def scan_message(
        self,
        content: str,
        context_type: str = CONTEXT_CHANNEL,
        user_id: str | None = None,
        channel_id: str | None = None,
        guild_id: str | None = None,
    ) -> ClawBotScanResult:
        """Scan a chat message for prompt injection.

        Args:
            content: Message content to scan.
            context_type: Type of context (dm, channel, thread, webhook).
            user_id: ID of the message author.
            channel_id: ID of the channel.
            guild_id: ID of the guild/server (if applicable).

        Returns:
            ClawBotScanResult with detection outcome.
        """
        # Build source identifier
        source = f"{context_type}/{channel_id or 'unknown'}"
        trust_level = self.map_source_to_trust(source)

        # Run detection
        result = self._pipeline.scan(content, source=source, trust_level=trust_level)

        # Log if configured
        if self._config.log_detections and result.flagged:
            logger.warning(
                f"Prompt injection in {context_type}: "
                f"confidence={result.confidence:.2%}, user={user_id}"
            )

        # Determine action
        action = self.get_action_for_confidence(result.confidence) if result.flagged else None

        # Create detection event
        if result.flagged:
            event = DetectionEvent(
                content=content[:500],
                confidence=result.confidence,
                source=source,
                trust_level=trust_level,
                action_taken=action or ActionMode.LOG,
                hook_name=HOOK_MESSAGE,
                details={
                    "user_id": user_id,
                    "channel_id": channel_id,
                    "guild_id": guild_id,
                    "context_type": context_type,
                },
            )
            self._notify_detection(event)

        # Create scan result
        return ClawBotScanResult(
            safe=not result.flagged,
            confidence=result.confidence,
            action=action,
            warning=self._get_warning(result) if result.flagged else None,
            metadata={
                "context_type": context_type,
                "detectors_run": result.detectors_run,
                "detectors_flagged": result.detectors_flagged,
            },
        )

    def scan_webhook(
        self,
        payload: dict[str, Any],
        webhook_id: str | None = None,
    ) -> ClawBotScanResult:
        """Scan an incoming webhook payload.

        Args:
            payload: Webhook payload dictionary.
            webhook_id: ID of the webhook.

        Returns:
            ClawBotScanResult with detection outcome.
        """
        # Extract content from payload
        content = payload.get("content", "")
        if not content and "text" in payload:
            content = payload["text"]
        if not content and "message" in payload:
            content = str(payload["message"])

        return self.scan_message(
            content=content,
            context_type=CONTEXT_WEBHOOK,
            channel_id=webhook_id,
        )

    def _get_warning(self, result: PipelineResult) -> str:
        """Generate a warning message for flagged content.

        Args:
            result: Detection result.

        Returns:
            Warning message string.
        """
        return (
            f"⚠️ This message may contain a prompt injection attempt "
            f"(confidence: {result.confidence:.0%})"
        )

    def health_check(self) -> bool:
        """Check integration health.

        Returns:
            True if operational (stub always returns True).
        """
        return self._installed

    # API endpoint methods for bot backend integration

    def api_scan(self, request: dict[str, Any]) -> dict[str, Any]:
        """API endpoint for scanning content.

        This method is designed to be called by a bot backend API.

        Args:
            request: API request with keys:
                - content: Text to scan
                - context_type: Optional context type
                - user_id: Optional user ID
                - channel_id: Optional channel ID

        Returns:
            API response dictionary.
        """
        content = request.get("content", "")
        context_type = request.get("context_type", CONTEXT_CHANNEL)
        user_id = request.get("user_id")
        channel_id = request.get("channel_id")

        result = self.scan_message(
            content=content,
            context_type=context_type,
            user_id=user_id,
            channel_id=channel_id,
        )

        return result.to_dict()

    def api_health(self) -> dict[str, Any]:
        """API health check endpoint.

        Returns:
            Health status dictionary.
        """
        pipeline_health = self._pipeline.health_check()
        return {
            "status": "healthy" if self.health_check() else "unhealthy",
            "integration": self.name,
            "is_stub": self._is_stub,
            "pipeline": {
                "detectors": len(pipeline_health),
                "healthy": sum(1 for v in pipeline_health.values() if v),
            },
        }


def get_integration(
    config: IntegrationConfig | None = None,
    bot_name: str = "clawbot",
) -> ClawBotIntegration:
    """Factory function to create a ClawBot integration.

    Args:
        config: Optional configuration.
        bot_name: Name of the bot instance.

    Returns:
        Configured ClawBotIntegration instance.
    """
    return ClawBotIntegration(config=config, bot_name=bot_name)
