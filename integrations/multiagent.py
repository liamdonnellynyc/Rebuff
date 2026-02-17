"""
Multi-agent integration adapter.

Provides hooks for integrating with multi-agent systems.
Supports mail.before, tool.before, and mcp.response hooks with
escalation to mayor/ on high-confidence detections.
"""

import logging
import os
import subprocess
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


# Multi-agent hook names
HOOK_MAIL_BEFORE = "mail.before"
HOOK_TOOL_BEFORE = "tool.before"
HOOK_MCP_RESPONSE = "mcp.response"

# All supported hooks
SUPPORTED_HOOKS = [HOOK_MAIL_BEFORE, HOOK_TOOL_BEFORE, HOOK_MCP_RESPONSE]

# Escalation thresholds
DEFAULT_ESCALATE_THRESHOLD = 0.85
DEFAULT_BLOCK_THRESHOLD = 0.9


@dataclass
class MultiAgentHookResult:
    """Result from a multi-agent hook execution.

    Attributes:
        allow: Whether to allow the operation to proceed.
        escalate: Whether to escalate to mayor/.
        reason: Reason for blocking or escalation.
        metadata: Additional metadata for logging.
    """
    allow: bool = True
    escalate: bool = False
    reason: str | None = None
    metadata: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        result: dict[str, Any] = {
            "allow": self.allow,
            "escalate": self.escalate,
        }
        if self.reason:
            result["reason"] = self.reason
        if self.metadata:
            result["metadata"] = self.metadata
        return result


class MultiAgentIntegration(Integration):
    """Integration with multi-agent systems.

    This integration hooks into the event system to scan:
    - Mail content before processing (mail.before)
    - Tool inputs before execution (tool.before)
    - MCP responses before returning (mcp.response)

    High-confidence detections can trigger escalation to mayor/ for
    system-wide security response.

    Usage:
        >>> integration = MultiAgentIntegration()
        >>> integration.install()
        >>> result = integration.scan_hook(HOOK_MAIL_BEFORE, content, context)
        >>> if result.escalate:
        ...     # Handle escalation
    """

    def __init__(
        self,
        config: IntegrationConfig | None = None,
        pipeline: Pipeline | None = None,
        rig_name: str | None = None,
        escalate_threshold: float = DEFAULT_ESCALATE_THRESHOLD,
    ) -> None:
        """Initialize multi-agent integration.

        Args:
            config: Integration configuration.
            pipeline: Detection pipeline to use. If None, creates default.
            rig_name: Name of the current rig (for escalation context).
            escalate_threshold: Confidence threshold for mayor escalation.
        """
        super().__init__(config)
        self._pipeline = pipeline or Pipeline()
        self._rig_name = rig_name or os.environ.get("RIG_NAME", "unknown")
        self._escalate_threshold = escalate_threshold
        self._hooks_registered: dict[str, bool] = {}

    @property
    def name(self) -> str:
        """Return integration identifier."""
        return "multiagent"

    def get_supported_hooks(self) -> list[str]:
        """Return supported multi-agent hooks."""
        return SUPPORTED_HOOKS.copy()

    def map_source_to_trust(self, source: str) -> TrustLevel:
        """Map source to trust level.

        Args:
            source: Source identifier from context.

        Returns:
            Appropriate TrustLevel based on source.
        """
        # Mail from known internal sources has high trust
        if source.startswith("mail/mayor") or source.startswith("mail/witness"):
            return TrustLevel.USER

        # Mail from polecats has medium trust
        if source.startswith("mail/polecat"):
            return TrustLevel.MCP

        # MCP responses have medium trust
        if source.startswith("mcp/"):
            return TrustLevel.MCP

        # External mail and tool outputs have lowest trust
        if source.startswith("mail/external") or source.startswith("tool/"):
            return TrustLevel.TOOL_OUTPUT

        # Default to lowest trust for unknown sources
        return TrustLevel.TOOL_OUTPUT

    def install(self) -> bool:
        """Register hooks with the hook system.

        Registers this integration's hooks with the event system.

        Returns:
            True if installation was successful.
        """
        try:
            # Hooks are typically registered via configuration
            # or by updating the rig's hook registry
            for hook_name in SUPPORTED_HOOKS:
                if self._is_hook_enabled(hook_name):
                    self._hooks_registered[hook_name] = True
                    logger.debug(f"Registered multi-agent hook: {hook_name}")

            self._installed = True
            logger.info(f"Installed multi-agent integration for rig: {self._rig_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to install multi-agent hooks: {e}")
            return False

    def uninstall(self) -> bool:
        """Unregister hooks.

        Returns:
            True if uninstallation was successful.
        """
        try:
            self._hooks_registered.clear()
            self._installed = False
            logger.info(f"Uninstalled multi-agent integration for rig: {self._rig_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to uninstall multi-agent hooks: {e}")
            return False

    def _is_hook_enabled(self, hook_name: str) -> bool:
        """Check if a specific hook is enabled.

        Args:
            hook_name: Name of the hook.

        Returns:
            True if hook is enabled.
        """
        if hook_name in self._config.hooks:
            return self._config.hooks[hook_name].enabled
        # Default: enable all hooks
        return True

    def scan_hook(
        self,
        hook_name: str,
        content: str,
        context: dict[str, Any] | None = None,
    ) -> MultiAgentHookResult:
        """Scan content from a hook.

        Args:
            hook_name: Name of the hook being invoked.
            content: Content to scan for injection.
            context: Additional context.

        Returns:
            MultiAgentHookResult indicating action to take.
        """
        context = context or {}

        # Determine source based on hook type and context
        source = self._get_source_for_hook(hook_name, context)
        trust_level = self.map_source_to_trust(source)

        # Run detection pipeline
        result = self._pipeline.scan(content, source=source, trust_level=trust_level)

        # Log if configured
        if self._config.log_detections and result.flagged:
            logger.warning(
                f"Prompt injection detected via {hook_name}: "
                f"confidence={result.confidence:.2%}, source={source}, rig={self._rig_name}"
            )

        # Determine action
        action = self.get_action_for_confidence(result.confidence)

        # Check for escalation threshold
        should_escalate = (
            result.flagged and
            result.confidence >= self._escalate_threshold
        )

        # Create detection event
        if result.flagged:
            event = DetectionEvent(
                content=content[:500],  # Truncate for logging
                confidence=result.confidence,
                source=source,
                trust_level=trust_level,
                action_taken=action,
                hook_name=hook_name,
                details={
                    "detectors_flagged": result.detectors_flagged,
                    "rig": self._rig_name,
                    "escalated": should_escalate,
                    "context": context,
                },
            )
            self._notify_detection(event)

        # Trigger escalation if needed
        if should_escalate:
            self._escalate_to_mayor(result, source, hook_name, context)

        # Return hook result
        return self._create_hook_result(result, action, should_escalate, hook_name)

    def _get_source_for_hook(
        self,
        hook_name: str,
        context: dict[str, Any],
    ) -> str:
        """Determine source identifier based on hook and context.

        Args:
            hook_name: Name of the hook.
            context: Context data.

        Returns:
            Source identifier for trust mapping.
        """
        if hook_name == HOOK_MAIL_BEFORE:
            sender = context.get("sender", "unknown")
            # Parse sender to determine trust category
            if sender.startswith("mayor/") or sender == "mayor":
                return "mail/mayor"
            elif "witness" in sender:
                return "mail/witness"
            elif "polecat" in sender:
                return "mail/polecat"
            else:
                return f"mail/external/{sender}"

        if hook_name == HOOK_MCP_RESPONSE:
            server = context.get("mcp_server", "unknown")
            return f"mcp/{server}"

        if hook_name == HOOK_TOOL_BEFORE:
            tool = context.get("tool_name", "unknown")
            return f"tool/{tool}"

        return "unknown/*"

    def _create_hook_result(
        self,
        result: PipelineResult,
        action: ActionMode,
        escalated: bool,
        hook_name: str,
    ) -> MultiAgentHookResult:
        """Create hook result based on detection and action mode.

        Args:
            result: Pipeline detection result.
            action: Action to take.
            escalated: Whether this was escalated.
            hook_name: Name of the hook.

        Returns:
            MultiAgentHookResult for the hook handler.
        """
        if not result.flagged:
            return MultiAgentHookResult(allow=True)

        metadata = {
            "confidence": result.confidence,
            "detectors_flagged": result.detectors_flagged,
            "hook": hook_name,
        }

        if action == ActionMode.BLOCK:
            return MultiAgentHookResult(
                allow=False,
                escalate=escalated,
                reason=f"Prompt injection blocked ({result.confidence:.0%} confidence)",
                metadata=metadata,
            )

        # WARN or LOG - allow but potentially escalate
        return MultiAgentHookResult(
            allow=True,
            escalate=escalated,
            reason=f"Prompt injection detected ({result.confidence:.0%} confidence)" if escalated else None,
            metadata=metadata,
        )

    def _escalate_to_mayor(
        self,
        result: PipelineResult,
        source: str,
        hook_name: str,
        context: dict[str, Any],
    ) -> None:
        """Escalate high-confidence detection to mayor/.

        Sends a mail to mayor/ with detection details for system-wide response.

        Args:
            result: Detection result.
            source: Source of the injection.
            hook_name: Hook that triggered detection.
            context: Original context.
        """
        try:
            subject = f"SECURITY: Prompt injection detected in {self._rig_name}"
            body = (
                f"High-confidence prompt injection detected.\n\n"
                f"Rig: {self._rig_name}\n"
                f"Hook: {hook_name}\n"
                f"Source: {source}\n"
                f"Confidence: {result.confidence:.2%}\n"
                f"Detectors flagged: {result.detectors_flagged}/{result.detectors_run}\n"
            )

            # Attempt to send mail via command
            # This is non-blocking and failure is logged but not fatal
            cmd = ["rebuff", "mail", "send", "mayor/", "-s", subject, "-m", body]
            subprocess.run(cmd, capture_output=True, timeout=5)
            logger.info(f"Escalated prompt injection to mayor/: {source}")

        except subprocess.TimeoutExpired:
            logger.warning("Timeout sending escalation mail to mayor/")
        except FileNotFoundError:
            logger.debug("rebuff command not available for escalation")
        except Exception as e:
            logger.warning(f"Failed to escalate to mayor/: {e}")

    def scan_mail(
        self,
        content: str,
        sender: str,
        subject: str | None = None,
    ) -> MultiAgentHookResult:
        """Convenience method to scan incoming mail.

        Args:
            content: Mail body content.
            sender: Sender identifier.
            subject: Optional mail subject.

        Returns:
            MultiAgentHookResult indicating action to take.
        """
        context = {
            "sender": sender,
            "subject": subject or "",
        }
        return self.scan_hook(HOOK_MAIL_BEFORE, content, context)

    def scan_tool_input(
        self,
        content: str,
        tool_name: str,
    ) -> MultiAgentHookResult:
        """Convenience method to scan tool input.

        Args:
            content: Tool input content.
            tool_name: Name of the tool.

        Returns:
            MultiAgentHookResult indicating action to take.
        """
        context = {"tool_name": tool_name}
        return self.scan_hook(HOOK_TOOL_BEFORE, content, context)


def get_integration(
    config: IntegrationConfig | None = None,
    rig_name: str | None = None,
) -> MultiAgentIntegration:
    """Factory function to create a multi-agent integration.

    Args:
        config: Optional configuration.
        rig_name: Name of the current rig.

    Returns:
        Configured MultiAgentIntegration instance.
    """
    return MultiAgentIntegration(config=config, rig_name=rig_name)
