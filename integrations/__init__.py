"""
Platform integrations for the prompt injection detector suite.

Provides integration adapters for various platforms:
- Claude Code CLI
- Multi-agent systems
- ClawBot (Discord/Slack bot stub)
"""

from typing import Any

from integrations.base import (
    ActionMode,
    AgenticIntegration,
    DetectionEvent,
    HookConfig,
    Integration,
    IntegrationConfig,
    InterceptionAction,
    InterceptionResult,
)
from integrations.claude_code import ClaudeCodeIntegration
from integrations.clawbot import ClawBotIntegration
from integrations.multiagent import MultiAgentIntegration

# Registry of available integrations
_INTEGRATIONS: dict[str, type[Integration]] = {
    "claude_code": ClaudeCodeIntegration,
    "multiagent": MultiAgentIntegration,
    "clawbot": ClawBotIntegration,
}

# Aliases for convenience
_ALIASES: dict[str, str] = {
    "claude-code": "claude_code",
    "claudecode": "claude_code",
    "cc": "claude_code",
    "multi_agent": "multiagent",
    "multi-agent": "multiagent",
    "ma": "multiagent",
    "claw_bot": "clawbot",
    "claw-bot": "clawbot",
    "discord": "clawbot",
    "slack": "clawbot",
}


def get_integration(
    name: str,
    config: IntegrationConfig | None = None,
    **kwargs: Any,
) -> Integration:
    """Get an integration instance by name.

    Args:
        name: Integration name (e.g., "claude_code", "multiagent", "clawbot").
              Also accepts aliases like "cc", "ma", "discord".
        config: Optional integration configuration.
        **kwargs: Additional arguments passed to the integration constructor.

    Returns:
        Configured Integration instance.

    Raises:
        ValueError: If integration name is not recognized.

    Example:
        >>> integration = get_integration("claude_code")
        >>> integration.install()
    """
    # Normalize name
    normalized = name.lower().strip()

    # Check aliases
    if normalized in _ALIASES:
        normalized = _ALIASES[normalized]

    # Look up integration class
    if normalized not in _INTEGRATIONS:
        available = list(_INTEGRATIONS.keys())
        raise ValueError(
            f"Unknown integration: '{name}'. "
            f"Available integrations: {available}"
        )

    integration_cls = _INTEGRATIONS[normalized]
    return integration_cls(config=config, **kwargs)


def list_integrations() -> list[str]:
    """List all available integration names.

    Returns:
        Sorted list of integration identifiers.

    Example:
        >>> list_integrations()
        ['clawbot', 'claude_code', 'multiagent']
    """
    return sorted(_INTEGRATIONS.keys())


def register_integration(name: str, integration_cls: type[Integration]) -> None:
    """Register a new integration type.

    Allows extensions to add custom integrations at runtime.

    Args:
        name: Integration identifier.
        integration_cls: Integration class (must inherit from Integration).

    Raises:
        TypeError: If integration_cls doesn't inherit from Integration.
        ValueError: If name is already registered.

    Example:
        >>> class MyIntegration(Integration):
        ...     @property
        ...     def name(self):
        ...         return "my_integration"
        ...     # ... implement other required methods
        >>> register_integration("my_integration", MyIntegration)
    """
    if not issubclass(integration_cls, Integration):
        raise TypeError(
            f"integration_cls must inherit from Integration, "
            f"got {integration_cls.__name__}"
        )

    normalized = name.lower().strip()
    if normalized in _INTEGRATIONS:
        raise ValueError(f"Integration '{name}' is already registered")

    _INTEGRATIONS[normalized] = integration_cls


def get_integration_info(name: str) -> dict[str, Any]:
    """Get information about an integration.

    Args:
        name: Integration name or alias.

    Returns:
        Dictionary with integration information.

    Raises:
        ValueError: If integration name is not recognized.
    """
    # Normalize name
    normalized = name.lower().strip()
    if normalized in _ALIASES:
        normalized = _ALIASES[normalized]

    if normalized not in _INTEGRATIONS:
        raise ValueError(f"Unknown integration: '{name}'")

    integration_cls = _INTEGRATIONS[normalized]

    # Create a temporary instance to get metadata
    try:
        temp = integration_cls()
        return {
            "name": normalized,
            "class": integration_cls.__name__,
            "hooks": temp.get_supported_hooks(),
            "doc": integration_cls.__doc__,
        }
    except Exception:
        # Return basic info if instantiation fails
        return {
            "name": normalized,
            "class": integration_cls.__name__,
            "hooks": [],
            "doc": integration_cls.__doc__,
        }


# Export public API
__all__ = [
    # Base types
    "ActionMode",
    "AgenticIntegration",
    "DetectionEvent",
    "HookConfig",
    "Integration",
    "IntegrationConfig",
    "InterceptionAction",
    "InterceptionResult",
    # Integration classes
    "ClaudeCodeIntegration",
    "MultiAgentIntegration",
    "ClawBotIntegration",
    # Factory functions
    "get_integration",
    "list_integrations",
    "register_integration",
    "get_integration_info",
]
