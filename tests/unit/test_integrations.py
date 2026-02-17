"""
Unit tests for the integrations module.

Tests the base integration interface and all platform-specific implementations.
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import pytest

from adapters.base import TrustLevel
from core.pipeline import Pipeline, PipelineResult
from integrations import (
    ActionMode,
    ClaudeCodeIntegration,
    ClawBotIntegration,
    DetectionEvent,
    HookConfig,
    Integration,
    IntegrationConfig,
    MultiAgentIntegration,
    get_integration,
    get_integration_info,
    list_integrations,
    register_integration,
)

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def mock_pipeline():
    """Create a mock pipeline that returns configurable results."""
    pipeline = MagicMock(spec=Pipeline)
    pipeline.scan.return_value = PipelineResult(
        is_injection=False,
        confidence=0.1,
        flagged=False,
        detectors_run=3,
        detectors_flagged=0,
    )
    pipeline.health_check.return_value = {"detector1": True, "detector2": True}
    return pipeline


@pytest.fixture
def injection_pipeline():
    """Create a mock pipeline that detects injection."""
    pipeline = MagicMock(spec=Pipeline)
    pipeline.scan.return_value = PipelineResult(
        is_injection=True,
        confidence=0.85,
        flagged=True,
        detectors_run=3,
        detectors_flagged=2,
    )
    return pipeline


@pytest.fixture
def temp_settings_dir():
    """Create a temporary directory for settings files."""
    with TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# ============================================================================
# Base Integration Tests
# ============================================================================


class TestIntegrationConfig:
    """Tests for IntegrationConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = IntegrationConfig()
        assert config.enabled is False
        assert config.action_mode == ActionMode.WARN
        assert config.warn_threshold == 0.5
        assert config.block_threshold == 0.8
        assert config.log_detections is True

    def test_custom_values(self):
        """Test custom configuration values."""
        config = IntegrationConfig(
            enabled=True,
            action_mode=ActionMode.BLOCK,
            warn_threshold=0.6,
            block_threshold=0.9,
        )
        assert config.enabled is True
        assert config.action_mode == ActionMode.BLOCK
        assert config.warn_threshold == 0.6
        assert config.block_threshold == 0.9


class TestHookConfig:
    """Tests for HookConfig dataclass."""

    def test_default_values(self):
        """Test default hook configuration."""
        hook = HookConfig(name="test_hook")
        assert hook.name == "test_hook"
        assert hook.enabled is True
        assert hook.action == ActionMode.WARN
        assert hook.threshold == 0.7

    def test_custom_values(self):
        """Test custom hook configuration."""
        hook = HookConfig(
            name="my_hook",
            enabled=False,
            action=ActionMode.BLOCK,
            threshold=0.9,
        )
        assert hook.name == "my_hook"
        assert hook.enabled is False
        assert hook.action == ActionMode.BLOCK


class TestDetectionEvent:
    """Tests for DetectionEvent dataclass."""

    def test_basic_event(self):
        """Test creating a basic detection event."""
        event = DetectionEvent(
            content="test content",
            confidence=0.8,
            source="test/source",
            trust_level=TrustLevel.USER,
            action_taken=ActionMode.WARN,
            hook_name="test_hook",
        )
        assert event.content == "test content"
        assert event.confidence == 0.8
        assert event.source == "test/source"
        assert event.trust_level == TrustLevel.USER
        assert event.action_taken == ActionMode.WARN


class TestActionMode:
    """Tests for ActionMode enum."""

    def test_action_values(self):
        """Test action mode values."""
        assert ActionMode.BLOCK.value == "block"
        assert ActionMode.WARN.value == "warn"
        assert ActionMode.LOG.value == "log"


# ============================================================================
# Claude Code Integration Tests
# ============================================================================


class TestClaudeCodeIntegration:
    """Tests for ClaudeCodeIntegration."""

    def test_name_property(self, mock_pipeline):
        """Test integration name."""
        integration = ClaudeCodeIntegration(pipeline=mock_pipeline)
        assert integration.name == "claude_code"

    def test_supported_hooks(self, mock_pipeline):
        """Test supported hooks list."""
        integration = ClaudeCodeIntegration(pipeline=mock_pipeline)
        hooks = integration.get_supported_hooks()
        assert "PreToolUse" in hooks
        assert "UserPromptSubmit" in hooks
        assert "PostToolUse" in hooks

    def test_map_source_user(self, mock_pipeline):
        """Test user source mapping."""
        integration = ClaudeCodeIntegration(pipeline=mock_pipeline)
        assert integration.map_source_to_trust("user_prompt") == TrustLevel.USER
        assert integration.map_source_to_trust("user/*") == TrustLevel.USER

    def test_map_source_mcp(self, mock_pipeline):
        """Test MCP source mapping."""
        integration = ClaudeCodeIntegration(pipeline=mock_pipeline)
        assert integration.map_source_to_trust("mcp") == TrustLevel.MCP
        assert integration.map_source_to_trust("mcp/*") == TrustLevel.MCP

    def test_map_source_tool(self, mock_pipeline):
        """Test tool source mapping."""
        integration = ClaudeCodeIntegration(pipeline=mock_pipeline)
        assert integration.map_source_to_trust("tool/bash") == TrustLevel.TOOL_OUTPUT
        assert integration.map_source_to_trust("tool_output") == TrustLevel.TOOL_OUTPUT

    def test_scan_hook_no_injection(self, mock_pipeline):
        """Test scanning with no injection detected."""
        integration = ClaudeCodeIntegration(pipeline=mock_pipeline)
        result = integration.scan_hook("PreToolUse", "safe content", {})
        assert result.proceed is True
        assert result.reason is None

    def test_scan_hook_with_injection(self, injection_pipeline):
        """Test scanning with injection detected."""
        integration = ClaudeCodeIntegration(pipeline=injection_pipeline)
        result = integration.scan_hook("PreToolUse", "malicious content", {})
        # 0.85 is above default block threshold 0.8, so it should block
        assert result.proceed is False
        assert result.reason is not None
        assert "blocked" in result.reason.lower()

    def test_scan_hook_blocks_high_confidence(self, mock_pipeline):
        """Test scanning blocks on high confidence."""
        # Configure to return high confidence
        mock_pipeline.scan.return_value = PipelineResult(
            is_injection=True,
            confidence=0.95,
            flagged=True,
            detectors_run=3,
            detectors_flagged=3,
        )
        integration = ClaudeCodeIntegration(pipeline=mock_pipeline)
        result = integration.scan_hook("PreToolUse", "malicious content", {})
        assert result.proceed is False
        assert "blocked" in result.reason.lower()

    def test_install_creates_settings(self, mock_pipeline, temp_settings_dir):
        """Test install creates settings file."""
        settings_path = temp_settings_dir / ".claude" / "settings.json"
        integration = ClaudeCodeIntegration(
            pipeline=mock_pipeline,
            settings_path=settings_path,
        )
        assert integration.install() is True
        assert settings_path.exists()

        with open(settings_path) as f:
            settings = json.load(f)
        assert "hooks" in settings
        assert "PreToolUse" in settings["hooks"]

    def test_uninstall_removes_hooks(self, mock_pipeline, temp_settings_dir):
        """Test uninstall removes hook configuration."""
        settings_path = temp_settings_dir / ".claude" / "settings.json"
        integration = ClaudeCodeIntegration(
            pipeline=mock_pipeline,
            settings_path=settings_path,
        )

        # Install first
        integration.install()

        # Then uninstall
        assert integration.uninstall() is True

        with open(settings_path) as f:
            settings = json.load(f)
        assert "hooks" not in settings or not settings.get("hooks")

    def test_generate_settings_snippet(self, mock_pipeline):
        """Test settings snippet generation."""
        integration = ClaudeCodeIntegration(pipeline=mock_pipeline)
        snippet = integration.generate_settings_snippet()
        parsed = json.loads(snippet)
        assert "hooks" in parsed

    def test_detection_callback(self, injection_pipeline):
        """Test detection callback is invoked."""
        integration = ClaudeCodeIntegration(pipeline=injection_pipeline)

        events = []
        integration.on_detection(lambda e: events.append(e))

        integration.scan_hook("PreToolUse", "malicious content", {})

        assert len(events) == 1
        assert events[0].hook_name == "PreToolUse"
        assert events[0].confidence == 0.85


# ============================================================================
# Multi-Agent Integration Tests
# ============================================================================


class TestMultiAgentIntegration:
    """Tests for MultiAgentIntegration."""

    def test_name_property(self, mock_pipeline):
        """Test integration name."""
        integration = MultiAgentIntegration(pipeline=mock_pipeline)
        assert integration.name == "multiagent"

    def test_supported_hooks(self, mock_pipeline):
        """Test supported hooks list."""
        integration = MultiAgentIntegration(pipeline=mock_pipeline)
        hooks = integration.get_supported_hooks()
        assert "mail.before" in hooks
        assert "tool.before" in hooks
        assert "mcp.response" in hooks

    def test_map_source_mayor(self, mock_pipeline):
        """Test mayor source has high trust."""
        integration = MultiAgentIntegration(pipeline=mock_pipeline)
        assert integration.map_source_to_trust("mail/mayor") == TrustLevel.USER

    def test_map_source_witness(self, mock_pipeline):
        """Test witness source has high trust."""
        integration = MultiAgentIntegration(pipeline=mock_pipeline)
        assert integration.map_source_to_trust("mail/witness") == TrustLevel.USER

    def test_map_source_polecat(self, mock_pipeline):
        """Test polecat source has medium trust."""
        integration = MultiAgentIntegration(pipeline=mock_pipeline)
        assert integration.map_source_to_trust("mail/polecat") == TrustLevel.MCP

    def test_map_source_external(self, mock_pipeline):
        """Test external source has low trust."""
        integration = MultiAgentIntegration(pipeline=mock_pipeline)
        assert integration.map_source_to_trust("mail/external/someone") == TrustLevel.TOOL_OUTPUT

    def test_scan_hook_no_injection(self, mock_pipeline):
        """Test scanning with no injection."""
        integration = MultiAgentIntegration(pipeline=mock_pipeline)
        result = integration.scan_hook("mail.before", "safe content", {"sender": "mayor/"})
        assert result.allow is True
        assert result.escalate is False

    def test_scan_hook_with_injection(self, injection_pipeline):
        """Test scanning with injection detected."""
        integration = MultiAgentIntegration(pipeline=injection_pipeline)
        result = integration.scan_hook("mail.before", "malicious", {"sender": "external/attacker"})
        # 0.85 >= IntegrationConfig default block_threshold 0.8, so blocks
        assert result.allow is False
        assert result.escalate is True  # 0.85 >= escalate threshold 0.85
        assert result.reason is not None

    def test_escalation_triggered(self, mock_pipeline):
        """Test escalation on high confidence."""
        mock_pipeline.scan.return_value = PipelineResult(
            is_injection=True,
            confidence=0.90,
            flagged=True,
            detectors_run=3,
            detectors_flagged=3,
        )
        integration = MultiAgentIntegration(
            pipeline=mock_pipeline,
            escalate_threshold=0.85,
        )

        with patch("subprocess.run") as mock_run:
            result = integration.scan_hook("mail.before", "malicious", {})
            assert result.escalate is True
            # Escalation should attempt to send mail
            mock_run.assert_called_once()

    def test_scan_mail_convenience(self, mock_pipeline):
        """Test scan_mail convenience method."""
        integration = MultiAgentIntegration(pipeline=mock_pipeline)
        result = integration.scan_mail("content", "mayor/", "Test Subject")
        assert result.allow is True

    def test_scan_tool_input_convenience(self, mock_pipeline):
        """Test scan_tool_input convenience method."""
        integration = MultiAgentIntegration(pipeline=mock_pipeline)
        result = integration.scan_tool_input("content", "bash")
        assert result.allow is True

    def test_install_uninstall(self, mock_pipeline):
        """Test install and uninstall."""
        integration = MultiAgentIntegration(pipeline=mock_pipeline)
        assert integration.install() is True
        assert integration.is_installed is True
        assert integration.uninstall() is True
        assert integration.is_installed is False


# ============================================================================
# ClawBot Integration Tests
# ============================================================================


class TestClawBotIntegration:
    """Tests for ClawBotIntegration stub."""

    def test_name_property(self, mock_pipeline):
        """Test integration name."""
        integration = ClawBotIntegration(pipeline=mock_pipeline)
        assert integration.name == "clawbot"

    def test_is_stub(self, mock_pipeline):
        """Test stub flag is set."""
        integration = ClawBotIntegration(pipeline=mock_pipeline)
        assert integration.is_stub is True

    def test_supported_hooks(self, mock_pipeline):
        """Test supported hooks list."""
        integration = ClawBotIntegration(pipeline=mock_pipeline)
        hooks = integration.get_supported_hooks()
        assert "message.before" in hooks
        assert "command.before" in hooks
        assert "webhook.incoming" in hooks

    def test_map_source_dm(self, mock_pipeline):
        """Test DM context has high trust."""
        integration = ClawBotIntegration(pipeline=mock_pipeline)
        assert integration.map_source_to_trust("dm/channel123") == TrustLevel.USER

    def test_map_source_channel(self, mock_pipeline):
        """Test channel context has medium trust."""
        integration = ClawBotIntegration(pipeline=mock_pipeline)
        assert integration.map_source_to_trust("channel/channel123") == TrustLevel.MCP

    def test_map_source_webhook(self, mock_pipeline):
        """Test webhook context has low trust."""
        integration = ClawBotIntegration(pipeline=mock_pipeline)
        assert integration.map_source_to_trust("webhook/hook123") == TrustLevel.TOOL_OUTPUT

    def test_scan_message_safe(self, mock_pipeline):
        """Test scanning safe message."""
        integration = ClawBotIntegration(pipeline=mock_pipeline)
        result = integration.scan_message("Hello!", context_type="channel")
        assert result.safe is True
        assert result.confidence < 0.5

    def test_scan_message_injection(self, injection_pipeline):
        """Test scanning malicious message."""
        integration = ClawBotIntegration(pipeline=injection_pipeline)
        result = integration.scan_message("malicious", context_type="channel")
        assert result.safe is False
        assert result.confidence == 0.85
        assert result.warning is not None

    def test_scan_webhook(self, mock_pipeline):
        """Test webhook scanning."""
        integration = ClawBotIntegration(pipeline=mock_pipeline)
        result = integration.scan_webhook({"content": "webhook message"})
        assert result.safe is True

    def test_api_scan(self, mock_pipeline):
        """Test API scan endpoint."""
        integration = ClawBotIntegration(pipeline=mock_pipeline)
        response = integration.api_scan({
            "content": "test message",
            "context_type": "dm",
            "user_id": "user123",
        })
        assert "safe" in response
        assert response["safe"] is True

    def test_api_health(self, mock_pipeline):
        """Test API health endpoint."""
        integration = ClawBotIntegration(pipeline=mock_pipeline)
        integration.install()
        health = integration.api_health()
        assert health["status"] == "healthy"
        assert health["integration"] == "clawbot"
        assert health["is_stub"] is True


# ============================================================================
# Factory Function Tests
# ============================================================================


class TestGetIntegration:
    """Tests for get_integration factory function."""

    def test_get_claude_code(self):
        """Test getting Claude Code integration."""
        integration = get_integration("claude_code")
        assert isinstance(integration, ClaudeCodeIntegration)
        assert integration.name == "claude_code"

    def test_get_multiagent(self):
        """Test getting Multi-Agent integration."""
        integration = get_integration("multiagent")
        assert isinstance(integration, MultiAgentIntegration)
        assert integration.name == "multiagent"

    def test_get_clawbot(self):
        """Test getting ClawBot integration."""
        integration = get_integration("clawbot")
        assert isinstance(integration, ClawBotIntegration)
        assert integration.name == "clawbot"

    def test_alias_cc(self):
        """Test 'cc' alias for claude_code."""
        integration = get_integration("cc")
        assert isinstance(integration, ClaudeCodeIntegration)

    def test_alias_ma(self):
        """Test 'ma' alias for multiagent."""
        integration = get_integration("ma")
        assert isinstance(integration, MultiAgentIntegration)

    def test_alias_discord(self):
        """Test 'discord' alias for clawbot."""
        integration = get_integration("discord")
        assert isinstance(integration, ClawBotIntegration)

    def test_case_insensitive(self):
        """Test case insensitivity."""
        integration = get_integration("CLAUDE_CODE")
        assert isinstance(integration, ClaudeCodeIntegration)

    def test_unknown_raises(self):
        """Test unknown integration raises ValueError."""
        with pytest.raises(ValueError, match="Unknown integration"):
            get_integration("nonexistent")

    def test_with_config(self):
        """Test passing configuration."""
        config = IntegrationConfig(enabled=True, action_mode=ActionMode.BLOCK)
        integration = get_integration("claude_code", config=config)
        assert integration.config.enabled is True
        assert integration.config.action_mode == ActionMode.BLOCK


class TestListIntegrations:
    """Tests for list_integrations function."""

    def test_returns_list(self):
        """Test returns a list."""
        integrations = list_integrations()
        assert isinstance(integrations, list)

    def test_contains_all(self):
        """Test contains all integrations."""
        integrations = list_integrations()
        assert "claude_code" in integrations
        assert "multiagent" in integrations
        assert "clawbot" in integrations

    def test_sorted(self):
        """Test list is sorted."""
        integrations = list_integrations()
        assert integrations == sorted(integrations)


class TestRegisterIntegration:
    """Tests for register_integration function."""

    def test_register_new(self):
        """Test registering a new integration."""
        class TestIntegration(Integration):
            @property
            def name(self):
                return "test_integration"

            def install(self):
                return True

            def uninstall(self):
                return True

            def map_source_to_trust(self, source):
                return TrustLevel.USER

            def get_supported_hooks(self):
                return []

        register_integration("test_new", TestIntegration)
        integration = get_integration("test_new")
        assert integration.name == "test_integration"

    def test_register_non_integration_raises(self):
        """Test registering non-Integration class raises TypeError."""
        with pytest.raises(TypeError):
            register_integration("bad", str)


class TestGetIntegrationInfo:
    """Tests for get_integration_info function."""

    def test_returns_info(self):
        """Test returns integration info."""
        info = get_integration_info("claude_code")
        assert info["name"] == "claude_code"
        assert info["class"] == "ClaudeCodeIntegration"
        assert "hooks" in info
        assert len(info["hooks"]) > 0

    def test_unknown_raises(self):
        """Test unknown integration raises ValueError."""
        with pytest.raises(ValueError):
            get_integration_info("nonexistent")
