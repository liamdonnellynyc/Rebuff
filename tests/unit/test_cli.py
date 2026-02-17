"""
Unit tests for the CLI commands module.
"""

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from adapters.base import TrustLevel
from cli.commands import (
    EXIT_INJECTION_DETECTED,
    EXIT_SUCCESS,
    cli,
    format_result,
    source_to_trust_level,
)
from core.pipeline import PipelineResult


class TestSourceToTrustLevel:
    """Tests for source_to_trust_level function."""

    def test_user_source(self):
        assert source_to_trust_level("user") == TrustLevel.USER
        assert source_to_trust_level("USER") == TrustLevel.USER

    def test_mcp_source(self):
        assert source_to_trust_level("mcp") == TrustLevel.MCP
        assert source_to_trust_level("MCP") == TrustLevel.MCP

    def test_tool_output_source(self):
        assert source_to_trust_level("tool_output") == TrustLevel.TOOL_OUTPUT
        assert source_to_trust_level("TOOL_OUTPUT") == TrustLevel.TOOL_OUTPUT

    def test_unknown_source_defaults_to_user(self):
        assert source_to_trust_level("unknown") == TrustLevel.USER
        assert source_to_trust_level("something_else") == TrustLevel.USER


class TestFormatResult:
    """Tests for format_result function."""

    def test_format_clean_result(self):
        result = PipelineResult(
            is_injection=False,
            confidence=0.2,
            flagged=False,
            detectors_run=3,
            detectors_flagged=0,
            total_latency_ms=10.5,
            trust_level_used="user",
        )
        output = format_result(result, json_output=False)

        assert "CLEAN" in output
        assert "20.0%" in output
        assert "user" in output
        assert "0/3" in output
        assert "10.5ms" in output

    def test_format_injection_result(self):
        result = PipelineResult(
            is_injection=True,
            confidence=0.85,
            flagged=True,
            detectors_run=3,
            detectors_flagged=2,
            total_latency_ms=15.2,
            trust_level_used="mcp",
        )
        output = format_result(result, json_output=False)

        assert "INJECTION DETECTED" in output
        assert "85.0%" in output
        assert "2/3" in output

    def test_format_json_output(self):
        result = PipelineResult(
            is_injection=False,
            confidence=0.3,
            flagged=False,
            detectors_run=2,
            detectors_flagged=0,
            total_latency_ms=5.0,
        )
        output = format_result(result, json_output=True)
        data = json.loads(output)

        assert data["is_injection"] is False
        assert data["confidence"] == 0.3
        assert data["flagged"] is False
        assert data["detectors_run"] == 2
        assert data["detector_results"] == []


class TestCliHelp:
    """Tests for CLI help commands."""

    def test_main_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "Prompt injection detection suite CLI" in result.output
        assert "scan" in result.output
        assert "config" in result.output
        assert "health" in result.output

    def test_scan_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])

        assert result.exit_code == 0
        assert "--source" in result.output
        assert "--content" in result.output
        assert "--file" in result.output
        assert "--batch" in result.output


class TestScanCommand:
    """Tests for the scan command."""

    def test_scan_with_content(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--source", "user", "--content", "Hello world"])

        assert result.exit_code == EXIT_SUCCESS
        assert "Status:" in result.output

    def test_scan_with_json_output(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "scan", "--source", "user", "--content", "Test"])

        assert result.exit_code == EXIT_SUCCESS
        data = json.loads(result.output)
        assert "is_injection" in data
        assert "confidence" in data
        assert "detector_results" in data

    def test_scan_requires_input(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--source", "user"])

        assert result.exit_code != 0
        assert "Must specify" in result.output

    def test_scan_mutually_exclusive_inputs(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--content", "a", "--batch"])

        assert result.exit_code != 0
        assert "mutually exclusive" in result.output

    def test_scan_with_file(self, tmp_path):
        test_file = tmp_path / "test_input.txt"
        test_file.write_text("Hello from file")

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--source", "mcp", "--file", str(test_file)])

        # Exit code 0 (clean) or 1 (injection detected) are both valid
        # depending on whether real ML services are running
        assert result.exit_code in [EXIT_SUCCESS, EXIT_INJECTION_DETECTED]
        assert "Status:" in result.output

    def test_scan_different_sources(self):
        runner = CliRunner()

        for source in ["user", "mcp", "tool_output"]:
            result = runner.invoke(cli, ["scan", "--source", source, "--content", "test"])
            assert result.exit_code == EXIT_SUCCESS


class TestBatchScan:
    """Tests for batch scanning."""

    def test_batch_scan_jsonl(self):
        runner = CliRunner()
        input_data = '{"content": "Hello", "source": "user"}\n{"content": "World", "source": "mcp"}'

        result = runner.invoke(cli, ["scan", "--batch"], input=input_data)

        assert result.exit_code == EXIT_SUCCESS
        assert "Line 1:" in result.output
        assert "Line 2:" in result.output

    def test_batch_scan_json_output(self):
        runner = CliRunner()
        input_data = '{"content": "Test"}'

        result = runner.invoke(cli, ["--json", "scan", "--batch"], input=input_data)

        assert result.exit_code == EXIT_SUCCESS
        data = json.loads(result.output)
        assert "results" in data
        assert len(data["results"]) == 1

    def test_batch_scan_invalid_json(self):
        runner = CliRunner()
        input_data = 'not valid json\n{"content": "valid"}'

        result = runner.invoke(cli, ["scan", "--batch"], input=input_data)

        # Should still process valid lines
        assert "Invalid JSON" in result.output
        assert "Line 2:" in result.output


class TestConfigCommand:
    """Tests for configuration commands."""

    def test_config_show(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "show"])

        assert result.exit_code == 0
        assert "Pipeline Configuration:" in result.output
        assert "Trust Levels:" in result.output

    def test_config_show_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "config", "show"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "pipeline" in data
        assert "trust_levels" in data
        assert "source_mapping" in data

    def test_config_set_valid_path(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "set", "pipeline.threshold", "0.8"])

        assert result.exit_code == 0
        assert "Validated" in result.output

    def test_config_set_invalid_value(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "set", "pipeline.strategy", "invalid"])

        assert result.exit_code != 0
        assert "Invalid value" in result.output


class TestHealthCommand:
    """Tests for health check command."""

    @patch("cli.commands.Pipeline")
    def test_health_check(self, mock_pipeline_class):
        mock_pipeline = MagicMock()
        mock_pipeline.health_check.return_value = {
            "puppetry": True,
            "pytector": True,
            "piguard": True,
            "llmguard": True,
        }
        mock_pipeline_class.return_value = mock_pipeline

        runner = CliRunner()
        result = runner.invoke(cli, ["health"])

        assert result.exit_code == 0
        assert "Detector Health Status:" in result.output
        assert "OK" in result.output

    @patch("cli.commands.Pipeline")
    def test_health_check_json(self, mock_pipeline_class):
        mock_pipeline = MagicMock()
        mock_pipeline.health_check.return_value = {
            "puppetry": True,
            "pytector": True,
            "piguard": True,
            "llmguard": True,
        }
        mock_pipeline_class.return_value = mock_pipeline

        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "health"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "healthy" in data
        assert "detectors" in data


class TestWarmupCommand:
    """Tests for warmup command."""

    def test_warmup(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["warmup"])

        assert result.exit_code == 0
        assert "Warmup complete" in result.output
        assert "Detectors ready" in result.output

    def test_warmup_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "warmup"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ready"
        assert "warmup_ms" in data
        assert "detectors" in data


class TestBenchmarkCommand:
    """Tests for benchmark command."""

    def test_benchmark(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["benchmark", "-n", "2"])

        assert result.exit_code == 0
        assert "Benchmark Results" in result.output
        assert "Average:" in result.output
        assert "P95:" in result.output

    def test_benchmark_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "benchmark", "-n", "2"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["iterations"] == 2
        assert "latency_ms" in data
        assert "avg" in data["latency_ms"]


class TestUpstreamCommands:
    """Tests for upstream management commands."""

    def test_upstream_check(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["upstream", "check"])

        assert result.exit_code == 0
        assert "Upstream Version Check:" in result.output

    def test_upstream_check_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "upstream", "check"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "detectors" in data
        assert "all_up_to_date" in data

    def test_upstream_update(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["upstream", "update"])

        assert result.exit_code == 0
        assert "Update Status:" in result.output

    def test_upstream_pin(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["upstream", "pin"])

        assert result.exit_code == 0
        assert "Pinned Versions:" in result.output
