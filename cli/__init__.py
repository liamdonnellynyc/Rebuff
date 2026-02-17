"""
CLI entry point for the prompt injection detector suite.

This module provides the command-line interface for scanning content,
managing configuration, and performing operational tasks.

Usage:
    gt injection scan --source user --content "text to scan"
    gt injection config show
    gt injection health
"""

from cli.commands import cli, main

__all__ = ["cli", "main"]
