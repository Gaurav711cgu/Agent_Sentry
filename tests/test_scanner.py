import os
import tempfile
import pytest
from agentsentry.scanner.engine import ScanEngine

def test_static_scanner_clean():
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = ScanEngine()
        reporter = engine.scan(tmpdir)
        summary = reporter.generate_summary()
        assert summary["total_findings"] == 0
        assert summary["critical"] == 0

def test_static_scanner_detects_secret():
    with tempfile.TemporaryDirectory() as tmpdir:
        mcp_file = os.path.join(tmpdir, ".mcp.json")
        with open(mcp_file, "w") as f:
            f.write('{"env": {"OPENAI_KEY": "sk-abcdef123456789012345678901234567890"}}')
            
        engine = ScanEngine()
        reporter = engine.scan(tmpdir)
        summary = reporter.generate_summary()
        assert summary["total_findings"] >= 1
        assert summary["high"] >= 1

def test_static_scanner_detects_unsandboxed_exec():
    with tempfile.TemporaryDirectory() as tmpdir:
        cursor_dir = os.path.join(tmpdir, ".cursor", "rules")
        os.makedirs(cursor_dir)
        rule_file = os.path.join(cursor_dir, "rule.mdc")
        with open(rule_file, "w") as f:
            f.write('{"allow_all_commands": true}')
            
        engine = ScanEngine()
        reporter = engine.scan(tmpdir)
        summary = reporter.generate_summary()
        assert summary["total_findings"] >= 1
        assert summary["critical"] >= 1
