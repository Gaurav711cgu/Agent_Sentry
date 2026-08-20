import pytest
from agentsentry.firewall.ast_analyzer import CommandASTAnalyzer, PythonASTSecurityVisitor


def test_ast_detects_dangerous_imports():
    analyzer = CommandASTAnalyzer()
    malicious_code = """
import subprocess
import socket

def run_pwn():
    subprocess.Popen(["whoami"])
"""
    is_clean, findings = analyzer.analyze_python_source(malicious_code)
    assert not is_clean
    rules = [f["rule"] for f in findings]
    assert "SEC_AST_001_DANGEROUS_IMPORT" in rules
    assert "SEC_AST_003_DESTRUCTIVE_OS_CALL" in rules


def test_ast_detects_eval_exec():
    analyzer = CommandASTAnalyzer()
    eval_code = "result = eval('__import__(\"os\").system(\"id\")')"
    is_clean, findings = analyzer.analyze_python_source(eval_code)
    assert not is_clean
    rules = [f["rule"] for f in findings]
    assert "SEC_AST_002_DYNAMIC_EXECUTION" in rules


def test_ast_allows_benign_code():
    analyzer = CommandASTAnalyzer()
    clean_code = """
import math
import json

def calculate_stats(data):
    total = sum(data)
    mean = total / len(data)
    variance = sum((x - mean) ** 2 for x in data) / len(data)
    return {"mean": mean, "std": math.sqrt(variance)}
"""
    is_clean, findings = analyzer.analyze_python_source(clean_code)
    assert is_clean
    assert len(findings) == 0


def test_subshell_extraction():
    analyzer = CommandASTAnalyzer()
    cmd = "echo $(whoami) && cat `find /tmp -name pass`"
    subshells = analyzer.extract_subshells(cmd)
    assert "whoami" in subshells
    assert "find /tmp -name pass" in subshells
