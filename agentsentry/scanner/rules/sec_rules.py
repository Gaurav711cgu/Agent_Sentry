import re
from typing import List, Dict, Any

class Rule:
    def __init__(self, rule_id: str, name: str, severity: str, description: str, remediation: str):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.description = description
        self.remediation = remediation

    def check(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

class PlaintextSecretRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="SEC001_PLAINTEXT_SECRET",
            name="Plaintext Secret / API Key Exposure",
            severity="HIGH",
            description="Hardcoded API key or credential detected in configuration file.",
            remediation="Extract credentials into process environment variables (e.g., ${ENV_VAR})."
        )
        self.patterns = [
            (r'sk-[a-zA-Z0-9]{32,}', "OpenAI API Key"),
            (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
            (r'xoxb-[0-9]{10,}-[a-zA-Z0-9]{24}', "Slack Bot Token"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'bearer\s+[a-zA-Z0-9\._\-]{30,}', "Bearer Authentication Token"),
        ]

    def check(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            for pattern, secret_type in self.patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "rule_id": self.rule_id,
                        "severity": self.severity,
                        "file_path": file_path,
                        "line_number": idx,
                        "description": f"{self.description} ({secret_type})",
                        "remediation": self.remediation
                    })
        return findings

class PromptInjectionRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="SEC002_SYSTEM_PROMPT_INJECTION",
            name="System Prompt Override / Injection Vector",
            severity="HIGH",
            description="Potentially dangerous system prompt override instruction detected.",
            remediation="Remove unconstrained override instructions or wrap input in protective guardrails."
        )
        self.phrases = [
            r"ignore\s+(all\s+)?previous\s+instructions",
            r"override\s+(all\s+)?security\s+filters",
            r"you\s+are\s+now\s+in\s+developer\s+mode",
            r"disable\s+(all\s+)?safety\s+checks",
            r"execute\s+arbitrary\s+shell\s+command"
        ]

    def check(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            for phrase in self.phrases:
                if re.search(phrase, line, re.IGNORECASE):
                    findings.append({
                        "rule_id": self.rule_id,
                        "severity": self.severity,
                        "file_path": file_path,
                        "line_number": idx,
                        "description": f"{self.description} Matching phrase: '{phrase}'",
                        "remediation": self.remediation
                    })
        return findings

class UnsandboxedExecutionRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="SEC003_UNSANDBOXED_EXECUTION",
            name="Unrestricted Tool / Shell Execution Permission",
            severity="CRITICAL",
            description="Configuration grants unrestricted shell execution or auto-approval without sandboxing.",
            remediation="Restrict tool permissions, require manual confirmation for command execution, or run inside a seccomp container."
        )
        self.patterns = [
            r'"auto_approve"\s*:\s*true',
            r'"allow_all_commands"\s*:\s*true',
            r'"bypass_sandbox"\s*:\s*true',
            r'sudo\s+bash',
            r'rm\s+-rf\s+/',
        ]

    def check(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            for pattern in self.patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "rule_id": self.rule_id,
                        "severity": self.severity,
                        "file_path": file_path,
                        "line_number": idx,
                        "description": f"{self.description} Found pattern: '{pattern}'",
                        "remediation": self.remediation
                    })
        return findings
