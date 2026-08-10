import os
import glob
from typing import List, Dict, Any
from agentsentry.scanner.rules.sec_rules import PlaintextSecretRule, PromptInjectionRule, UnsandboxedExecutionRule

class MCPGenericScanner:
    def __init__(self):
        self.rules = [PlaintextSecretRule(), PromptInjectionRule(), UnsandboxedExecutionRule()]

    def scan_path(self, root_dir: str) -> List[Dict[str, Any]]:
        findings = []
        possible_files = [
            os.path.join(root_dir, ".mcp.json"),
            os.path.join(root_dir, "mcp.json"),
            os.path.join(root_dir, ".mcp_config.json")
        ]
        for target_file in possible_files:
            if os.path.exists(target_file):
                try:
                    with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    rel_path = os.path.relpath(target_file, root_dir)
                    for rule in self.rules:
                        findings.extend(rule.check(content, rel_path))
                except Exception:
                    pass
        return findings
