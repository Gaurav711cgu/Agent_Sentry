import os
from typing import List, Dict, Any
from agentsentry.scanner.rules.sec_rules import PlaintextSecretRule, PromptInjectionRule, UnsandboxedExecutionRule

class WindsurfScanner:
    def __init__(self):
        self.rules = [PlaintextSecretRule(), PromptInjectionRule(), UnsandboxedExecutionRule()]

    def scan_path(self, root_dir: str) -> List[Dict[str, Any]]:
        findings = []
        target_file = os.path.join(root_dir, ".windsurfrules")
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
