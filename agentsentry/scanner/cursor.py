import os
import glob
from typing import List, Dict, Any
from agentsentry.scanner.rules.sec_rules import PlaintextSecretRule, PromptInjectionRule, UnsandboxedExecutionRule

class CursorScanner:
    def __init__(self):
        self.rules = [PlaintextSecretRule(), PromptInjectionRule(), UnsandboxedExecutionRule()]

    def scan_path(self, root_dir: str) -> List[Dict[str, Any]]:
        findings = []
        pattern = os.path.join(root_dir, ".cursor", "rules", "*.mdc")
        matching_files = glob.glob(pattern)
        
        for file_path in matching_files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                rel_path = os.path.relpath(file_path, root_dir)
                for rule in self.rules:
                    findings.extend(rule.check(content, rel_path))
            except Exception:
                pass
        return findings
