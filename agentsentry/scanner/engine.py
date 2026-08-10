import os
from typing import List, Dict, Any
from agentsentry.scanner.cursor import CursorScanner
from agentsentry.scanner.windsurf import WindsurfScanner
from agentsentry.scanner.copilot import CopilotScanner
from agentsentry.scanner.mcp_generic import MCPGenericScanner
from agentsentry.scanner.reporter import ScanReporter

class ScanEngine:
    def __init__(self):
        self.scanners = [
            CursorScanner(),
            WindsurfScanner(),
            CopilotScanner(),
            MCPGenericScanner()
        ]

    def scan(self, target_dir: str = ".") -> ScanReporter:
        target_dir = os.path.abspath(target_dir)
        all_findings = []
        
        for scanner in self.scanners:
            findings = scanner.scan_path(target_dir)
            all_findings.extend(findings)
            
        # Count scanned configuration files
        count = 0
        if os.path.exists(os.path.join(target_dir, ".windsurfrules")):
            count += 1
        if os.path.exists(os.path.join(target_dir, ".github", "copilot-instructions.md")):
            count += 1
        for f in [".mcp.json", "mcp.json", ".mcp_config.json"]:
            if os.path.exists(os.path.join(target_dir, f)):
                count += 1
        cursor_dir = os.path.join(target_dir, ".cursor", "rules")
        if os.path.exists(cursor_dir):
            count += len(os.listdir(cursor_dir))
            
        return ScanReporter(all_findings, max(count, 1))
