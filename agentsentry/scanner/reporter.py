import json
from typing import List, Dict, Any

class ScanReporter:
    def __init__(self, findings: List[Dict[str, Any]], files_scanned_count: int):
        self.findings = findings
        self.files_scanned_count = files_scanned_count

    def generate_summary(self) -> Dict[str, Any]:
        critical = sum(1 for f in self.findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in self.findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in self.findings if f.get("severity") == "MEDIUM")
        low = sum(1 for f in self.findings if f.get("severity") == "LOW")
        return {
            "files_scanned": self.files_scanned_count,
            "total_findings": len(self.findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        }

    def to_json(self) -> str:
        data = {
            "summary": self.generate_summary(),
            "findings": self.findings
        }
        return json.dumps(data, indent=2)

    def print_console(self):
        summary = self.generate_summary()
        print("\n=== AgentSentry Static Security Scan Results ===")
        print(f"Files Scanned: {summary['files_scanned']}")
        print(f"Total Findings: {summary['total_findings']} (Critical: {summary['critical']}, High: {summary['high']}, Medium: {summary['medium']}, Low: {summary['low']})\n")
        
        if not self.findings:
            print("Status: CLEAN (0 security findings detected)")
            return

        for idx, f in enumerate(self.findings, 1):
            print(f"[{idx}] {f['severity']} - {f['rule_id']} ({f['file_path']}:L{f['line_number']})")
            print(f"    Description: {f['description']}")
            print(f"    Remediation: {f['remediation']}\n")
