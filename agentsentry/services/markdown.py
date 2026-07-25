from typing import Dict, Any, List, Optional

def compile_report_markdown(
    decision: str,
    reason: str,
    static_score: float,
    vulnerabilities: List[Dict[str, Any]],
    test_command: str,
    sandbox_logs: Optional[Dict[str, Any]]
) -> str:
    """
    Compiles a beautiful markdown validation report for GitLab merge request threads.
    """
    decision_emoji = "✅" if decision == "APPROVED" else "❌"
    status_color = "green" if decision == "APPROVED" else "red"
    
    report = []
    report.append(f"## {decision_emoji} DevSecOps Sentinel Audit Report")
    report.append(f"**Verification Status:** <span style='color:{status_color}; font-weight:bold'>{decision}</span>")
    report.append(f"**Details:** {reason}\n")
    report.append("---")
    report.append("### 🛡️ Static Vulnerability Review")
    report.append(f"* **Code Safety Score:** `{static_score} / 10.0`\n")
    
    if vulnerabilities:
        report.append("| File | Line | Severity | Issue |")
        report.append("| :--- | :---: | :---: | :--- |")
        for v in vulnerabilities:
            report.append(f"| `{v['file']}` | `{v['line']}` | **{v['severity']}** | {v['issue']} |")
        report.append("")
    else:
        report.append("🎉 No static vulnerabilities detected.")
        
    report.append("---")
    report.append("### 🧪 Dynamic Sandbox Execution")
    if test_command:
        report.append(f"* **Command Invoked:** `{test_command}`")
        if sandbox_logs:
            if sandbox_logs.get("status") == "blocked":
                report.append("* **Status:** 🔴 **BLOCKED (Security Deflection)**")
                report.append(f"* **Reason:** `{sandbox_logs.get('reason')}`")
            else:
                status_emoji = "🟢 Pass" if sandbox_logs.get("return_code") == 0 else "🔴 Fail"
                report.append(f"* **Execution Status:** {status_emoji} (Exit Code: `{sandbox_logs.get('return_code')}`)")
                stdout_str = sandbox_logs.get("stdout", "").strip()
                stderr_str = sandbox_logs.get("stderr", "").strip()
                if stdout_str:
                    report.append(f"\n**Standard Output:**\n```text\n{stdout_str}\n```")
                if stderr_str:
                    report.append(f"\n**Standard Error:**\n```text\n{stderr_str}\n```")
        else:
            report.append("* **Status:** Run timed out or connection failed.")
    else:
        report.append("⏭️ No test executions defined in diff. Skipping dynamic testing.")
        
    report.append("\n*Report generated autonomously by **AgentSentry** (formerly GitLabSentry).*")
    return "\n".join(report)
