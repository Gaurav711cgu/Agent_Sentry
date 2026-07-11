import logging
from agentsentry.config import AgentSentryConfig
from agentsentry.services.gemini import call_gemini_reviewer
from agentsentry.services.markdown import compile_report_markdown
from agentsentry.tools.gitlab_mcp import GitLabMCPWrapper

logger = logging.getLogger("AgentSentry.Agent")

class DevSecOpsSentinelAgent:
    def __init__(self, config: AgentSentryConfig):
        self.config = config
        self.gitlab_mcp = GitLabMCPWrapper(config)
        # Note: We now use the local AgentSentry instance (via state) instead of an external executor

    async def execute_agent_loop(
        self,
        project_id: int,
        mr_iid: int,
        source_branch: str,
        target_branch: str,
        last_commit_sha: str
    ):
        """
        Orchestrates the multi-step audit loop:
        1. Fetch MR details and diff content from GitLab.
        2. Invoke Gemini for static analysis and fetch test instructions.
        3. Execute test commands in AgentSentry sandbox.
        4. Post reviews and merge/block MR based on results.
        """
        logger.info(f"Starting DevSecOps Sentinel review for Project {project_id} MR {mr_iid}")

        # Step 1: Fetch MR diff content
        try:
            mr_diff = await self.gitlab_mcp.fetch_mr_diff(project_id, mr_iid)
            if not mr_diff:
                logger.warning("No diff found or merge request empty. Exiting execution loop.")
                return
        except Exception as e:
            logger.error(f"Failed to fetch MR details: {str(e)}")
            return

        # Step 2: Trigger static scan via Gemini
        logger.info("Executing static vulnerability review via Gemini...")
        audit_results = await call_gemini_reviewer(self.config, mr_diff)
        
        static_score = audit_results.get("score", 10.0)
        vulnerabilities = audit_results.get("vulnerabilities", [])
        test_command = audit_results.get("execution_command", "")

        logger.info(f"Vulnerability audit completed. Static Score: {static_score}/10")
        
        # Step 3: Trigger dynamic testing sandbox via AgentSentry if command is found
        sandbox_logs = None
        sandbox_success = True
        security_deflection = False

        if test_command:
            logger.info(f"Dynamic testing instruction found: '{test_command}'. Initiating sandbox...")
            try:
                from agentsentry.core import state
                import asyncio
                
                gateway = state.gateway_instance
                if gateway:
                    loop = asyncio.get_event_loop()
                    is_safe, ret_code, stdout, stderr = await loop.run_in_executor(
                        None, gateway.firewall.execute_safely, test_command
                    )
                    
                    sandbox_logs = {
                        "status": "blocked" if not is_safe else "executed",
                        "return_code": ret_code,
                        "stdout": stdout,
                        "stderr": stderr,
                        "reason": stderr if not is_safe else ""
                    }
                    
                    if not is_safe:
                        security_deflection = True
                        sandbox_success = False
                        logger.warning(f"SECURITY DEFLECTION: AgentSentry blocked script payload: {stderr}")
                    elif ret_code != 0:
                        sandbox_success = False
                        logger.warning(f"Sandbox tests failed with return code: {ret_code}")
                    else:
                        logger.info("Sandbox verification command executed successfully.")
                else:
                    logger.error("AgentSentry gateway not initialized.")
                    sandbox_success = False
            except Exception as e:
                logger.error(f"Error executing command in sandbox: {str(e)}")
                sandbox_success = False
        else:
            logger.info("No test script execution instructions found. Skipping dynamic verification phase.")

        # Step 4: Compile findings and post review
        decision = "APPROVED"
        reason = "All validation criteria passed."

        if static_score < 7.5:
            decision = "REJECTED"
            reason = f"Static security audit score {static_score}/10 is below compliance threshold."
        elif security_deflection:
            decision = "REJECTED"
            reason = "Security injection vulnerability detected and blocked during dynamic sandbox execution checks."
        elif not sandbox_success:
            decision = "REJECTED"
            reason = "Verification tests failed during dynamic container execution checks."

        logger.info(f"Validation Decision: {decision}. Reason: {reason}")

        # Post inline code review comments for each vulnerability found
        for vuln in vulnerabilities:
            try:
                file_path = vuln.get("file", "unknown")
                line_number = vuln.get("line", 1)
                severity = vuln.get("severity", "MEDIUM")
                issue = vuln.get("issue", "Unspecified issue")
                remediation = vuln.get("remediation", "No remediation specified")
                
                comment_body = (
                    f"⚠️ **[{severity}] Security Issue:** {issue}\n"
                    f"💡 **Suggested Remediation:** {remediation}"
                )
                await self.gitlab_mcp.post_inline_comment(
                    project_id=project_id,
                    mr_iid=mr_iid,
                    commit_sha=last_commit_sha,
                    file_path=file_path,
                    line_number=line_number,
                    body=comment_body
                )
            except Exception as e:
                logger.error(f"Failed to post inline comment for {vuln.get('file', 'unknown')}:L{vuln.get('line', 1)}: {str(e)}")

        # Post overall summary report
        report_md = compile_report_markdown(
            decision, reason, static_score, vulnerabilities, test_command, sandbox_logs
        )
        await self.gitlab_mcp.post_mr_discussion(project_id, mr_iid, report_md)

        # Merge MR autonomously if approved
        if decision == "APPROVED":
            logger.info(f"Auto-merging Merge Request {mr_iid}...")
            await self.gitlab_mcp.accept_merge_request(project_id, mr_iid)
        else:
            logger.info(f"Merge Request {mr_iid} blocks merge due to compliance validation failure.")
