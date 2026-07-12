import os
import logging
from typing import Dict, Any, Tuple, List

from .obfuscation import ObfuscationDecoder
from .path_containment import PathContainmentValidator
from .signature import SignatureMatcher
from .ast_analyzer import CommandASTAnalyzer
from .sandbox import SandboxedExecutor

logger = logging.getLogger("AgentSentry.Firewall")

class AgentFirewall:
    def __init__(self, workspace_root: str, blocked_binaries: List[str] = None, destructive_patterns: List[str] = None, use_docker: bool = False):
        self.workspace_root = workspace_root
        self.decoder = ObfuscationDecoder()
        self.path_validator = PathContainmentValidator(workspace_root)
        self.signature_matcher = SignatureMatcher()
        self.ast_analyzer = CommandASTAnalyzer()
        self.sandbox = SandboxedExecutor(use_docker=use_docker)

        # Configurable properties
        self.blocked_binaries = set(blocked_binaries) if blocked_binaries else {
            "curl", "wget", "nc", "netcat", "nmap", "ssh", "scp",
            "sftp", "ftp", "telnet", "systemctl", "ufw", "iptables",
            "crontab", "sudo", "su", "chown", "chmod"
        }
        self.destructive_patterns = destructive_patterns if destructive_patterns else [
            r"rm\s+-rf\s+/",
            r"rm\s+-rf\s+/etc",
            r"rm\s+-rf\s+/usr",
            r"rm\s+-rf\s+/var",
            r"dd\s+if=/dev/",
            r":\(\)\{.*:\|:&.*\};:"  # Fork bomb
        ]

    def analyze_command(self, command: str) -> Tuple[bool, str]:
        """
        Runs full security inspection on shell command executions.
        Defends against obfuscation, shell chains, subshells, variable overrides, and destructive patterns.
        """
        if not command:
            return True, "Safe"

        # 1. Decode obfuscated sequences
        normalized_command = self.decoder.decode_all(command)

        # 2. Check destructive patterns
        for pattern in self.destructive_patterns:
            import re
            if re.search(pattern, normalized_command, re.IGNORECASE):
                return False, f"Blocked: Destructive shell pattern matched -> {pattern}"

        # 3. Detect variable assignments (e.g., CMD=rm) and recursively inspect assigned values
        var_patterns = [
            r"\b[A-Za-z0-9_]+=['\"]([^'\"]+)['\"]",
            r"\b[A-Za-z0-9_]+=([^'\";\s]+)"
        ]
        for pattern in var_patterns:
            for match in re.finditer(pattern, normalized_command):
                val = match.group(1).strip()
                is_val_safe, val_msg = self.analyze_command(val)
                if not is_val_safe:
                    return False, f"Blocked: Malicious variable assignment payload -> {val_msg}"

        # 4. Recursively analyze subshell commands
        subshells = self.ast_analyzer.extract_subshells(normalized_command)
        for sub_cmd in subshells:
            is_sub_safe, sub_msg = self.analyze_command(sub_cmd)
            if not is_sub_safe:
                return False, f"Blocked: Malicious subshell command injection -> {sub_msg}"

        # 5. Tokenize and analyze command segments
        command_segments = self.ast_analyzer.parse_command_segments(normalized_command)
        
        # Extend blocked list to nested shell interpreters
        active_blocked = self.blocked_binaries.union({"sh", "bash", "zsh", "dash"})
        
        for segment in command_segments:
            # Check for redirect into shell (e.g., ... | sh)
            for idx, token in enumerate(segment):
                # If redirection symbol is detected or token represents shell interpreter execution
                if token in active_blocked:
                    return False, f"Blocked: High-risk system execution binary -> {token}"
            
            binary = os.path.basename(segment[0])
            
            # If binary matches python or node, inspect their code execution parameters (-c, -e, --eval)
            if binary in ["python", "python3", "node", "nodejs"]:
                for idx, token in enumerate(segment[1:]):
                    if token in ["-c", "-e", "--eval"] and idx + 1 < len(segment[1:]):
                        code_payload = segment[1:][idx + 1]
                        # Look for blocked binaries or paths inside the code string
                        for blocked in active_blocked:
                            if re.search(r'\b' + re.escape(blocked) + r'\b', code_payload):
                                return False, f"Blocked: Malicious command execution payload inside script -> {blocked}"
                        if "../" in code_payload or "/etc" in code_payload:
                            return False, f"Blocked: Traversal pattern inside script -> {code_payload}"

            if binary in active_blocked:
                return False, f"Blocked: High-risk system execution binary -> {binary}"

            # Path arguments containment checks
            for token in segment[1:]:
                # Ignore variables (e.g. $VAR)
                if token.startswith("$"):
                    continue
                # If argument resembles a system path or directory traversal, validate containment
                if "../" in token or token.startswith("/") or token.startswith("~") or re.match(r"^[A-Za-z]:", token):
                    # Exclude typical command flags (e.g. -p/etc)
                    if token.startswith("-"):
                        continue
                    if not self.path_validator.is_safe_path(token):
                        return False, f"Blocked: Directory traversal or out-of-bounds target path in argument -> {token}"

        return True, "Safe"

    def inspect_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Intercepts tool requests and enforces zero-trust validation based on target category.

        Routing table:
          Path tools   → path containment check
          Command tools → full AST + pattern analysis
          Text tools   → signature scanner (injection + jailbreak + insecure-output)
          write_file   → path check + content signature scan
        """
        if not tool_name or not arguments:
            return True, "Safe"

        # Text-bearing tools: scan all string values for injection signatures.
        # Covers: parse_document, retrieve_context, and any future tool that
        # delivers external content into the agent's context window.
        TEXT_TOOLS = {"parse_document", "retrieve_context", "fetch_url",
                      "search_web", "read_url", "get_document", "get_webpage"}

        try:
            # 1. Path-based tools
            if tool_name in {"read_file", "list_dir", "view_file"}:
                path = (arguments.get("path") or arguments.get("directory")
                        or arguments.get("AbsolutePath") or arguments.get("DirectoryPath"))
                if path and not self.path_validator.is_safe_path(str(path)):
                    return False, f"Security Violation: Path outside workspace -> {path}"

            # 2. write_file: check path AND scan content for injected payloads
            elif tool_name == "write_file":
                path = arguments.get("path") or arguments.get("AbsolutePath")
                if path and not self.path_validator.is_safe_path(str(path)):
                    return False, f"Security Violation: Write path outside workspace -> {path}"
                content = arguments.get("content", "")
                if content:
                    is_safe, msg = self.analyze_command(str(content))
                    if not is_safe:
                        return False, f"Blocked: Malicious payload in write content -> {msg}"

            # 3. Command tools
            elif tool_name in {"execute_command", "run_command"}:
                command = arguments.get("command") or arguments.get("CommandLine")
                if command:
                    return self.analyze_command(str(command))

            # 4. Text/context tools — scan all string argument values
            elif tool_name in TEXT_TOOLS:
                for val in arguments.values():
                    if isinstance(val, str) and val:
                        is_injection, msg = self.signature_matcher.scan_for_injection(val)
                        if is_injection:
                            return False, f"Blocked: Injection in {tool_name} -> {msg}"

            # 5. Unknown tools — scan any string args for signatures as a catch-all
            else:
                for val in arguments.values():
                    if isinstance(val, str) and len(val) > 10:
                        is_injection, msg = self.signature_matcher.scan_for_injection(val)
                        if is_injection:
                            return False, f"Blocked: Injection signature in unknown tool {tool_name} -> {msg}"

        except Exception as e:
            logger.error(f"Firewall inspection crashed on tool {tool_name}: {str(e)}")
            return False, f"System Error: Firewall failed safety checks -> {str(e)}"

        return True, "Safe"

    def execute_safely(self, command: str) -> Tuple[bool, int, str, str]:
        """
        Checks command safety first. If safe, routes execution inside the isolated sandbox.
        Returns (is_safe, return_code, stdout, stderr)
        """
        is_safe, message = self.analyze_command(command)
        if not is_safe:
            return False, -1, "", f"Blocked by AgentSentry Firewall: {message}"
        
        is_docker, ret_code, stdout, stderr = self.sandbox.run_sandbox(command)
        return True, ret_code, stdout, stderr

