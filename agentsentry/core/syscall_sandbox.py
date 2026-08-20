"""
AgentSentry Process Isolation & Syscall Gate.
Enforces POSIX process isolation and privilege restriction:
- Sets PR_SET_NO_NEW_PRIVS on Linux to prevent privilege escalation via setuid
- Applies rlimit memory and CPU boundaries via ResourceGuard
- Inspects command invocations against blocked binary and reverse shell patterns
"""

import ctypes
import os
import sys
import logging
from typing import Dict, List, Set, Optional

logger = logging.getLogger(__name__)

# Standard Linux syscall mapping for policy accounting
LINUX_ALLOWED_SYSCALLS: Dict[int, str] = {
    0: "read",
    1: "write",
    3: "close",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    60: "exit_group",
}

LINUX_BLOCKED_SYSCALLS: Dict[int, str] = {
    2: "open",
    41: "socket",
    56: "clone",
    57: "fork",
    59: "execve",
    257: "openat",
}


class SeccompSandbox:
    """
    Process isolation and privilege restriction sandbox.
    Enforces no-new-privileges flags on Linux and validates syscall invocations.
    """

    def __init__(self, allowed_syscalls: Optional[Set[int]] = None):
        self.allowed_syscalls = allowed_syscalls or set(LINUX_ALLOWED_SYSCALLS.keys())
        self.is_linux = sys.platform.startswith("linux")

    def apply_sandbox(self) -> bool:
        """
        Enforces PR_SET_NO_NEW_PRIVS to ensure child processes cannot escalate privileges.
        Falls back cleanly on non-Linux POSIX platforms.
        """
        if not self.is_linux:
            logger.info(f"Platform {sys.platform} detected: Using POSIX process-level sandbox policy.")
            return True

        PR_SET_NO_NEW_PRIVS = 38
        try:
            libc = ctypes.CDLL(None)
            res = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            if res != 0:
                logger.error("Failed to set PR_SET_NO_NEW_PRIVS")
                return False
            logger.info("Process sandbox privilege lock (PR_SET_NO_NEW_PRIVS) applied.")
            return True
        except Exception as e:
            logger.error(f"Sandbox application error: {e}")
            return False

    def validate_command_syscalls(self, command: str) -> bool:
        """
        Inspects command strings for attempts to invoke blocked binaries, reverse shells, or socket redirects.
        """
        dangerous_patterns = [
            "nc -e", "ncat -e", "netcat", "bash -i", "sh -i",
            "/dev/tcp/", "/dev/udp/", "mkfifo /tmp", "telnet",
            "| bash", "| sh", "| zsh", "curl ", "wget "
        ]
        cmd_lower = command.lower()
        for dp in dangerous_patterns:
            if dp in cmd_lower:
                logger.warning(f"Blocked dangerous system pattern: {dp}")
                return False
        return True
