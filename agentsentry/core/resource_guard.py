"""
AgentSentry Process Resource Exhaustion Guard.
Enforces POSIX resource limits (RLIMIT_CPU, RLIMIT_AS) on executed agent tools/sub-processes,
preventing infinite loops, CPU starvation, memory exhaustion, and fork bombs.
"""

import os
import resource
import signal
import sys
import time
import subprocess
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    execution_time_sec: float
    cpu_limit_exceeded: bool
    memory_limit_exceeded: bool


class ResourceGuard:
    """
    POSIX Resource Limiter & Process Isolator.
    Prevents CPU starvation and memory exhaustion attacks in sandboxed code execution.
    """

    def __init__(self, max_cpu_time_sec: int = 5, max_memory_mb: int = 256):
        self.max_cpu_time_sec = max_cpu_time_sec
        self.max_memory_mb = max_memory_mb

    def _set_limits(self):
        """Child pre-exec callback setting POSIX rlimits."""
        if sys.platform != "win32":
            try:
                # 1. CPU Time Limit (seconds)
                resource.setrlimit(resource.RLIMIT_CPU, (self.max_cpu_time_sec, self.max_cpu_time_sec + 2))

                # 2. Virtual Memory Limit (bytes)
                mem_bytes = self.max_memory_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))

                # 3. Maximum child processes (prevent fork bomb)
                if hasattr(resource, "RLIMIT_NPROC"):
                    resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
            except Exception:
                pass

    def run_sandboxed(self, command: str, timeout_sec: Optional[float] = None) -> ExecutionResult:
        """
        Executes a shell command inside a sandboxed sub-process with rlimits and timeout traps.
        """
        timeout = timeout_sec or (self.max_cpu_time_sec + 2.0)
        start_time = time.time()

        cpu_exceeded = False
        mem_exceeded = False

        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=self._set_limits if sys.platform != "win32" else None,
                text=True,
            )

            stdout, stderr = proc.communicate(timeout=timeout)
            exec_time = time.time() - start_time

            return ExecutionResult(
                stdout=stdout or "",
                stderr=stderr or "",
                exit_code=proc.returncode,
                execution_time_sec=round(exec_time, 4),
                cpu_limit_exceeded=proc.returncode == -signal.SIGXCPU if hasattr(signal, "SIGXCPU") else False,
                memory_limit_exceeded="MemoryError" in (stderr or "") or proc.returncode in [137, -9],
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return ExecutionResult(
                stdout=stdout or "",
                stderr=(stderr or "") + "\n[AgentSentry] Process terminated: CPU/Timeout limit exceeded.",
                exit_code=-1,
                execution_time_sec=round(time.time() - start_time, 4),
                cpu_limit_exceeded=True,
                memory_limit_exceeded=False,
            )
