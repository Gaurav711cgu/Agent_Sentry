import subprocess
import os
import logging
from typing import Tuple

logger = logging.getLogger("AgentSentry.Sandbox")

class SandboxedExecutor:
    def __init__(self, use_docker: bool = False, docker_image: str = "python:3.10-alpine", timeout: int = 15):
        self.use_docker = use_docker
        self.docker_image = docker_image
        self.timeout = timeout

    def check_docker_available(self) -> bool:
        """
        Validates if Docker is installed and the daemon is currently active.
        """
        try:
            res = subprocess.run(
                ["docker", "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3
            )
            return res.returncode == 0
        except Exception:
            return False

    def execute_in_docker(self, command: str) -> Tuple[int, str, str]:
        """
        Executes shell command inside a resource-constrained, transient Docker container.
        """
        try:
            # Mount a read-only scratch folder if needed, here we run as a pure sandbox
            # We restrict CPU and Memory constraints to prevent resource exhaustion
            docker_cmd = [
                "docker", "run", "--rm",
                "--network", "none",        # Disable network access to prevent exfiltration
                "--memory", "128m",         # Cap memory
                "--cpus", "0.5",            # Cap CPU resources
                self.docker_image,
                "sh", "-c", command
            ]
            
            logger.info(f"Launching Docker Sandbox: {self.docker_image}")
            res = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            return res.returncode, res.stdout, res.stderr
        except subprocess.TimeoutExpired:
            logger.error("Docker Sandbox execution timed out.")
            return -1, "", "Execution Timed Out (Max Limit reached)"
        except Exception as e:
            logger.error(f"Failed executing in Docker: {str(e)}")
            return -1, "", f"Docker Error: {str(e)}"

    def execute_in_local_jail(self, command: str) -> Tuple[int, str, str]:
        """
        Local fallback sandbox. Spawns command inside a subprocess with cleared env variables,
        blocking environment configuration leakages, and enforces timeouts.
        """
        try:
            # Clear env variables to prevent SSH keys / AWS keys leakage
            clean_env = {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "en_US.UTF-8"
            }
            
            logger.info("Launching Local Subprocess Jail...")
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=clean_env,
                preexec_fn=os.setsid if os.name != 'nt' else None # Run in separate process group
            )
            
            stdout, stderr = process.communicate(timeout=self.timeout)
            return process.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            logger.error("Local Sandbox execution timed out.")
            # Kill process group
            try:
                import signal
                if os.name != 'nt':
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                else:
                    process.kill()
            except Exception:
                pass
            return -1, "", "Execution Timed Out (Max Limit reached)"
        except Exception as e:
            logger.error(f"Failed executing in Local Jail: {str(e)}")
            return -1, "", f"Sandbox Error: {str(e)}"

    def run_sandbox(self, command: str) -> Tuple[bool, int, str, str]:
        """
        Runs command in Docker if requested and available, else falls back to Local Subprocess Jail.
        Returns (executed_in_docker, return_code, stdout, stderr)
        """
        if self.use_docker and self.check_docker_available():
            ret_code, stdout, stderr = self.execute_in_docker(command)
            return True, ret_code, stdout, stderr
        
        ret_code, stdout, stderr = self.execute_in_local_jail(command)
        return False, ret_code, stdout, stderr
