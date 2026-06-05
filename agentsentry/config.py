import os
import json
import logging
from typing import Dict, Any, List

# Set up logging format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
    ]
)

logger = logging.getLogger("AgentSentry.Config")

class AgentSentryConfig:
    def __init__(self, config_path: str = None):
        self.config_path = config_path
        self.workspace_root = os.getcwd()
        self.blocked_binaries: List[str] = [
            "curl", "wget", "nc", "netcat", "nmap", "ssh", "scp",
            "sftp", "ftp", "telnet", "systemctl", "ufw", "iptables",
            "crontab", "sudo", "su", "chown", "chmod"
        ]
        self.destructive_patterns: List[str] = [
            r"rm\s+-rf\s+/",
            r"rm\s+-rf\s+/etc",
            r"rm\s+-rf\s+/usr",
            r"rm\s+-rf\s+/var",
            r"dd\s+if=/dev/",
            r":\(\)\{.*:\|:&.*\};:"  # Fork bomb
        ]
        self.cache_savings_threshold = 0.10  # Minimum savings before diff format is enforced
        self.mcp_proxy_url = "http://localhost:8000"
        
        if config_path and os.path.exists(config_path):
            self.load_from_file(config_path)

    def load_from_file(self, filepath: str):
        """
        Loads configuration variables from a JSON layout.
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                
            self.workspace_root = data.get("workspace_root", self.workspace_root)
            self.blocked_binaries = data.get("blocked_binaries", self.blocked_binaries)
            self.destructive_patterns = data.get("destructive_patterns", self.destructive_patterns)
            self.cache_savings_threshold = data.get("cache_savings_threshold", self.cache_savings_threshold)
            self.mcp_proxy_url = data.get("mcp_proxy_url", self.mcp_proxy_url)
            
            logger.info(f"Loaded custom configuration successfully from: {filepath}")
        except Exception as e:
            logger.error(f"Failed to load custom config from {filepath}: {str(e)}")

    def save_defaults(self, filepath: str):
        """
        Saves default configuration profile to target filepath.
        """
        data = {
            "workspace_root": self.workspace_root,
            "blocked_binaries": self.blocked_binaries,
            "destructive_patterns": self.destructive_patterns,
            "cache_savings_threshold": self.cache_savings_threshold,
            "mcp_proxy_url": self.mcp_proxy_url
        }
        try:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Saved default configurations to: {filepath}")
        except Exception as e:
            logger.error(f"Failed to save defaults to {filepath}: {str(e)}")
