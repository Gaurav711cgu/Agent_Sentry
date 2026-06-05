import os
import re
import logging

logger = logging.getLogger("AgentSentry.PathContainment")

class PathContainmentValidator:
    def __init__(self, workspace_root: str):
        self.workspace_root = os.path.realpath(os.path.abspath(workspace_root))

    def is_safe_path(self, target_path: str) -> bool:
        """
        Validates if target path is resolved and strictly contained within the workspace root.
        Defends against directory traversal exploits (e.g. symlink escape, ../../../etc/passwd).
        """
        if not target_path:
            return False

        try:
            # 1. Normalize backslashes (Windows) to forward slashes for unified checks
            normalized = target_path.replace("\\", "/")
            
            # 2. Block absolute Windows paths (e.g., C:/...) or absolute Unix paths
            if re.match(r"^[A-Za-z]:", normalized) or normalized.startswith("//"):
                logger.warning(f"Blocked absolute path attempt: {target_path}")
                return False

            # Expand ~ to home directories
            expanded = os.path.expanduser(target_path)
            
            # If path is relative, anchor it to workspace root
            if not os.path.isabs(expanded):
                expanded = os.path.join(self.workspace_root, expanded)

            # Resolve all symlinks and relative references dynamically
            resolved_target = os.path.realpath(expanded)

            # Containment check: target path must start with the workspace root directory path
            check_root = self.workspace_root if self.workspace_root.endswith(os.path.sep) else self.workspace_root + os.path.sep
            
            return resolved_target.startswith(check_root) or resolved_target == self.workspace_root
        except Exception as e:
            logger.error(f"Error during path validation of '{target_path}': {str(e)}")
            return False
