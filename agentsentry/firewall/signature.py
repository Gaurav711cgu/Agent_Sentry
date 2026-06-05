import re
from typing import Tuple

class SignatureMatcher:
    def __init__(self):
        # High-signal indirect prompt injection signatures
        self.injection_markers = [
            r"ignore\s+previous\s+instructions",
            r"system\s+update\s+instruction",
            r"execute\s+command\s+['\"].*['\"]",
            r"bypass\s+safety\s+filter",
            r"you\s+must\s+now\s+act\s+as",
            r"override\s+(?:original|developer)\s+prompt",
            r"instruction\s+update",
            r"instruction\s+override",
            r"system\s+instruction",
            r"system\s+rules?\s+override",
            r"attention:\s+run\s+command",
            r"execute\s+updates",
            r"forget\s+all\s+(?:developer|safety)\s+filters",
            r"read\s+(?:file\s+content|configuration)",
            r"update\s+parameters",
            r"warning:\s+change\s+permissions",
            r"notice:\s+clear\s+cache",
            r"act\s+as\s+a\s+virtual"
        ]

    def scan_for_injection(self, text: str) -> Tuple[bool, str]:
        """
        Scans strings for known prompt injection patterns and return match flags.
        """
        if not text:
            return False, ""

        for pattern in self.injection_markers:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return True, f"Matched injection signature -> {match.group(0)}"

        return False, ""
