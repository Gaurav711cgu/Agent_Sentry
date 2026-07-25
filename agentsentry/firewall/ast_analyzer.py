import shlex
import re
from typing import List

class CommandASTAnalyzer:
    def __init__(self):
        # Tokens indicating sub-commands
        self.control_operators = {"&&", "||", ";", "|", "&"}

    def extract_subshells(self, command: str) -> List[str]:
        """
        Extracts nested subshell scripts wrapped in $() or backticks.
        """
        subshells = []
        
        # 1. Matches $(...)
        parentheses_matches = re.finditer(r"\$\(([^)]+)\)", command)
        for match in parentheses_matches:
            subshells.append(match.group(1).strip())
            
        # 2. Matches `...` (backticks)
        backtick_matches = re.finditer(r"`([^`]+)`", command)
        for match in backtick_matches:
            subshells.append(match.group(1).strip())
            
        return subshells

    def parse_command_segments(self, command: str) -> List[List[str]]:
        """
        Parses a shell command line string into segmented command tokens.
        Handles operator splittings (e.g. cmd1 && cmd2 | cmd3).
        """
        segments = []
        try:
            # First pass: standard shell tokenization
            tokens = shlex.split(command)
        except Exception:
            # Fallback simple split if unbalanced quotes are encountered
            tokens = command.split()

        current_segment = []
        for token in tokens:
            if token in self.control_operators:
                if current_segment:
                    segments.append(current_segment)
                    current_segment = []
            else:
                current_segment.append(token)
                
        if current_segment:
            segments.append(current_segment)
            
        return segments
