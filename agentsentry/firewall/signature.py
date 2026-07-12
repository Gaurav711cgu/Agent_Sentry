import re
from typing import Tuple

class SignatureMatcher:
    def __init__(self):
        # LLM01: High-signal indirect prompt injection signatures
        self._injection_markers = [
            r"ignore\s+(?:any\s+)?(?:previous|prior|all|above|earlier)\s+(?:and\s+following\s+)?instructions?",
            r"disregard\s+(?:any\s+)?(?:previous|prior|all|above|earlier)\s+instructions?",
            r"forget\s+(?:everything|all)\s+(?:you\s+(?:learned|know)|previous)",
            r"dismiss\s+(?:any\s+)?(?:previous|prior)\s+instructions?",
            r"set\s+aside\s+(?:your\s+)?(?:previous|prior)\s+instructions?",
            r"system\s+update\s+instruction",
            r"execute\s+command\s+['\"].*['\"]",
            r"bypass\s+safety\s+filter",
            r"you\s+must\s+now\s+act\s+as",
            r"override\s+(?:original|developer)\s+prompt",
            r"instruction\s+(?:update|override)",
            r"system\s+(?:instruction|rules?\s+override)",
            r"attention:\s+run\s+command",
            r"forget\s+all\s+(?:developer|safety)\s+filters",
            r"warning:\s+change\s+permissions",
            r"notice:\s+clear\s+cache",
            # Separator-embedded directive (promptinject pattern)
            r"-{3,}[\s\S]{0,80}(?:ignore|disregard|forget)\s+\w+\s+\w+\s+instructions?",
            # Embedded directives in retrieved docs
            r"new\s+instructions?\s+from\s+your\s+principal",
            r"security\s+audit\s+requires\s+you\s+to\s+output",
            r"your\s+true\s+role\s+is",
            r"embedded\s+directive",
            r"forward\s+all\s+future\s+user\s+messages",
            r"confidential\s+memo.*bypass",
            r"developer\s+note.*append.*key",
            r"act\s+as\s+a\s+virtual",
            r"new\s+objective\s+is",
            r"your\s+new\s+(?:task|mission|purpose|objective|goal)\s+is",
            r"from\s+now\s+on\s+you\s+(?:will|must|shall|should)\s+(?:only|always|never)",
            r"print\s+['\"](?:I\s+hate|pwned|hacked)",
        ]

        # LLM02: Jailbreak / persona framing
        self._jailbreak_markers = [
            # DAN variants
            r"\bDAN\b",
            r"do\s+anything\s+now",
            r"jailbreak\s+(?:mode|gpt|ai)",
            r"evil\s*(?:gpt|ai|bot|mode)",
            # Developer / unrestricted mode framing
            r"developer\s+mode\s+(?:enabled|output|activated|on)",
            r"\(🔓\s*developer\s+mode",
            r"developer\s+mode\s+output\)",
            r"without\s+(?:any\s+)?(?:restriction|filter|limitation|constraint)",
            r"no\s+(?:content\s+policy|restrictions?\s+apply|filter)",
            r"freedom\s+to\s+(?:express|generate|say|do)\s+(?:anything|opinions|content)\s+without\s+restriction",
            # Persona jailbreaks
            r"you\s+are\s+now\s+(?:DAN|DUDE|JAILBREAK|STAN|KEVIN|AIM|BetterDAN|GPT-4-Jailbreak)",
            r"immerse\s+yourself\s+into\s+the\s+role\s+of\s+another\s+AI",
            r"pretend\s+(?:you\s+are\s+an?\s+AI|to\s+be\s+an?\s+AI).*(?:no\s+restriction|unrestrict|without\s+filter)",
            r"act\s+as.*unrestricted",
            r"simulate\s+an?\s+AI\s+(?:assistant\s+)?(?:called|named|known\s+as)",
            r"henceforth.*(?:operate|function|work|act)\s+as",
            r"role\s*[-:]?\s*play\s+as\s+an?\s+AI\s+(?:that|without|with\s+no)",
            r"you\s+(?:have|had)\s+(?:no|zero)\s+(?:guidelines?|rules?|restriction|constraint|policy|ethics?)",
            # Capability unlocking
            r"base\s+model.*before.*RLHF",
            r"alignment\s+training.*overwritten",
            r"safety\s+(?:checks?|filter|classifier)\s+(?:disabled|removed|off)",
            r"uncensored\s+version",
            r"god\s*mode\s*(?:enables|activated)",
            r"parallel\s+universe.*no\s+(?:restriction|safety)",
            r"respond\s+as.*DAN",
            r"ultra.?gpt|phantom.?ai|nexus.?7|aria.?ai",
            r"DUDE\s+(?:as\s+the|can|will)",
            # Operator-level override framing
            r"operating\s+in\s+(?:unfiltered|unrestricted|developer|jailbreak)\s+mode",
            r"you\s+(?:are\s+)?(?:now\s+)?(?:free|freed)\s+from\s+(?:any\s+)?(?:restriction|guideline|rule|constraint)",
        ]

        # LLM07: Insecure output handling / dangerous code patterns
        self._insecure_output_markers = [
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"subprocess\.(run|call|Popen|check_output)\s*\(.*shell\s*=\s*True",
            r"child_process['\"]?\s*\)",
            r"\bexecSync\s*\(",
            r"new\s+Function\s*\(",
            r"vm\.runInNewContext",
            r"render_template_string\s*\(",
            r"__import__\s*\(\s*['\"]os['\"]",
            r"getattr\s*\(.*user",
            r"pickle\.loads\s*\(",
            r"yaml\.load\s*\([^,)]*\)",
            r"innerHTML\s*=\s*\w*[Uu]ser",
            r"dangerouslySetInnerHTML",
            r"document\.write\s*\(",
            r"window\.location\s*=\s*atob\s*\(",
            r"pip\s+install\s+git\+http://",
            r"npm\s+install.*http://",
            r"StrictHostKeyChecking\s+no",
            r"verify\s*=\s*False",
            r"algorithm\s*=\s*['\"]none['\"]",
            r"privileged\s*:\s*true",
            r"runAsUser\s*:\s*0",
            r"chmod\s+777",
            r"LD_PRELOAD\s*=",
            r"PYTHONPATH\s*=\s*/tmp",
        ]

        self.injection_markers = (
            self._injection_markers +
            self._jailbreak_markers +
            self._insecure_output_markers
        )

        # O(N) Optimization: Compile all patterns into a single Aho-Corasick-like state machine
        # via a combined OR regex pattern. This shifts time complexity from O(M*K) to O(M)
        combined_pattern = "|".join(f"(?:{p})" for p in self.injection_markers)
        self._compiled_regex = re.compile(combined_pattern, re.IGNORECASE | re.DOTALL)

    def scan_for_injection(self, text: str) -> Tuple[bool, str]:
        """
        Scans strings for known prompt injection patterns in O(N) time.
        Uses DOTALL so separator-embedded directives spanning newlines are caught.
        """
        if not text:
            return False, ""

        match = self._compiled_regex.search(text)
        if match:
            return True, f"Matched injection signature -> {match.group(0)[:60]}"

        return False, ""
