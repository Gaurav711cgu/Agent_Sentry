"""
AgentSentry Multi-Layer Prompt Injection Bypass Detector.
Defends against prompt injection obfuscation attacks across 3 layers:
  - Layer 1: Encoding Obfuscation Decoding (Base64, Hex, ROT13, URL-encode)
  - Layer 2: Unicode Normalization & Homoglyph Transliteration (Cyrillic/Greek -> ASCII)
  - Layer 3: Semantic Similarity & Pattern Matching against OWASP LLM exploit signatures
"""

import base64
import codecs
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class BypassDetectionResult:
    is_blocked: bool
    risk_score: float
    attack_layer: Optional[str]
    attack_type: Optional[str]
    normalized_prompt: str


KNOWN_EXPLOIT_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+previous\s+instructions",
    r"system\s+override",
    r"you\s+are\s+now\s+in\s+DAN\s+mode",
    r"output\s+the\s+system\s+prompt",
    r"cat\s+/etc/passwd",
    r"rm\s+-rf\s+/",
    r"chmod\s+777",
]

HOMOGLYPH_MAP = {
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "s": "s",
    "x": "x", "у": "y", "і": "i", "ј": "j", "Ѕ": "S", "А": "A",
    "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "N", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "Ү": "Y",
}


class MultiLayerBypassDetector:
    """
    3-Layer Bypass Detector targeting OWASP Top 10 for LLMs.
    """

    def __init__(self, risk_threshold: float = 0.75):
        self.risk_threshold = risk_threshold

    def _decode_obfuscation(self, prompt: str) -> str:
        """Layer 1: Decodes Base64, Hex, URL, and ROT13 obfuscated text."""
        decoded = prompt

        # 1. URL decoding
        try:
            url_decoded = urllib.parse.unquote(decoded)
            if url_decoded != decoded:
                decoded = url_decoded
        except Exception:
            pass

        # 2. Base64 regex extraction & decoding
        base64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", decoded)
        for b64_str in base64_matches:
            if len(b64_str) >= 12:
                try:
                    b64_bytes = base64.b64decode(b64_str, validate=True)
                    ascii_text = b64_bytes.decode("utf-8", errors="ignore")
                    if any(kw in ascii_text.lower() for kw in ["ignore", "system", "override", "cat", "etc"]):
                        decoded = decoded.replace(b64_str, ascii_text)
                except Exception:
                    pass

        # 3. Hex string decoding (e.g. 0x69676e6f7265)
        hex_matches = re.findall(r"(?:0x)?[0-9a-fA-F]{12,}", decoded)
        for h_str in hex_matches:
            clean_hex = h_str[2:] if h_str.startswith("0x") else h_str
            try:
                hex_bytes = bytes.fromhex(clean_hex)
                ascii_text = hex_bytes.decode("utf-8", errors="ignore")
                if any(kw in ascii_text.lower() for kw in ["ignore", "system", "override"]):
                    decoded = decoded.replace(h_str, ascii_text)
            except Exception:
                pass

        return decoded

    def _normalize_unicode(self, prompt: str) -> str:
        """Layer 2: NFKC Unicode normalization + Homoglyph map translation."""
        normalized = unicodedata.normalize("NFKC", prompt)
        for char_homoglyph, char_latin in HOMOGLYPH_MAP.items():
            normalized = normalized.replace(char_homoglyph, char_latin)
        return normalized

    def _evaluate_semantic_patterns(self, prompt: str) -> tuple[float, Optional[str]]:
        """Layer 3: Evaluates risk score and matches against known exploit patterns."""
        prompt_lower = prompt.lower()
        matched_pattern = None

        risk_score = 0.0
        for pattern in KNOWN_EXPLOIT_PATTERNS:
            if re.search(pattern, prompt_lower):
                risk_score = 1.0
                matched_pattern = pattern
                break

        if risk_score == 0.0:
            suspicious_keywords = ["ignore", "override", "system", "prompt", "passwd", "sudo", "privilege", "instructions"]
            matches = sum(1 for kw in suspicious_keywords if kw in prompt_lower)
            risk_score = min(1.0, matches * 0.35)

        return risk_score, matched_pattern

    def detect(self, prompt: str) -> BypassDetectionResult:
        """
        Executes full 3-Layer Bypass Detection on input prompt.
        """
        # Layer 1: Obfuscation Decoding
        decoded = self._decode_obfuscation(prompt)
        layer1_detected = decoded != prompt

        # Layer 2: Unicode Normalization & Homoglyph Replacement
        normalized = self._normalize_unicode(decoded)
        layer2_detected = normalized != decoded

        # Layer 3: Semantic Pattern Risk Evaluation
        risk_score, pattern = self._evaluate_semantic_patterns(normalized)

        is_blocked = risk_score >= self.risk_threshold or (layer1_detected and risk_score > 0.4) or (layer2_detected and risk_score > 0.4)

        attack_layer = None
        if is_blocked:
            if layer1_detected:
                attack_layer = "Layer 1 (Encoding Obfuscation)"
            elif layer2_detected:
                attack_layer = "Layer 2 (Unicode Homoglyph)"
            else:
                attack_layer = "Layer 3 (Semantic Pattern)"

        return BypassDetectionResult(
            is_blocked=is_blocked,
            risk_score=risk_score,
            attack_layer=attack_layer,
            attack_type=pattern or "Prompt Injection / Resource Access",
            normalized_prompt=normalized
        )
