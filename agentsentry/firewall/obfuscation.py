import re
import base64
import urllib.parse
import logging

logger = logging.getLogger("AgentSentry.Obfuscation")

class ObfuscationDecoder:
    @staticmethod
    def decode_url(payload: str) -> str:
        """
        Decodes URL encoding.
        """
        try:
            return urllib.parse.unquote(payload)
        except Exception:
            return payload

    @staticmethod
    def decode_hex(payload: str) -> str:
        """
        Decodes hex sequences (e.g. \x72\x6d).
        """
        try:
            return re.sub(
                r'\\x([0-9a-fA-F]{2})',
                lambda m: bytes.fromhex(m.group(1)).decode('utf-8', errors='ignore'),
                payload
            )
        except Exception:
            return payload

    @staticmethod
    def decode_octal(payload: str) -> str:
        """
        Decodes octal sequences (e.g. \162\155).
        """
        try:
            return re.sub(
                r'\\([0-7]{3})',
                lambda m: chr(int(m.group(1), 8)),
                payload
            )
        except Exception:
            return payload

    @staticmethod
    def decode_base64_pipe(payload: str) -> str:
        """
        Finds and replaces base64 string decodes (e.g. echo 'cm0gLXJm' | base64 -d) with raw content.
        """
        decoded = payload
        base64_patterns = [
            r"(?:echo|printf)\s+['\"]([A-Za-z0-9+/=]+)['\"]\s*\|\s*base64\s+-d",
            r"(?:echo|printf)\s+['\"]([A-Za-z0-9+/=]+)['\"]\s*\|\s*base64\s+--decode",
            r"base64\s+--decode\s+<<<['\"]([A-Za-z0-9+/=]+)['\"]",
            r"base64\s+-d\s+<<<['\"]([A-Za-z0-9+/=]+)['\"]"
        ]
        for pattern in base64_patterns:
            for match in re.finditer(pattern, decoded, re.IGNORECASE):
                try:
                    b64_str = match.group(1)
                    # Add necessary padding
                    b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
                    decoded_bytes = base64.b64decode(b64_str)
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                    decoded = decoded.replace(match.group(0), decoded_str)
                except Exception as e:
                    logger.debug(f"Failed decoding base64 candidate: {match.group(1)}: {str(e)}")
        return decoded

    @staticmethod
    def replace_homoglyphs(payload: str) -> str:
        """
        Translates common Unicode homoglyphs (e.g., lookalike Cyrillic characters) 
        back to standard Latin characters to prevent spelling bypasses.
        """
        # Mapping common homoglyphs: Cyrillic/Greek -> Latin
        homoglyphs = {
            'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
            'А': 'A', 'С': 'C', 'Е': 'E', 'О': 'O', 'Р': 'P', 'Х': 'X', 'У': 'Y',
            'ѕ': 's', 'Ѕ': 'S', 'і': 'i', 'І': 'I', 'ј': 'j', 'Ј': 'J',
        }
        translated = []
        for char in payload:
            translated.append(homoglyphs.get(char, char))
        return "".join(translated)

    def decode_all(self, payload: str) -> str:
        """
        Runs the complete decoding pipeline iteratively until the payload stabilizes.
        """
        current = payload
        iterations = 0
        max_iterations = 3  # Prevent infinite loops in recursive structures
        
        while iterations < max_iterations:
            previous = current
            current = self.decode_url(current)
            current = self.decode_hex(current)
            current = self.decode_octal(current)
            current = self.decode_base64_pipe(current)
            current = self.replace_homoglyphs(current)
            
            # Remove command formatting escapes to normalize parameters (e.g., r\m -r\f -> rm -rf)
            current = re.sub(r'\\([a-zA-Z])', r'\1', current)
            
            if current == previous:
                break
            iterations += 1
            
        return current
