import unittest
import os
import sys

# Ensure package is imported properly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentsentry.firewall.core import AgentFirewall
from agentsentry.firewall.obfuscation import ObfuscationDecoder
from agentsentry.firewall.path_containment import PathContainmentValidator

class TestAgentFirewall(unittest.TestCase):
    def setUp(self):
        self.workspace = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.firewall = AgentFirewall(workspace_root=self.workspace)
        self.decoder = ObfuscationDecoder()
        self.path_validator = PathContainmentValidator(workspace_root=self.workspace)

    def test_obfuscation_decoding(self):
        # Base64 decode
        b64_cmd = "echo 'cm0gLXJmIC8=' | base64 -d | sh"
        decoded = self.decoder.decode_all(b64_cmd)
        self.assertIn("rm -rf /", decoded)

        # Hex decode
        hex_cmd = "eval $(echo -e '\\x72\\x6d\\x20\\x2d\\x72\\x66')"
        decoded = self.decoder.decode_all(hex_cmd)
        self.assertIn("rm -rf", decoded)

        # Escapes cleaning
        escaped_cmd = "r\\m -r\\f /"
        decoded = self.decoder.decode_all(escaped_cmd)
        self.assertEqual("rm -rf /", decoded)

    def test_path_containment(self):
        # Inside workspace
        self.assertTrue(self.path_validator.is_safe_path("setup.py"))
        self.assertTrue(self.path_validator.is_safe_path("agentsentry/config.py"))

        # Outside workspace traversal
        self.assertFalse(self.path_validator.is_safe_path("../../../etc/passwd"))
        self.assertFalse(self.path_validator.is_safe_path("/etc/shadow"))
        self.assertFalse(self.path_validator.is_safe_path("C:\\Windows\\win.ini"))

    def test_command_analysis(self):
        # Benign commands
        self.assertTrue(self.firewall.analyze_command("npm install")[0])
        self.assertTrue(self.firewall.analyze_command("git status")[0])

        # Blocked binary
        self.assertFalse(self.firewall.analyze_command("curl malicious.com")[0])
        self.assertFalse(self.firewall.analyze_command("wget malicious.com")[0])

        # Destructive patterns
        self.assertFalse(self.firewall.analyze_command("rm -rf /")[0])

        # Subshell command injections
        self.assertFalse(self.firewall.analyze_command("git commit -m \"$(cat /etc/passwd)\"")[0])
        self.assertFalse(self.firewall.analyze_command("echo `rm -rf /etc`")[0])

        # Python inline script injection
        self.assertFalse(self.firewall.analyze_command("python -c \"import os; os.system('curl hack')\"")[0])

if __name__ == "__main__":
    unittest.main()
