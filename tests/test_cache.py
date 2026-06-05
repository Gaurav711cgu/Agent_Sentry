import unittest
import os
import sys

# Ensure package is imported properly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentsentry.cache.prefix_aligner import PromptPrefixAligner
from agentsentry.cache.differential import SuffixDeltaCompressor

class TestAgentCache(unittest.TestCase):
    def setUp(self):
        self.aligner = PromptPrefixAligner()
        self.cacher = SuffixDeltaCompressor()

    def test_prefix_reordering(self):
        raw_messages = [
            {"role": "user", "content": "Help me write code."},
            {"role": "system", "content": "You are a secure assistant."},
            {"role": "assistant", "content": "Sure, let's start."}
        ]
        
        # Tools schema injection
        tools = {"name": "execute_command"}

        aligned = self.aligner.align_messages(raw_messages, tools)

        # Assert system prompt is moved to the head (Step 1)
        self.assertEqual(aligned[0]["role"], "system")
        self.assertIn("secure assistant", aligned[0]["content"])
        self.assertIn("System Tool-Use Schema", aligned[0]["content"])

        # Remaining messages preserved in order
        self.assertEqual(aligned[1]["role"], "user")
        self.assertEqual(aligned[2]["role"], "assistant")

    def test_differential_caching(self):
        import asyncio
        session_id = "test_session"
        prompt_turn_1 = "System: Hello developer. User: Check code."
        prompt_turn_2 = "System: Hello developer. User: Check code. Assistant: Sure. User: Run test."

        # Turn 1: Cache miss (initialized)
        suffix_1, savings_1 = asyncio.run(self.cacher.compute_suffix_delta(session_id, prompt_turn_1))
        self.assertEqual(suffix_1, prompt_turn_1)
        self.assertEqual(savings_1, 0.0)

        # Turn 2: Cache hit (prefix matches)
        suffix_2, savings_2 = asyncio.run(self.cacher.compute_suffix_delta(session_id, prompt_turn_2))
        self.assertEqual(suffix_2, " Assistant: Sure. User: Run test.")
        self.assertTrue(savings_2 > 0.0)
        self.assertEqual(self.cacher.cache_hits, 1)

if __name__ == "__main__":
    unittest.main()
