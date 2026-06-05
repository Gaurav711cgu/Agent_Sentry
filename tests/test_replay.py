import unittest
import os
import sys

# Ensure package is imported properly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentsentry.testing.recorder import TrajectoryRecorder
from agentsentry.testing.replayer import TrajectoryReplayer

class TestAgentReplay(unittest.TestCase):
    def setUp(self):
        self.trace_file = "trace_cache/test_units.json"
        if os.path.exists(self.trace_file):
            os.remove(self.trace_file)
            
        self.recorder = TrajectoryRecorder(self.trace_file)

    def tearDown(self):
        if os.path.exists(self.trace_file):
            os.remove(self.trace_file)

    def test_trajectory_recording_and_drift(self):
        import asyncio
        # 1. Record mock steps
        self.recorder.record_step("tool_call", "list_dir", {"arguments": {"path": "src"}})
        self.recorder.record_step("tool_response", "list_dir", {"matching_call_step": 1, "files": ["app"]})
        asyncio.run(self.recorder.save_trace_async())

        self.assertTrue(os.path.exists(self.trace_file))

        # 2. Replay & match trajectory
        replayer_matching = TrajectoryReplayer(self.trace_file)
        asyncio.run(replayer_matching.load_reference_async())
        replayer_matching.record_replay_step("tool_call", "list_dir", {"arguments": {"path": "src"}})
        replayer_matching.record_replay_step("tool_response", "list_dir", {"matching_call_step": 1, "files": ["app"]})

        match_analysis = replayer_matching.analyze_trajectory_drift()
        self.assertFalse(match_analysis["drift_detected"])
        self.assertEqual(match_analysis["similarity_ratio"], 1.0)

        # 3. Replay with drift arguments mismatch
        replayer_drifting = TrajectoryReplayer(self.trace_file)
        asyncio.run(replayer_drifting.load_reference_async())
        replayer_drifting.record_replay_step("tool_call", "list_dir", {"arguments": {"path": "config"}}) # mismatched arg
        
        drift_analysis = replayer_drifting.analyze_trajectory_drift()
        self.assertTrue(drift_analysis["drift_detected"])
        self.assertTrue(drift_analysis["similarity_ratio"] < 1.0)

if __name__ == "__main__":
    unittest.main()
