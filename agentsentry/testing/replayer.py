import json
import os
import logging
import asyncio
import math
from collections import Counter
from typing import List, Dict, Any, Tuple

logger = logging.getLogger("AgentSentry.Replayer")

def _compute_cosine_similarity(text1: str, text2: str) -> float:
    """
    Computes a lightweight semantic cosine similarity between two text strings using TF-IDF principles.
    This serves as the core of the Semantic Drift tracking.
    """
    # Tokenize
    words1 = text1.lower().split()
    words2 = text2.lower().split()
    
    # Term frequencies
    vec1 = Counter(words1)
    vec2 = Counter(words2)
    
    intersection = set(vec1.keys()) & set(vec2.keys())
    numerator = sum([vec1[x] * vec2[x] for x in intersection])
    
    sum1 = sum([vec1[x]**2 for x in list(vec1.keys())])
    sum2 = sum([vec2[x]**2 for x in list(vec2.keys())])
    denominator = math.sqrt(sum1) * math.sqrt(sum2)
    
    if not denominator:
        return 0.0
    else:
        return float(numerator) / denominator

class TrajectoryReplayer:
    def __init__(self, trace_file: str):
        self.trace_file = trace_file
        self.reference_trajectory: List[Dict[str, Any]] = []
        self.current_trajectory: List[Dict[str, Any]] = []

    async def load_reference_async(self):
        """
        Asynchronously loads reference trace configurations using running executors.
        """
        if not os.path.exists(self.trace_file):
            return

        try:
            loop = asyncio.get_event_loop()
            def sync_load():
                with open(self.trace_file, 'r') as f:
                    return json.load(f)

            self.reference_trajectory = await loop.run_in_executor(None, sync_load)
            logger.info(f"Loaded reference trajectory asynchronously ({len(self.reference_trajectory)} steps)")
        except Exception as e:
            logger.error(f"Failed to read reference trajectory asynchronously: {str(e)}")

    def get_mock_response(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, Any]:
        """
        Retrieves mock responses matching parameters.
        """
        for step in self.reference_trajectory:
            if step["type"] == "tool_call" and step["action"] == tool_name:
                ref_args = step["data"].get("arguments", {})
                if ref_args == arguments:
                    response_step = self._find_response_step(step["step"])
                    if response_step:
                        return True, response_step["data"]
        return False, None

    def _find_response_step(self, call_step_number: int) -> Dict[str, Any]:
        for step in self.reference_trajectory:
            if step["type"] == "tool_response":
                if step["data"].get("matching_call_step") == call_step_number:
                    return step
        return None

    def record_replay_step(self, step_type: str, action: str, data: Any):
        step_number = len(self.current_trajectory) + 1
        self.current_trajectory.append({
            "step": step_number,
            "type": step_type,
            "action": action,
            "data": data
        })

    def analyze_trajectory_drift(self, semantic_threshold: float = 0.85) -> Dict[str, Any]:
        """
        Detects argument-divergence drift between a reference trajectory and
        the current replay session.

        Two levels of comparison:
          1. Structural: action name mismatch → immediate drift
          2. Argument: JSON string divergence → cosine similarity below threshold

        Note: the similarity metric is bag-of-words cosine on JSON strings,
        not embedding-based semantic similarity.
        """
        if not self.reference_trajectory:
            return {"drift_detected": False, "similarity_ratio": 1.0,
                    "reason": "No reference trajectory loaded."}

        drift_points = []
        drift_detected = False

        min_length = min(len(self.reference_trajectory), len(self.current_trajectory))
        for i in range(min_length):
            ref  = self.reference_trajectory[i]
            curr = self.current_trajectory[i]

            # Level 1: action name mismatch
            if ref["type"] != curr["type"] or ref["action"] != curr["action"]:
                drift_detected = True
                drift_points.append({
                    "step": i + 1,
                    "reason": "Action sequence mismatch",
                    "reference": f"{ref['type']}/{ref['action']}",
                    "current":   f"{curr['type']}/{curr['action']}",
                })
                break

            # Level 2: argument divergence (for tool_call steps)
            if ref["type"] == "tool_call":
                ref_args  = ref["data"].get("arguments", {})
                curr_args = curr["data"].get("arguments", {})

                if ref_args != curr_args:
                    ref_str  = json.dumps(ref_args,  sort_keys=True)
                    curr_str = json.dumps(curr_args, sort_keys=True)
                    sim = _compute_cosine_similarity(ref_str, curr_str)

                    if sim < semantic_threshold:
                        drift_detected = True
                        drift_points.append({
                            "step":            i + 1,
                            "reason":          "Argument divergence detected",
                            "similarity":      round(sim, 4),
                            "reference_args":  ref_args,
                            "current_args":    curr_args,
                        })
                    else:
                        logger.info(f"Step {i+1}: minor arg variance tolerated (sim={sim:.3f})")

        # Length mismatch
        if not drift_detected and len(self.reference_trajectory) != len(self.current_trajectory):
            drift_detected = True
            drift_points.append({
                "step":             min_length + 1,
                "reason":           "Trajectory length mismatch",
                "reference_steps":  len(self.reference_trajectory),
                "current_steps":    len(self.current_trajectory),
            })

        # Similarity ratio = matching steps / max steps
        matching = sum(
            1 for i in range(min_length)
            if (self.reference_trajectory[i]["type"]   == self.current_trajectory[i]["type"] and
                self.reference_trajectory[i]["action"] == self.current_trajectory[i]["action"] and
                self.reference_trajectory[i]["data"].get("arguments", {}) ==
                self.current_trajectory[i]["data"].get("arguments", {}))
        )
        total = max(len(self.reference_trajectory), len(self.current_trajectory))
        similarity = matching / total if total > 0 else 1.0

        return {
            "drift_detected":          drift_detected,
            "similarity_ratio":        similarity,
            "similarity_threshold":    semantic_threshold,
            "drift_points":            drift_points,
            "matching_steps":          matching,
            "total_steps_compared":    total,
        }

