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
        Analyzes trajectory drift including Semantic Drift Tracking.
        """
        if not self.reference_trajectory:
            return {"drift_detected": False, "similarity_ratio": 1.0, "reason": "No reference trajectory loaded."}

        drift_points = []
        drift_detected = False

        min_length = min(len(self.reference_trajectory), len(self.current_trajectory))
        for i in range(min_length):
            ref = self.reference_trajectory[i]
            curr = self.current_trajectory[i]

            if ref["type"] != curr["type"] or ref["action"] != curr["action"]:
                drift_detected = True
                drift_points.append({
                    "step": i + 1,
                    "reason": "Execution sequence action mismatch",
                    "reference": f"Type: {ref['type']}, Action: {ref['action']}",
                    "current": f"Type: {curr['type']}, Action: {curr['action']}"
                })
                break

            if ref["type"] == "tool_call" and ref["action"] == curr["action"]:
                ref_args = ref["data"].get("arguments", {})
                curr_args = curr["data"].get("arguments", {})
                
                # Semantic Drift Check
                ref_str = json.dumps(ref_args, sort_keys=True)
                curr_str = json.dumps(curr_args, sort_keys=True)
                
                if ref_str != curr_str:
                    semantic_score = _compute_cosine_similarity(ref_str, curr_str)
                    
                    if semantic_score < semantic_threshold:
                        drift_detected = True
                        drift_points.append({
                            "step": i + 1,
                            "reason": "Semantic Drift detected in tool arguments",
                            "semantic_score": semantic_score,
                            "reference_args": ref_args,
                            "current_args": curr_args
                        })
                    else:
                        logger.info(f"Step {i+1}: Minor variance tolerated (score: {semantic_score:.2f} >= {semantic_threshold})")

        if not drift_detected and len(self.reference_trajectory) != len(self.current_trajectory):
            drift_detected = True
            drift_points.append({
                "step": min_length + 1,
                "reason": "Trajectory sequence length mismatch",
                "reference_steps": len(self.reference_trajectory),
                "current_steps": len(self.current_trajectory)
            })

        matching_steps = 0
        for i in range(min_length):
            ref = self.reference_trajectory[i]
            curr = self.current_trajectory[i]
            if ref["type"] == curr["type"] and ref["action"] == curr["action"]:
                matching_steps += 1

        total_max_steps = max(len(self.reference_trajectory), len(self.current_trajectory))
        similarity = (matching_steps / total_max_steps) if total_max_steps > 0 else 1.0

        return {
            "drift_detected": drift_detected,
            "similarity_ratio": similarity,
            "semantic_threshold_used": semantic_threshold,
            "drift_points": drift_points
        }
