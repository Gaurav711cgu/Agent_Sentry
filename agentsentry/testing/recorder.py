import json
import os
import logging
from typing import List, Dict, Any

logger = logging.getLogger("AgentSentry.Recorder")

class TrajectoryRecorder:
    def __init__(self, trace_file: str):
        self.trace_file = trace_file
        self.trajectory: List[Dict[str, Any]] = []

    def record_step(self, step_type: str, action: str, data: Any):
        """
        Appends an execution step to the current agent session trace list.
        """
        step_number = len(self.trajectory) + 1
        self.trajectory.append({
            "step": step_number,
            "type": step_type,
            "action": action,
            "data": data
        })

    async def save_trace_async(self):
        """
        Asynchronously writes the recorded trajectory trace to file.
        Use non-blocking async loops.
        """
        if not self.trajectory:
            return

        try:
            # We defer execution to a thread pool via standard async tools or loop run_in_executor
            # to prevent blocking the FastAPI main server threads during high load I/O.
            import asyncio
            loop = asyncio.get_event_loop()
            
            def sync_save():
                directory = os.path.dirname(os.path.abspath(self.trace_file))
                os.makedirs(directory, exist_ok=True)
                with open(self.trace_file, 'w') as f:
                    json.dump(self.trajectory, f, indent=2)

            await loop.run_in_executor(None, sync_save)
            logger.info(f"Trajectory trace saved asynchronously to: {self.trace_file}")
        except Exception as e:
            logger.error(f"Failed to write trajectory trace asynchronously: {str(e)}")
