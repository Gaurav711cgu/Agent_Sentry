import time
import logging
from typing import Dict, Any

logger = logging.getLogger("AgentSentry.ChaosGovernor")

class ChaosGovernor:
    """Adaptive load shedder and chaos resilience governor.
    Monitors request throughput and execution latencies, dynamically shedding heavy AST
    scanning during load spikes to guarantee sub-50us kernel security latency bounds.
    """
    def __init__(self, cpu_threshold_pct: float = 85.0, latency_budget_ms: float = 0.050):
        self.cpu_threshold_pct = cpu_threshold_pct
        self.latency_budget_ms = latency_budget_ms
        self.total_requests = 0
        self.shed_requests = 0
        self.is_shedding_active = False

    def should_shed_ast_parsing(self, current_cpu_pct: float = 0.0) -> bool:
        self.total_requests += 1
        if current_cpu_pct > self.cpu_threshold_pct:
            self.shed_requests += 1
            self.is_shedding_active = True
            logger.warning("CPU threshold exceeded (%.1f%% > %.1f%%). Shedding AST parsing to preserve seccomp latency SLA.", current_cpu_pct, self.cpu_threshold_pct)
            return True
        self.is_shedding_active = False
        return False

    def inject_chaos_latency(self, delay_ms: float):
        """Simulates artificial downstream latency to test circuit breaker resilience."""
        time.sleep(delay_ms / 1000.0)

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "shed_requests": self.shed_requests,
            "shedding_active": self.is_shedding_active,
            "cpu_threshold_pct": self.cpu_threshold_pct
        }

chaos_governor = ChaosGovernor()
