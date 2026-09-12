"""
Circuit Breaker Pattern for AgentSentry.
Prevents cascading failures when external monitoring/LLM systems go down.
Unified with agentsentry.core.circuit_breaker.
"""

from agentsentry.core.circuit_breaker import (
    CircuitBreaker,
    AsyncCircuitBreaker,
    CircuitState,
    CircuitBreakerOpenException,
)

__all__ = [
    "CircuitBreaker",
    "AsyncCircuitBreaker",
    "CircuitState",
    "CircuitBreakerOpenException",
]
