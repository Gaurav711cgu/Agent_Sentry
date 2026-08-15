import pytest
from agentsentry.core.circuit_breaker import CircuitBreaker, CircuitBreakerOpenException, CircuitState
from agentsentry.core.chaos_governor import ChaosGovernor

def test_circuit_breaker_transitions():
    breaker = CircuitBreaker(name="test_tool", failure_threshold=2, recovery_timeout=0.2)
    assert breaker.state == CircuitState.CLOSED

    def failing_func():
        raise RuntimeError("Tool execution failed")

    with pytest.raises(RuntimeError):
        breaker.call(failing_func)
    assert breaker.state == CircuitState.CLOSED

    with pytest.raises(RuntimeError):
        breaker.call(failing_func)
    assert breaker.state == CircuitState.OPEN

    # Subsequent call while OPEN should raise CircuitBreakerOpenException immediately
    with pytest.raises(CircuitBreakerOpenException):
        breaker.call(lambda: "ok")

def test_chaos_governor_adaptive_shedding():
    governor = ChaosGovernor(cpu_threshold_pct=80.0)
    assert not governor.should_shed_ast_parsing(current_cpu_pct=50.0)
    assert governor.get_metrics()["shedding_active"] is False

    assert governor.should_shed_ast_parsing(current_cpu_pct=90.0)
    assert governor.get_metrics()["shedding_active"] is True
    assert governor.get_metrics()["shed_requests"] == 1
