import time
import threading
from enum import Enum
from typing import Callable, Any, Dict

class CircuitState(Enum):
    CLOSED = "CLOSED"        # Normal operations
    OPEN = "OPEN"            # Reject requests (failing fast)
    HALF_OPEN = "HALF_OPEN"  # Probe recovery mode

class CircuitBreakerOpenException(Exception):
    """Raised when request is rejected because Circuit Breaker is in OPEN state."""
    pass

class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 5, recovery_timeout: float = 30.0):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_state_change = time.time()
        self._lock = threading.Lock()

    def call(self, func: Callable, *args, **kwargs) -> Any:
        with self._lock:
            now = time.time()
            if self.state == CircuitState.OPEN:
                if now - self.last_state_change > self.recovery_timeout:
                    self.state = CircuitState.HALF_OPEN
                    self.last_state_change = now
                else:
                    raise CircuitBreakerOpenException(f"CircuitBreaker '{self.name}' is OPEN. Requests shed.")

        try:
            result = func(*args, **kwargs)
        except Exception as e:
            self._on_failure()
            raise e
        else:
            self._on_success()
            return result

    def _on_success(self):
        with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.last_state_change = time.time()

    def _on_failure(self):
        with self._lock:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN
                self.last_state_change = time.time()

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "state": self.state.value,
                "failure_count": self.failure_count,
                "recovery_timeout_sec": self.recovery_timeout
            }
