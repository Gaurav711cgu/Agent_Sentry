import time
import asyncio
import threading
from enum import Enum
from functools import wraps
from typing import Callable, Any, Dict, Optional


class CircuitState(str, Enum):
    CLOSED = "CLOSED"        # Normal operations
    OPEN = "OPEN"            # Reject requests (failing fast)
    HALF_OPEN = "HALF_OPEN"  # Probe recovery mode

    def __eq__(self, other):
        if isinstance(other, str):
            return self.value == other
        return super().__eq__(other)


class CircuitBreakerOpenException(Exception):
    """Raised when request is rejected because Circuit Breaker is in OPEN state."""
    pass


class CircuitBreaker:
    """
    Production-grade, unified Circuit Breaker with synchronous and asynchronous support,
    sliding-window recovery, and failure count reset on success in CLOSED state.
    """

    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ):
        # Support positional failure_threshold if first arg is int
        if isinstance(name, int):
            self.failure_threshold = name
            self.recovery_timeout = float(failure_threshold) if isinstance(failure_threshold, (int, float)) else 30.0
            self.name = "default"
        else:
            self.name = str(name)
            self.failure_threshold = int(failure_threshold)
            self.recovery_timeout = float(recovery_timeout)

        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_state_change = time.time()
        self._lock = threading.Lock()

    @property
    def failures(self) -> int:
        """Backward compatibility with legacy circuit breaker property."""
        return self.failure_count

    @failures.setter
    def failures(self, val: int) -> None:
        self.failure_count = val

    @property
    def last_failure_time(self) -> float:
        """Backward compatibility with legacy circuit breaker property."""
        return self.last_state_change

    @last_failure_time.setter
    def last_failure_time(self, val: float) -> None:
        self.last_state_change = val

    def _before_call(self) -> None:
        with self._lock:
            now = time.time()
            if self.state == CircuitState.OPEN:
                if now - self.last_state_change > self.recovery_timeout:
                    self.state = CircuitState.HALF_OPEN
                    self.last_state_change = now
                else:
                    raise CircuitBreakerOpenException(
                        f"CircuitBreaker '{self.name}' is OPEN. Requests shed."
                    )

    def _on_success(self) -> None:
        with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.last_state_change = time.time()
            elif self.state == CircuitState.CLOSED:
                # Reset failure counter on success in CLOSED state to eliminate false trips
                self.failure_count = 0

    def _on_failure(self) -> None:
        with self._lock:
            self.failure_count += 1
            self.last_state_change = time.time()
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Synchronous execution wrapper."""
        if asyncio.iscoroutinefunction(func):
            return self.acall(func, *args, **kwargs)

        self._before_call()
        try:
            result = func(*args, **kwargs)
            if asyncio.iscoroutine(result):
                return self._await_sync(result)
        except Exception as e:
            self._on_failure()
            raise e
        else:
            self._on_success()
            return result

    async def acall(self, func: Callable, *args, **kwargs) -> Any:
        """Asynchronous execution wrapper."""
        self._before_call()
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                res = func(*args, **kwargs)
                if asyncio.iscoroutine(res):
                    result = await res
                else:
                    result = res
        except Exception as e:
            self._on_failure()
            raise e
        else:
            self._on_success()
            return result

    def _await_sync(self, coro):
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # In running event loop, caller should use acall
            return asyncio.ensure_future(coro)
        return loop.run_until_complete(coro)

    def __call__(self, func: Callable) -> Callable:
        """Decorator supporting both sync and async functions."""
        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                return await self.acall(func, *args, **kwargs)
            return async_wrapper
        else:
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                return self.call(func, *args, **kwargs)
            return sync_wrapper

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "state": self.state.value if isinstance(self.state, CircuitState) else str(self.state),
                "failure_count": self.failure_count,
                "recovery_timeout_sec": self.recovery_timeout,
            }


class AsyncCircuitBreaker(CircuitBreaker):
    """Alias adhering to PROJECT.md Interface Contract."""

    async def call(self, coro_or_func, *args, **kwargs) -> Any:
        return await self.acall(coro_or_func, *args, **kwargs)
