"""
Health check registry for Anisakys.

Provides extensible health checks for system components.
Built-in checks: database connectivity, circuit breaker states, disk space.

Status values:
    - healthy:   All checks pass, system fully operational
    - degraded:  Some checks warn (e.g. circuit breaker HALF_OPEN, low disk)
    - unhealthy: Critical check failed (e.g. DB unreachable)

Usage:
    >>> from src.observability.health import create_health_checker
    >>> checker = create_health_checker(db_engine=engine, circuit_breakers=breakers)
    >>> result = checker.check_all()
    >>> print(result["status"])  # "healthy" | "degraded" | "unhealthy"
"""

import shutil
import time
from typing import Any, Callable, Dict, Optional


# ---------------------------------------------------------------------------
# Status constants
# ---------------------------------------------------------------------------

STATUS_HEALTHY = "healthy"
STATUS_DEGRADED = "degraded"
STATUS_UNHEALTHY = "unhealthy"


def _aggregate_status(*statuses: str) -> str:
    """Return the worst status from a list of statuses."""
    if STATUS_UNHEALTHY in statuses:
        return STATUS_UNHEALTHY
    if STATUS_DEGRADED in statuses:
        return STATUS_DEGRADED
    return STATUS_HEALTHY


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class HealthCheck:
    """
    Extensible health check registry.

    Components register check functions that return a dict with at minimum:
        {"status": "healthy"|"degraded"|"unhealthy", "message": str}

    Additional fields are allowed and forwarded in the aggregate result.
    """

    def __init__(self) -> None:
        self._checks: Dict[str, Callable[[], Dict[str, Any]]] = {}

    def register(self, name: str, check_fn: Callable[[], Dict[str, Any]]) -> None:
        """
        Register a health check function.

        Args:
            name:     Component name (e.g. "database", "virustotal")
            check_fn: Zero-argument callable returning a status dict
        """
        self._checks[name] = check_fn

    def check_all(self) -> Dict[str, Any]:
        """
        Run all registered checks and return aggregate result.

        Returns:
            {
                "status": "healthy" | "degraded" | "unhealthy",
                "timestamp": float,
                "components": {
                    "<name>": {"status": ..., "message": ..., ...}
                }
            }
        """
        components: Dict[str, Any] = {}
        statuses: list = []

        for name, check_fn in self._checks.items():
            start = time.time()
            try:
                result = check_fn()
                result.setdefault("status", STATUS_HEALTHY)
                result["check_duration_ms"] = round((time.time() - start) * 1000, 2)
            except Exception as exc:
                result = {
                    "status": STATUS_UNHEALTHY,
                    "message": f"Check raised exception: {exc}",
                    "check_duration_ms": round((time.time() - start) * 1000, 2),
                }
            components[name] = result
            statuses.append(result["status"])

        return {
            "status": _aggregate_status(*statuses) if statuses else STATUS_HEALTHY,
            "timestamp": time.time(),
            "components": components,
        }

    def check_component(self, name: str) -> Dict[str, Any]:
        """
        Run a single named check.

        Args:
            name: Component name registered via register()

        Returns:
            Check result dict, or unhealthy if component not found.
        """
        if name not in self._checks:
            return {"status": STATUS_UNHEALTHY, "message": f"No check registered for '{name}'"}
        try:
            return self._checks[name]()
        except Exception as exc:
            return {"status": STATUS_UNHEALTHY, "message": f"Check raised exception: {exc}"}


# ---------------------------------------------------------------------------
# Built-in check functions
# ---------------------------------------------------------------------------


def check_database(db_engine: Any) -> Dict[str, Any]:
    """
    Verify database connectivity by executing a lightweight query.

    Args:
        db_engine: SQLAlchemy engine instance

    Returns:
        Health status dict
    """
    try:
        from sqlalchemy import text

        with db_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": STATUS_HEALTHY, "message": "Database reachable"}
    except Exception as exc:
        return {"status": STATUS_UNHEALTHY, "message": f"Database unreachable: {exc}"}


def check_circuit_breakers(breakers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check the state of all circuit breakers.

    A breaker in OPEN state is unhealthy; HALF_OPEN is degraded; CLOSED is healthy.

    Args:
        breakers: Dict mapping api_name → CircuitBreaker instance

    Returns:
        Health status dict with per-breaker detail
    """
    from src.circuit_breaker import CircuitState

    detail: Dict[str, Any] = {}
    statuses: list = []

    for name, breaker in breakers.items():
        state = breaker.state
        stats = breaker.stats
        if state == CircuitState.OPEN:
            status = STATUS_UNHEALTHY
        elif state == CircuitState.HALF_OPEN:
            status = STATUS_DEGRADED
        else:
            status = STATUS_HEALTHY

        detail[name] = {
            "state": state.value,
            "total_requests": stats.total_requests,
            "failed_requests": stats.failed_requests,
            "rejected_requests": stats.rejected_requests,
            "status": status,
        }
        statuses.append(status)

    return {
        "status": _aggregate_status(*statuses) if statuses else STATUS_HEALTHY,
        "message": f"{len(breakers)} circuit breakers checked",
        "breakers": detail,
    }


def check_disk_space(
    path: str = "/opt/anisakys", warn_threshold_pct: float = 85.0
) -> Dict[str, Any]:
    """
    Check available disk space at the given path.

    Args:
        path:               Path to check (defaults to /opt/anisakys, falls back to /)
        warn_threshold_pct: Percentage used before reporting degraded (default 85%)

    Returns:
        Health status dict with disk usage details
    """
    try:
        check_path = path
        try:
            usage = shutil.disk_usage(check_path)
        except FileNotFoundError:
            check_path = "/"
            usage = shutil.disk_usage(check_path)

        used_pct = (usage.used / usage.total) * 100
        free_gb = usage.free / (1024**3)

        if used_pct >= 95.0:
            status = STATUS_UNHEALTHY
            message = f"Disk critically full: {used_pct:.1f}% used at {check_path}"
        elif used_pct >= warn_threshold_pct:
            status = STATUS_DEGRADED
            message = f"Disk usage high: {used_pct:.1f}% used at {check_path}"
        else:
            status = STATUS_HEALTHY
            message = f"Disk OK: {used_pct:.1f}% used, {free_gb:.1f}GB free at {check_path}"

        return {
            "status": status,
            "message": message,
            "path": check_path,
            "used_pct": round(used_pct, 1),
            "free_gb": round(free_gb, 2),
            "total_gb": round(usage.total / (1024**3), 2),
        }
    except Exception as exc:
        return {"status": STATUS_DEGRADED, "message": f"Could not check disk: {exc}"}


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_health_checker(
    db_engine: Optional[Any] = None,
    circuit_breakers: Optional[Dict[str, Any]] = None,
    check_disk: bool = True,
    disk_path: str = "/opt/anisakys",
) -> HealthCheck:
    """
    Create a HealthCheck instance with standard checks pre-registered.

    Args:
        db_engine:        SQLAlchemy engine (registers DB check if provided)
        circuit_breakers: Dict of api_name → CircuitBreaker (registers CB check if provided)
        check_disk:       Whether to register a disk space check (default True)
        disk_path:        Path for disk check (default /opt/anisakys)

    Returns:
        Configured HealthCheck instance

    Example:
        >>> checker = create_health_checker(db_engine=engine, circuit_breakers=breakers)
        >>> result = checker.check_all()
    """
    checker = HealthCheck()

    if db_engine is not None:
        checker.register("database", lambda: check_database(db_engine))

    if circuit_breakers is not None:
        checker.register("circuit_breakers", lambda: check_circuit_breakers(circuit_breakers))

    if check_disk:
        checker.register("disk", lambda: check_disk_space(disk_path))

    return checker
