from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from agentsentry.core import state

router = APIRouter()

@router.get("/metrics")
async def prometheus_metrics():
    """
    Exposes structured operational telemetry in Prometheus scraping format.
    """
    gateway = state.gateway_instance
    if not gateway:
        raise HTTPException(status_code=500, detail="Gateway not initialized")

    t = gateway.telemetry
    avg_lat = sum(t["latency_records"]) / len(t["latency_records"]) if t["latency_records"] else 0.0
    
    metrics = [
        f"# HELP agentsentry_requests_total Total number of intercepted requests.",
        f"# TYPE agentsentry_requests_total counter",
        f"agentsentry_requests_total {t['total_requests']}",
        
        f"# HELP agentsentry_blocked_actions_total Total number of blocked tool actions.",
        f"# TYPE agentsentry_blocked_actions_total counter",
        f"agentsentry_blocked_actions_total {t['blocked_actions']}",
        
        f"# HELP agentsentry_cache_hits_total Total number of caching prefix hits.",
        f"# TYPE agentsentry_cache_hits_total counter",
        f"agentsentry_cache_hits_total {t['cache_hits']}",
        
        f"# HELP agentsentry_cache_misses_total Total number of caching prefix misses.",
        f"# TYPE agentsentry_cache_misses_total counter",
        f"agentsentry_cache_misses_total {t['cache_misses']}",
        
        f"# HELP agentsentry_latency_overhead_avg_ms Average proxy overhead processing latency.",
        f"# TYPE agentsentry_latency_overhead_avg_ms gauge",
        f"agentsentry_latency_overhead_avg_ms {avg_lat:.6f}",
        
        f"# HELP agentsentry_failed_calls_total Total failed LLM API requests.",
        f"# TYPE agentsentry_failed_calls_total counter",
        f"agentsentry_failed_calls_total {t['failed_calls']}",
        
        f"# HELP agentsentry_retry_attempts_total Total API retry events.",
        f"# TYPE agentsentry_retry_attempts_total counter",
        f"agentsentry_retry_attempts_total {t['retry_attempts']}"
    ]
    
    return PlainTextResponse(content="\n".join(metrics) + "\n")
