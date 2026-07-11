from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from agentsentry.core import state

router = APIRouter()

@router.post("/chat/completions")
async def chat_completions(request: Request):
    gateway = state.gateway_instance
    if not gateway:
        raise HTTPException(status_code=500, detail="Gateway not initialized")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    session_id = request.headers.get("X-Session-ID", "default_session")
    provider = request.headers.get("X-LLM-Provider", "anthropic")
    
    # 1. Process prompt alignment and caching deltas
    optimized_payload, overhead = await gateway.process_llm_request_async(session_id, payload)
    
    # 2. Route request to simulated LLM with retries & failover logic
    llm_response = await gateway.execute_llm_call_with_retry(provider, optimized_payload)

    return JSONResponse(content={
        "status": "success",
        "overhead_ms": overhead,
        "savings_ratio": optimized_payload["savings_ratio"],
        "llm_response": llm_response
    })
