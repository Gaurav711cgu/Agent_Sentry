import asyncio
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from agentsentry.core import state

router = APIRouter()

@router.post("/execute")
async def execute_tool(request: Request):
    gateway = state.gateway_instance
    if not gateway:
        raise HTTPException(status_code=500, detail="Gateway not initialized")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    tool_name = payload.get("tool")
    arguments = payload.get("arguments", {})

    if not tool_name:
        raise HTTPException(status_code=400, detail="Missing required field: tool")

    result = await gateway.route_tool_call_async(tool_name, arguments)
    
    if result["status"] == "blocked":
        return JSONResponse(status_code=403, content=result)
    
    return JSONResponse(content=result)

@router.post("/execute-safe")
async def execute_tool_safely(request: Request):
    """
    Inspects command and executes it inside the isolated Docker/subprocess sandbox.
    """
    gateway = state.gateway_instance
    if not gateway:
        raise HTTPException(status_code=500, detail="Gateway not initialized")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    command = payload.get("command")
    if not command:
        raise HTTPException(status_code=400, detail="Missing required field: command")

    loop = asyncio.get_event_loop()
    # Execute safely in thread pool to prevent blocking FastAPI event loop
    is_safe, ret_code, stdout, stderr = await loop.run_in_executor(
        None, gateway.firewall.execute_safely, command
    )

    if not is_safe:
        return JSONResponse(status_code=403, content={
            "status": "blocked",
            "message": stderr
        })

    return JSONResponse(content={
        "status": "success",
        "return_code": ret_code,
        "stdout": stdout,
        "stderr": stderr
    })
