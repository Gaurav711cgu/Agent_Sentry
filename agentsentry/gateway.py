from fastapi import FastAPI
from agentsentry.core import state
from agentsentry.core.gateway import AgentSentryGateway
from agentsentry.api.routers import llm, tools, metrics, webhooks
from agentsentry.services.agent import DevSecOpsSentinelAgent

# FastAPI Web Server Factory
def create_app(gateway: AgentSentryGateway) -> FastAPI:
    app = FastAPI(title="AgentSentry Gateway Proxy", version="1.0.0")

    # Set the global state so routers can access it
    state.gateway_instance = gateway

    @app.on_event("startup")
    async def startup_event():
        await gateway.initialize_async()
        
        # Initialize GitLab Sentinel Agent
        sentinel_agent = DevSecOpsSentinelAgent(gateway.config)
        webhooks.register_agent_runner(sentinel_agent.execute_agent_loop)
        
    @app.on_event("shutdown")
    async def shutdown_event():
        await gateway.finalize_session_async()

    # Include routers
    app.include_router(llm.router, prefix="/v1")
    app.include_router(tools.router, prefix="/v1/tools")
    app.include_router(webhooks.router, prefix="/v1/webhooks")
    app.include_router(metrics.router)

    return app
