import os
import sys

# Ensure the root directory is in the path to allow importing the local agentsentry package
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentsentry.config import AgentSentryConfig
from agentsentry.gateway import AgentSentryGateway, create_app

# 1. Initialize configuration with defaults suitable for serverless env
config = AgentSentryConfig()
config.workspace_root = os.getenv("WORKSPACE_ROOT", "/tmp")
config.cache_savings_threshold = float(os.getenv("CACHE_SAVINGS_THRESHOLD", "0.10"))

# 2. Instantiate the gateway
# For serverless, trace files are written to /tmp (Vercel's only writeable directory)
trace_file = os.getenv("TRACE_FILE", "/tmp/agentsentry_trace.json")
gateway = AgentSentryGateway(
    config=config,
    trace_file=trace_file,
    is_replay_mode=False,
    use_docker=False  # Docker is not supported in Vercel Serverless environment
)

# 3. Create the FastAPI app
app = create_app(gateway)
