import argparse
import sys
import uvicorn
import logging

from agentsentry.config import AgentSentryConfig
from agentsentry.gateway import AgentSentryGateway, create_app

logger = logging.getLogger("AgentSentry.CLI")

def run_start(args):
    """
    Launches the FastAPI gateway proxy server.
    """
    config_file = args.config
    trace_file = args.trace
    port = args.port
    host = args.host
    replay = args.replay

    print(f"Initializing AgentSentry on {host}:{port}...")
    
    config = AgentSentryConfig(config_file)
    gateway = AgentSentryGateway(config, trace_file, is_replay_mode=replay)
    app = create_app(gateway)
    
    uvicorn.run(app, host=host, port=port, loop="uvloop")

def run_init(args):
    """
    Saves a default configuration JSON profile.
    """
    target = args.output
    config = AgentSentryConfig()
    config.save_defaults(target)
    print(f"Default configuration written successfully to: {target}")

def run_benchmark(args):
    """
    Trigger the verification test harness.
    """
    # Import the benchmark runner execution segment dynamically
    try:
        from harness.run_benchmarks import main as run_test
        print("Starting AgentSentry verification benchmarks...")
        run_test()
    except Exception as e:
        print(f"Failed to execute verification benchmark harness: {str(e)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="AgentSentry: Enterprise Security, Cache, and Trajectory Validation Gateway for AI Agents"
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Start subcommand
    start_parser = subparsers.add_parser("start", help="Launches the proxy gateway server")
    start_parser.add_argument("--config", "-c", type=str, help="Path to config JSON file")
    start_parser.add_argument("--trace", "-t", type=str, default="trace_cache/trajectory.json", help="Path to trajectory trace file")
    start_parser.add_argument("--port", "-p", type=int, default=8000, help="Server port number")
    start_parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host IP")
    start_parser.add_argument("--replay", action="store_true", help="Launch server in trajectory replay test mode")

    # Init subcommand
    init_parser = subparsers.add_parser("init", help="Generates default configuration settings")
    init_parser.add_argument("--output", "-o", type=str, default="config/default_policy.json", help="Output path for config JSON")

    # Benchmark subcommand
    subparsers.add_parser("benchmark", help="Triggers verification benchmark harness checks")

    args = parser.parse_args()

    if args.command == "start":
        run_start(args)
    elif args.command == "init":
        run_init(args)
    elif args.command == "benchmark":
        run_benchmark(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
