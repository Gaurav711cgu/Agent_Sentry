#!/bin/bash
export PYTHONPATH=$(pwd)
python3 agentsentry/cli.py start -p 8000 &
SERVER_PID=$!

echo "Waiting for server to start..."
sleep 2

python3 harness/load_test_10k_rps.py

kill $SERVER_PID
