# AgentSentry: Secure Sandboxing & Prompt Caching Middleware for LLM Agents

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![Git](https://img.shields.io/badge/Git-F05032?style=flat-square&logo=git&logoColor=white)
![Vercel](https://img.shields.io/badge/Vercel-000000?style=flat-square&logo=vercel&logoColor=white)

AgentSentry is a security and optimization gateway for autonomous LLM agents. It shields agent execution runtimes from malicious tool execution breakouts while cutting token costs in half using an intelligent header alignment prompt caching layer.

---

## Key Capabilities

### 1. AST Command Validation (Exploit Shield)
Autonomous agents executing shell commands introduce remote execution (RCE) hazards. AgentSentry recursively checks command structures before execution:
- Parses commands using a Recursive Abstract Syntax Tree (AST) validator.
- Intercepts subshell breakouts, command chaining, and directory traversals.
- Blocks execution immediately if anomalies or untrusted binary commands are detected.

### 2. Suffix-Delta Prompt Caching
LLM API pricing is optimized by prompt prefix caching. However, dynamic user history breaks prefix hashing alignment. AgentSentry:
- Dynamically reorders static headers (e.g., system prompts, schemas) to the beginning.
- Aligns dynamic suffix components to maximize hashing overlap.
- Achieves up to 50% savings on LLM invocation fees.

### 3. Deterministic Mock-Replays (Taming Prompt Drift)
Prompt changes can cause agent trajectories to drift, resulting in tool-use failures or infinite loops. AgentSentry:
- Records and replays deterministic agent tool-call traces.
- Employs Levenshtein distance metrics to measure trace similarity and report drift.
- Automatically flags divergent execution sequences during CI/CD checks.

---

## System Architecture

```mermaid
graph TD
    A[Agent Runtime Engine] -->|Executes Tool Command| B[AgentSentry Middleware]
    B -->|Parse Command AST| C{Recursive AST Scanner}
    C -->|Unsafe syntax or command| D[Block & Alert]
    C -->|Safe command| E[Docker Execution Sandbox]
    
    A -->|LLM API Request| F[Prompt Hashing Layer]
    F -->|Suffix-Delta Reordering| G[Aligned Prompt Cache]
    G -->|API Invocation| H[LLM Provider]

    Directory Structure
yaml


agentsentry/
  ├── core/
  │   ├── ast_parser.py     # Recursive AST command analyzer & blocker
  │   ├── cache.py          # Suffix-delta prompt alignment & caching logic
  │   └── replays.py        # Levenshtein trace similarity and mock-replay runner
  ├── sandbox/
  │   ├── docker_runtime.py # Containerized environment execution layer
  │   └── config.json       # Sandbox CPU, Memory, and Network restrictions
  ├── api/
  │   └── gateway.py        # FastAPI middleware endpoints
  ├── tests/                # Test suite for exploit payloads & caching efficiency
  └── main.py               # Gateway entrypoint
Getting Started
1. Installation
Clone the repository and install dependencies:

bash


git clone https://github.com/Gaurav711cgu/Agent_Sentry.git
cd Agent_Sentry
pip install -r requirements.txt
2. Configure Sandbox Environment
Ensure Docker is running, then build the sandbox execution container:

bash


docker build -t agentsentry-sandbox ./sandbox
3. Run the Security Gateway
Launch the FastAPI gateway server:

bash


uvicorn main:app --host 0.0.0.5 --port 8080
Running Security & Cache Tests
To validate the AST interceptor against exploit payloads and evaluate cache alignment efficiency:

bash


pytest tests/
Example Log Output:
text


[AST WARNING] Blocked exploit payload: "cat secret.txt || rm -rf /" (type: CMD_CHAINING)
[CACHE INFO] Prompt prefix alignment achieved. Hashing cache hit rate: 94.6%. Token savings: 51.2%.
[REPLAY OK] Trace similarity score: 1.00 (No prompt drift detected).
Security Disclaimers
AgentSentry reduces risk in agent-driven runtime systems. However, container isolation and AST parsing are not bulletproof. Always run agent systems inside isolated virtual networks with limited write privileges on parent drives.

License
This project is licensed under the MIT License - see the LICENSE file for details.






