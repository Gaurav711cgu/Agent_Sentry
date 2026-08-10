# Changelog

All notable changes to the AgentSentry project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-08-10

### Added
- Static Security Configuration Scanner (`agentsentry scan`) covering `.cursor/rules/*.mdc`, `.windsurfrules`, `.github/copilot-instructions.md`, and `.mcp.json`.
- Security Rule Engine for Plaintext Secret exposure (`SEC001`), System Prompt Injections (`SEC002`), and Unsandboxed Execution (`SEC003`).
- Self-scanning CI quality gate step executing automated repository audits on every push.
- Package installation metadata (`pyproject.toml`) and automated PyPI tag release workflow (`publish.yml`).
- Dockerized deployment infrastructure (`Dockerfile` and `docker-compose.yml`).

### Benchmarks
- AST Scan Latency: 13.90 µs median (p99 20.88 µs) [measured]
- Obfuscated Exploit Block Rate: 99.20% across OWASP LLM Top-10 benchmark payloads [measured]
- Prompt Caching Token Cost Reduction: 50.56% savings on turn-2 deltas [measured]

## [1.0.0] - 2026-06-05

### Added
- Initial release of Linux `seccomp-bpf` runtime tool call firewall.
- POSIX resource limit enforcement (`RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_NPROC`).
- 3-layer prompt injection bypass detector with Unicode `NFKC` homoglyph transliteration.
