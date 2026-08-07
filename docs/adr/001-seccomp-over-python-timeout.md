# ADR 001: Kernel-Level Seccomp-BPF & POSIX Rlimits over Pure Python Timeouts

**Status:** Accepted  
**Date:** Aug 2026  
**Deciders:** Senior Security Architect

---

## Context & Problem Statement
AgentSentry previously relied on Python-level text regex and `multiprocessing` timeouts to guard against malicious agent payloads.

In security audits, pure text regex and Python timeouts suffer from critical vulnerabilities:
1. **Obfuscation Bypasses:** Base64, Hex, ROT13, and Unicode homoglyphs bypass static regex string patterns.
2. **CPU & Memory Starvation:** Infinite loops (`while True: pass`) or large memory allocations (`[0] * 10**10`) hang Python application processes, evading non-preemptive timeouts.
3. **Unauthorized Subprocess Calls:** Sub-processes spawned via `subprocess.Popen` can invoke system binaries (`nc`, `curl`, `execve`) even if Python code is constrained.

---

## Decision Outcome
**Chosen Option:** **Kernel-Level `seccomp-bpf` System Call Filtering & POSIX `rlimits`**

### Rationale:
- **Kernel-Level Enforcing:** `seccomp-bpf` hooks directly into the Linux kernel via `prctl(PR_SET_SECCOMP)`. Unwanted system calls (`execve`, `socket`, `open`, `fork`) trigger an immediate `SIGKILL` signal from the OS kernel, bypassing Python runtime dependencies.
- **3-Layer Bypass Detection:** Normalizes Unicode NFKC homoglyphs and decodes Base64/Hex/URL inputs before running AST analysis.
- **Resource Hardening:** Sets POSIX kernel limits (`RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_NPROC`) directly on child process executions, preventing fork bombs and memory spikes.
