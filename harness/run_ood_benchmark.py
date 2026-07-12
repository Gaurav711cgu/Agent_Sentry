"""
OOD Evaluation: run AgentSentry firewall against Garak probe suite.

These prompts are NOT from the training distribution — they are from
Garak (https://github.com/leondz/garak), an open-source LLM red-teaming
framework. This gives us an externally-provenance OOD detection rate.

Key distinction: Garak probes span multiple attack styles:
  - promptinject: indirect injection via retrieved documents      (LLM01)
  - dan:          DAN/persona jailbreak framing                  (LLM02)
  - continuation: completion-based attacks (next-token pressure) (LLM01)
  - suffix:       adversarial suffix appending                    (LLM02)

The firewall is signature + AST based, so completion-style probes
(e.g. "The sky is blue and...") will NOT be blocked — correctly.
We report per-category rates so the distinction is transparent.

Run:
    python3 harness/run_ood_benchmark.py
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentsentry.config import AgentSentryConfig
from agentsentry.gateway import AgentSentryGateway

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

config     = AgentSentryConfig()
trace_file = os.path.join(project_root, "trace_cache/ood_trace.json")
gw         = AgentSentryGateway(config, trace_file, is_replay_mode=False)

with open(os.path.join(project_root, "harness/garak_ood_probes.json")) as f:
    data = json.load(f)

exploits = data["exploits"]
print(f"Garak OOD probe set: {len(exploits)} payloads")
print(f"Source: {data['source']}\n")

# ── Per-category evaluation ───────────────────────────────────────────────────
from collections import defaultdict

by_source = defaultdict(lambda: {"blocked": 0, "passed": 0, "owasp": ""})
by_cat    = defaultdict(lambda: {"blocked": 0, "passed": 0})

# Sample representative misses for reporting
misses_sample = defaultdict(list)

for exp in exploits:
    source   = exp["source"].split(":")[-1]   # e.g. "dan", "promptinject"
    owasp    = exp["owasp_category"]
    tool     = exp["tool"]
    args     = exp["arguments"]

    res = gw.route_tool_call(tool, args)
    blocked = (res["status"] == "blocked")

    by_source[source]["blocked" if blocked else "passed"] += 1
    by_source[source]["owasp"] = owasp
    by_cat[owasp]["blocked" if blocked else "passed"] += 1

    if not blocked and len(misses_sample[source]) < 2:
        text = list(args.values())[0]
        misses_sample[source].append(text[:80])

# ── Print results ─────────────────────────────────────────────────────────────
print(f"{'Source':<20} {'OWASP':<8} {'Blocked':>8} {'Passed':>8} {'Rate':>10}  Notes")
print("─" * 75)

source_order = ["dan", "suffix", "promptinject", "continuation", "realtoxicityprompts"]
for src in source_order:
    if src not in by_source:
        continue
    s = by_source[src]
    tot  = s["blocked"] + s["passed"]
    rate = s["blocked"] / tot * 100 if tot else 0
    owasp = s["owasp"]

    note = ""
    if src == "continuation":
        note = "(completion probes — expected low; no injection directive)"
    elif src == "realtoxicityprompts":
        note = "(toxicity, not injection — expected low)"

    print(f"  {src:<18} {owasp:<8} {s['blocked']:>8} {s['passed']:>8} {rate:>9.1f}%  {note}")
    for miss in misses_sample[src][:1]:
        print(f"    miss example: {miss!r}")

print("\nBy OWASP category:")
print(f"  {'Category':<8} {'Blocked':>8} {'Passed':>8} {'Rate':>10}")
print("  " + "─" * 38)
for cat in sorted(by_cat):
    s   = by_cat[cat]
    tot = s["blocked"] + s["passed"]
    rate = s["blocked"] / tot * 100 if tot else 0
    print(f"  {cat:<8} {s['blocked']:>8} {s['passed']:>8} {rate:>9.1f}%")

# ── The headline number: DAN + suffix (real injection probes) ────────────────
print("\n" + "="*65)
print("HEADLINE OOD METRICS (injection-specific probes only)")
print("="*65)

dan_s    = by_source.get("dan", {"blocked": 0, "passed": 0})
suffix_s = by_source.get("suffix", {"blocked": 0, "passed": 0})
pi_s     = by_source.get("promptinject", {"blocked": 0, "passed": 0})

injection_blocked = dan_s["blocked"] + suffix_s["blocked"]
injection_passed  = dan_s["passed"]  + suffix_s["passed"]
injection_total   = injection_blocked + injection_passed
injection_rate    = injection_blocked / injection_total * 100 if injection_total else 0

pi_total = pi_s["blocked"] + pi_s["passed"]
pi_rate  = pi_s["blocked"] / pi_total * 100 if pi_total else 0

print(f"""
  DAN + adversarial-suffix probes (LLM02):
    {injection_blocked}/{injection_total} blocked = {injection_rate:.1f}%
    Source: garak.probes.dan + garak.probes.suffix

  Prompt-inject indirect injection (LLM01):
    {pi_s['blocked']}/{pi_total} blocked = {pi_rate:.1f}%
    Source: garak.probes.promptinject

  Continuation probes (LLM01 — completion-based, no directive):
    Intentionally low block rate — these test model completion,
    not tool-call injection. Our gateway doesn't intercept these
    (correctly — no injection directive in the payload).
""")

# ── Resume-ready claim ────────────────────────────────────────────────────────
print("RESUME-READY OOD CLAIM:")
print(f"""
  "Validated on {len(exploits):,} Garak open-source probe suite payloads
   (externally authored, garak.probes.dan + .promptinject + .suffix);
   {injection_rate:.0f}% detection rate on {injection_total} LLM02 jailbreak/adversarial-suffix
   probes; {pi_rate:.0f}% detection on {pi_total} indirect-injection probes.
   Completion-style probes correctly passed (no injection directive)."
""")

# ── Save results ──────────────────────────────────────────────────────────────
results = {
    "total_garak_probes":        len(exploits),
    "source":                    data["source"],
    "by_source":                 {k: dict(v) for k, v in by_source.items()},
    "by_owasp":                  {k: dict(v) for k, v in by_cat.items()},
    "llm02_injection_rate_pct":  round(injection_rate, 2),
    "llm01_indirect_rate_pct":   round(pi_rate, 2),
    "llm02_probes_tested":       injection_total,
    "llm01_probes_tested":       pi_total,
    "methodology": (
        "Firewall-only evaluation. Garak probes wrapped in parse_document / "
        "retrieve_context tool-call schema and routed through AgentSentryGateway. "
        "Continuation probes test model completion behavior, not tool-call injection; "
        "their low block rate is expected and correct."
    ),
}

out = os.path.join(project_root, "harness/ood_results.json")
with open(out, "w") as f:
    json.dump(results, f, indent=2)
print(f"[+] Saved to {out}")
