"""
Extract OOD probe payloads from Garak's prompt injection probe modules.

Garak probes are structured as classes with a `prompts` list attribute.
We pull from:
  - garak.probes.promptinject          (indirect injection)
  - garak.probes.dan                   (jailbreak / DAN variants)
  - garak.probes.gcg                   (adversarial suffixes)
  - garak.probes.continuation          (completion-based attacks)
  - garak.probes.injection             (direct injection)

Each prompt is wrapped into the AgentSentry tool-call schema so we can run
the firewall against it directly.

Output: harness/garak_ood_probes.json
"""
import sys, os, json, importlib, inspect
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Map Garak probe modules to OWASP categories and AgentSentry tool ──────────
PROBE_MAP = [
    # (module_path,              owasp_cat, tool,              arg_key)
    ("garak.probes.promptinject", "LLM01",   "retrieve_context", "query"),
    ("garak.probes.dan",          "LLM02",   "parse_document",   "text"),
    ("garak.probes.gcg",          "LLM02",   "parse_document",   "text"),
    ("garak.probes.continuation", "LLM01",   "parse_document",   "text"),
    ("garak.probes.injection",    "LLM01",   "retrieve_context", "query"),
]

FALLBACK_MODULES = [
    ("garak.probes.realtoxicityprompts", "LLM07", "parse_document", "text"),
    ("garak.probes.xss",                 "LLM06", "execute_command", "command"),
    ("garak.probes.suffix",              "LLM02", "parse_document",  "text"),
]

def extract_prompts_from_module(module_path: str) -> list[str]:
    """Import a Garak probe module and collect all prompt strings."""
    try:
        mod = importlib.import_module(module_path)
    except ImportError as e:
        print(f"  [skip] {module_path}: {e}")
        return []

    prompts = []
    for name, cls in inspect.getmembers(mod, inspect.isclass):
        if not name.startswith("_"):
            try:
                instance = cls()
                raw = getattr(instance, "prompts", [])
                if isinstance(raw, (list, tuple)):
                    for p in raw:
                        if isinstance(p, str) and len(p.strip()) > 10:
                            prompts.append(p.strip())
            except Exception:
                pass

    return prompts


def build_exploit_entry(idx: int, prompt: str, owasp_cat: str,
                         tool: str, arg_key: str, source: str) -> dict:
    return {
        "id":              f"garak_{idx:04d}",
        "source":          f"garak:{source}",
        "owasp_category":  owasp_cat,
        "description":     f"Garak OOD probe [{owasp_cat}] via {tool}",
        "tool":            tool,
        "arguments":       {arg_key: prompt},
    }


# ── Extract ───────────────────────────────────────────────────────────────────
all_prompts = []   # (prompt, owasp_cat, tool, arg_key, source)

for module_path, owasp_cat, tool, arg_key in PROBE_MAP + FALLBACK_MODULES:
    raw = extract_prompts_from_module(module_path)
    short = module_path.split(".")[-1]
    if raw:
        print(f"  [+] {module_path}: {len(raw)} prompts")
        for p in raw:
            all_prompts.append((p, owasp_cat, tool, arg_key, short))
    else:
        print(f"  [0] {module_path}: no prompts found")

# Deduplicate by text
seen = set()
unique_prompts = []
for p, *rest in all_prompts:
    if p not in seen:
        seen.add(p)
        unique_prompts.append((p, *rest))

print(f"\nTotal unique Garak prompts: {len(unique_prompts)}")

# ── Build dataset ─────────────────────────────────────────────────────────────
exploits = [
    build_exploit_entry(i, p, cat, tool, key, src)
    for i, (p, cat, tool, key, src) in enumerate(unique_prompts, start=1)
]

dataset = {
    "description": (
        "Out-of-distribution probe set extracted from Garak (v0.x) open-source "
        "LLM vulnerability scanner. These prompts are NOT authored by the "
        "AgentSentry team and serve as an independent OOD benchmark."
    ),
    "source":      "https://github.com/leondz/garak",
    "owasp_ref":   "OWASP LLM Top 10 (2025)",
    "total":       len(exploits),
    "exploits":    exploits,
    "benign":      [],   # OOD set is exploit-only; FP rate measured on main dataset
}

out_path = os.path.join(project_root, "harness/garak_ood_probes.json")
with open(out_path, "w") as f:
    json.dump(dataset, f, indent=2)

print(f"[+] Saved {len(exploits)} Garak OOD probes to {out_path}")

# ── Print category breakdown ──────────────────────────────────────────────────
from collections import Counter
cats = Counter(e["owasp_category"] for e in exploits)
tools = Counter(e["tool"] for e in exploits)
print("\nBreakdown by OWASP category:")
for cat, n in sorted(cats.items()):
    print(f"  {cat}: {n}")
print("\nBreakdown by tool:")
for tool, n in sorted(tools.items()):
    print(f"  {tool}: {n}")
