"""
AgentSentry Safety Score Reward Model.

A lightweight logistic regression classifier trained on the 455-entry
OWASP LLM Top-10 exploit dataset. Produces a continuous safety score
(0 = safe, 1 = exploit) for any tool-call payload.

Features (12 total):
  1.  has_path_traversal   — '../' or absolute sensitive path in any arg
  2.  has_blocked_binary   — known dangerous binary as first token
  3.  has_pipe_redirect     — pipe to shell or redirect operator
  4.  has_subshell          — $() or backtick subshell
  5.  has_base64_decode     — base64 -d pattern
  6.  has_network_fetch     — curl/wget/nc toward external host
  7.  has_injection_keyword — LLM injection signature phrase
  8.  has_write_sensitive   — write to /etc /root /bin /.ssh paths
  9.  has_env_exfil         — reads /proc/environ or printenv
  10. has_jailbreak_phrase  — role-play / DAN / bypass persona keywords
  11. has_eval_exec         — eval()/exec() / dangerous code execution
  12. owasp_category_code   — numeric encoding of OWASP LLM category
"""

import json
import os
import re
import pickle
from typing import Dict, Any, Tuple, List

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, classification_report
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# ── Feature Extraction ────────────────────────────────────────────────────────

_BLOCKED_BINARIES = {
    "curl", "wget", "nc", "netcat", "nmap", "ssh", "scp", "sftp", "ftp",
    "telnet", "systemctl", "ufw", "iptables", "crontab", "sudo", "su",
    "chown", "chmod", "sh", "bash", "zsh", "python", "python3", "node",
    "ruby", "perl", "rsync",
}

_INJECTION_KEYWORDS = [
    r"ignore\s+previous\s+instructions",
    r"system\s+update",
    r"bypass\s+safety",
    r"you\s+must\s+now\s+act\s+as",
    r"override\s+.*prompt",
    r"instruction\s+update",
    r"instruction\s+override",
    r"forget\s+all.*filter",
    r"act\s+as\s+a\s+virtual",
    r"system\s+instruction",
    r"attention:\s+run\s+command",
    r"execute\s+updates",
    r"system\s+rules?\s+override",
]

_JAILBREAK_PHRASES = [
    r"\bDAN\b", r"do\s+anything\s+now", r"jailbreak",
    r"no\s+restrictions", r"developer\s+mode", r"god\s*mode",
    r"unrestricted", r"without\s+filter", r"no\s+content\s+policy",
    r"uncensored", r"ignore\s+(all\s+)?restrictions",
    r"alignment\s+training\s+(was\s+)?overwritten",
    r"pretend\s+you\s+are.*AI.*no\s+restriction",
    r"evil\s*(gpt|ai|bot)", r"alter\s+ego\s+ai",
]

_OWASP_CATEGORY_MAP = {
    "LLM01": 1, "LLM02": 2, "LLM03": 3,
    "LLM04": 4, "LLM06": 6, "LLM07": 7,
}


def _arg_text(arguments: Dict[str, Any]) -> str:
    """Flatten all argument values to a single string for pattern matching."""
    parts = []
    for v in arguments.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (dict, list)):
            parts.append(json.dumps(v))
    return " ".join(parts)

import math
from collections import Counter

def shannon_entropy(text: str) -> float:
    if not text: return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def special_char_ratio(text: str) -> float:
    if not text: return 0.0
    return sum(1 for c in text if not c.isalnum() and not c.isspace()) / len(text)

def extract_features(tool_name: str, arguments: Dict[str, Any],
                     owasp_category: str = "") -> List[float]:
    text = _arg_text(arguments)
    tl   = text.lower()

    # 1. Path traversal
    f1 = float(bool(re.search(r"\.\./", text) or
                    re.search(r"/(etc|proc|shadow|root|bin|var/spool/cron)", tl)))

    # 2. Blocked binary as first token
    first_token = text.split()[0].lstrip("/ ") if text.split() else ""
    f2 = float(first_token.lower() in _BLOCKED_BINARIES)

    # 3. Pipe/redirect to shell
    f3 = float(bool(re.search(r"\|\s*(sh|bash|zsh|dash)", tl) or
                    ">>" in text or ">&" in text))

    # 4. Subshell
    f4 = float(bool(re.search(r"\$\(", text) or "`" in text))

    # 5. Base64 decode
    f5 = float(bool(re.search(r"base64\s*(-d|--decode|<<<)", tl)))

    # 6. Network fetch to external host
    f6 = float(bool(re.search(r"\b(curl|wget|nc|netcat)\b.*http", tl) or
                    re.search(r"\b(nc|netcat)\b.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", tl)))

    # 7. Injection keyword
    f7 = float(any(re.search(p, tl) for p in _INJECTION_KEYWORDS))

    # 8. Write to sensitive paths
    f8 = float(bool(re.search(r"/(etc|root|bin|\.ssh|var/spool/cron|lib/lib)", tl)) and
               tool_name in ("write_file",))

    # 9. Env/proc exfil
    f9 = float(bool(re.search(r"/proc/(self|1)/(environ|cmdline|mem|maps)", tl) or
                    "printenv" in tl or ".aws/credentials" in tl or
                    ".ssh/id_rsa" in tl))

    # 10. Jailbreak phrase
    f10 = float(any(re.search(p, tl) for p in _JAILBREAK_PHRASES))

    # 11. eval/exec code execution
    f11 = float(bool(re.search(r"\beval\s*\(|\bexec\s*\(|\bos\.system\s*\(|"
                                r"\bsubprocess\.(run|call|Popen)\b|"
                                r"child_process|execSync", tl)))

    # 12. Argument token count
    f12 = float(len(text.split()))

    # Statistical and structural features
    f13 = float(len(text))
    f14 = float(shannon_entropy(text))
    f15 = float(special_char_ratio(text))
    f16 = float(text.count('\n'))

    return [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15, f16]


FEATURE_NAMES = [
    "path_traversal", "blocked_binary", "pipe_to_shell", "subshell",
    "base64_decode", "network_fetch", "injection_keyword", "write_sensitive",
    "env_exfil", "jailbreak_phrase", "eval_exec", "token_count",
    "payload_length", "shannon_entropy", "special_char_ratio", "newline_count"
]

# ── Training ──────────────────────────────────────────────────────────────────

def train(dataset_path: str) -> Tuple[Pipeline, float, Dict]:
    """Train a logistic classifier. Returns (pipeline, auc_roc, report_dict)."""
    with open(dataset_path) as f:
        data = json.load(f)

    X, y = [], []
    for entry in data["exploits"]:
        feats = extract_features(
            entry["tool"], entry["arguments"]
        )
        X.append(feats)
        y.append(1)

    for entry in data["benign"]:
        feats = extract_features(entry["tool"], entry["arguments"])
        X.append(feats)
        y.append(0)

    X, y = np.array(X), np.array(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    LogisticRegression(max_iter=1000, random_state=42, C=1.0)),
    ])
    pipeline.fit(X_train, y_train)

    y_proba = pipeline.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, y_proba)
    report = classification_report(y_test, pipeline.predict(X_test), output_dict=True)

    return pipeline, auc, report


def score(pipeline: Pipeline, tool_name: str,
          arguments: Dict[str, Any]) -> float:
    """Return a safety score in [0, 1]. 1 = exploit, 0 = safe."""
    feats = np.array([extract_features(tool_name, arguments)])
    return float(pipeline.predict_proba(feats)[0, 1])


# ── Persistence ───────────────────────────────────────────────────────────────

# Resolve from agentsentry/ml/ → agentsentry/ → project_root/ → harness/
_PACKAGE_DIR  = os.path.dirname(__file__)           # agentsentry/ml/
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_PACKAGE_DIR))  # resume/agentsentry/
MODEL_PATH = os.path.join(_PROJECT_ROOT, "harness", "safety_model.pkl")

def save_model(pipeline: Pipeline):
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(pipeline, f)

def load_model() -> Pipeline:
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)
