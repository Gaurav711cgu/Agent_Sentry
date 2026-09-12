"""
AgentSentry & GitLabSentry: Webhook HMAC-SHA256 Authentication Middleware.
Eliminates unsigned webhook vector — validates every inbound payload before
processing. Follows the GitHub/Stripe production webhook verification pattern.
"""
import hmac
import hashlib
import logging
from functools import wraps
from flask import request, abort

logger = logging.getLogger(__name__)

WEBHOOK_SECRET_ENV = "WEBHOOK_SECRET"


def _get_secret(secret: str | None) -> bytes:
    import os
    raw = secret or os.environ.get(WEBHOOK_SECRET_ENV, "")
    if not raw:
        raise RuntimeError(f"Webhook secret not configured. Set {WEBHOOK_SECRET_ENV} env var.")
    return raw.encode("utf-8")


def verify_github_signature(payload_body: bytes, signature_header: str, secret: str | None = None) -> bool:
    """
    Validates X-Hub-Signature-256 header from GitHub/GitLab webhooks.
    Uses constant-time comparison to prevent timing attacks.
    """
    if not signature_header or not signature_header.startswith("sha256="):
        logger.warning("Missing or malformed webhook signature header.")
        return False

    secret_key = _get_secret(secret)
    expected = hmac.new(secret_key, payload_body, hashlib.sha256).hexdigest()
    received = signature_header[len("sha256="):]

    if not hmac.compare_digest(expected, received):
        logger.error("Webhook HMAC signature mismatch. Potential spoofed request.")
        return False

    return True


def require_webhook_auth(secret: str | None = None):
    """
    Flask decorator to enforce HMAC-SHA256 authentication on all webhook endpoints.
    Usage:
        @app.route('/webhook', methods=['POST'])
        @require_webhook_auth()
        def handle_webhook():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            sig = request.headers.get("X-Hub-Signature-256") or \
                  request.headers.get("X-Gitlab-Token")

            payload = request.get_data()

            if not verify_github_signature(payload, sig or "", secret):
                logger.critical("Webhook auth failed. Aborting with 403.")
                abort(403, "Webhook signature verification failed.")

            return f(*args, **kwargs)
        return decorated
    return decorator
