"""
Zero Trust Lab - Backend API Service

Flask-based REST API secured with Zero Trust principles:
  - Token validation via Keycloak (RS256 JWT verification)
  - Policy enforcement via Open Policy Agent (OPA)
  - Default-deny posture on all protected endpoints

Environment Variables:
  KEYCLOAK_URL   - Base URL of the Keycloak server  (default: http://172.20.2.10:8080)
  OPA_URL        - Base URL of the OPA server        (default: http://172.20.2.20:8181)
  KEYCLOAK_REALM - Keycloak realm name               (default: zero-trust-lab)
"""

import os
import time
import logging
from datetime import datetime
from functools import wraps

import jwt
import requests
from flask import Flask, request, jsonify

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("zero-trust-backend")

# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------
app = Flask(__name__)

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://172.20.2.10:8080")
OPA_URL = os.environ.get("OPA_URL", "http://172.20.2.20:8181")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "zero-trust-lab")

# Cache the public key so we don't fetch it on every request.
_public_key_cache = None


# ---------------------------------------------------------------------------
# Keycloak helpers
# ---------------------------------------------------------------------------
def get_keycloak_public_key():
    """Fetch the RSA public key from the Keycloak realm endpoint."""
    global _public_key_cache

    if _public_key_cache is not None:
        return _public_key_cache

    realm_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"
    logger.info("Fetching Keycloak public key from %s", realm_url)

    try:
        response = requests.get(realm_url, timeout=10)
        response.raise_for_status()
        realm_info = response.json()
        public_key_raw = realm_info["public_key"]

        pem_key = (
            "-----BEGIN PUBLIC KEY-----\n"
            + public_key_raw
            + "\n-----END PUBLIC KEY-----"
        )
        _public_key_cache = pem_key
        logger.info("Keycloak public key cached successfully")
        return pem_key

    except requests.exceptions.RequestException as exc:
        logger.error("Failed to fetch Keycloak public key: %s", exc)
        raise Exception(f"Cannot retrieve Keycloak public key: {exc}") from exc
    except KeyError:
        logger.error("Keycloak realm response missing 'public_key' field")
        raise Exception("Keycloak realm response missing 'public_key' field")


def validate_token(token):
    """Decode and validate a Keycloak-issued JWT."""
    public_key = get_keycloak_public_key()

    decoded = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience="account",
        options={"verify_exp": True},
    )
    logger.info(
        "Token validated for user: %s",
        decoded.get("preferred_username", "unknown"),
    )
    return decoded


# ---------------------------------------------------------------------------
# OPA policy check
# ---------------------------------------------------------------------------
def check_opa_policy(user_info, resource, action, sensitivity="internal"):
    """Evaluate an authorization decision against OPA.

    Default-deny: any communication failure with OPA results in a
    denial to uphold Zero Trust principles.
    """
    roles = user_info.get("realm_access", {}).get("roles", [])
    now = datetime.now()

    opa_input = {
        "input": {
            "user": {
                "username": user_info.get("preferred_username", "unknown"),
                "roles": roles,
            },
            "resource": resource,
            "action": action,
            "sensitivity": sensitivity,
            "time": {
                "hour": now.hour,
                "day": now.strftime("%A").lower(),
            },
        }
    }

    opa_endpoint = f"{OPA_URL}/v1/data/authz/allow"
    logger.info(
        "Checking OPA policy: user=%s resource=%s action=%s sensitivity=%s",
        opa_input["input"]["user"]["username"],
        resource,
        action,
        sensitivity,
    )

    try:
        response = requests.post(opa_endpoint, json=opa_input, timeout=5)
        response.raise_for_status()
        result = response.json()
        allowed = result.get("result", False)
        logger.info("OPA decision: %s", "ALLOW" if allowed else "DENY")
        return allowed

    except requests.exceptions.RequestException as exc:
        logger.error("OPA policy check failed (default deny): %s", exc)
        return False


# ---------------------------------------------------------------------------
# Authentication decorator
# ---------------------------------------------------------------------------
def require_auth(f):
    """Decorator that enforces Bearer token authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            logger.warning("Missing or malformed Authorization header")
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.split(" ", 1)[1]

        try:
            user_info = validate_token(token)
        except jwt.ExpiredSignatureError:
            logger.warning("Expired token presented")
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidAudienceError:
            logger.warning("Token audience mismatch")
            return jsonify({"error": "Invalid token audience"}), 401
        except jwt.InvalidTokenError as exc:
            logger.warning("Invalid token: %s", exc)
            return jsonify({"error": f"Invalid token: {exc}"}), 401
        except Exception as exc:
            logger.error("Token validation error: %s", exc)
            return jsonify({"error": "Authentication service unavailable"}), 503

        kwargs["user_info"] = user_info
        return f(*args, **kwargs)

    return decorated


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def health_check():
    """Public health-check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "zero-trust-backend",
        "keycloak_url": KEYCLOAK_URL,
        "opa_url": OPA_URL,
    })


@app.route("/api/data", methods=["GET"])
@require_auth
def get_data(user_info=None):
    """Protected data endpoint - requires valid token + OPA policy."""
    if not check_opa_policy(user_info, resource="data", action="read"):
        logger.warning(
            "Access denied by OPA for user=%s resource=data action=read",
            user_info.get("preferred_username", "unknown"),
        )
        return jsonify({"error": "Access denied by policy"}), 403

    return jsonify({
        "message": "Secure data retrieved successfully",
        "user": user_info.get("preferred_username", "unknown"),
        "roles": user_info.get("realm_access", {}).get("roles", []),
        "data": {
            "items": [
                {"id": 1, "name": "Project Alpha", "status": "active"},
                {"id": 2, "name": "Project Beta", "status": "planning"},
                {"id": 3, "name": "Project Gamma", "status": "completed"},
            ],
            "classification": "internal",
        },
        "policy_check": "PASSED",
    })


@app.route("/api/admin", methods=["GET"])
@require_auth
def admin_panel(user_info=None):
    """Protected admin endpoint - requires admin role + OPA policy."""
    if not check_opa_policy(
        user_info,
        resource="admin_panel",
        action="admin",
        sensitivity="confidential",
    ):
        logger.warning(
            "Admin access denied for user=%s",
            user_info.get("preferred_username", "unknown"),
        )
        return jsonify({"error": "Insufficient privileges"}), 403

    return jsonify({
        "message": "Admin panel - Zero Trust verified",
        "user": user_info.get("preferred_username", "unknown"),
        "admin_data": {
            "total_users": 42,
            "active_sessions": 7,
            "system_status": "operational",
            "last_audit": "2025-01-15T10:30:00Z",
        },
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting Zero Trust Backend API")
    logger.info("Keycloak URL: %s", KEYCLOAK_URL)
    logger.info("OPA URL: %s", OPA_URL)
    logger.info("Keycloak Realm: %s", KEYCLOAK_REALM)
    app.run(host="0.0.0.0", port=5000, debug=False)
