"""
Zero Trust Lab - Deliberately Vulnerable Application

!! WARNING: This application is INTENTIONALLY INSECURE. !!
!! It exists solely for educational and testing purposes. !!
!! NEVER deploy this in production. !!

Vulnerabilities:
  1. Information Disclosure - root endpoint lists all routes
  2. Broken Access Control / IDOR - any authenticated user can access admin
  3. SSRF Simulation - /api/search accepts arbitrary URLs
  4. Environment Variable Exposure - /debug/env leaks process environment
  5. Command Injection Simulation - /api/ping passes user input unsanitized

All vulnerability triggers are logged with [security] prefixes for SIEM detection.
Port: 8888
"""

import os
import json
import logging
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [security] %(message)s",
)
logger = logging.getLogger("vulnerable-app")

# ---------------------------------------------------------------------------
# Simulated sensitive data
# ---------------------------------------------------------------------------
SENSITIVE_DATA = {
    "employees": [
        {"name": "Alice Admin", "ssn": "***-**-1234", "salary": "$150,000"},
        {"name": "Bob Analyst", "ssn": "***-**-5678", "salary": "$95,000"},
    ],
    "api_keys": {
        "production": "sk-REDACTED-prod-key-do-not-expose",
        "staging": "sk-REDACTED-staging-key",
    },
    "database_credentials": {
        "host": "internal-db.company.local",
        "username": "db_admin",
        "password": "REDACTED-password-123",
    },
}

# Deliberately weak token auth
VALID_TOKENS = {
    "admin-token-12345": {"role": "admin", "user": "alice"},
    "user-token-67890": {"role": "user", "user": "bob"},
}


class VulnerableHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # VULNERABILITY 1: Information Disclosure
        if path == "/":
            self.send_json(200, {
                "app": "Vulnerable Demo App",
                "version": "1.0.0",
                "endpoints": ["/api/data", "/api/admin", "/api/health",
                              "/api/search", "/debug/env"],
                "auth": "Send token in Authorization header",
            })

        elif path == "/api/health":
            self.send_json(200, {"status": "healthy", "uptime": "24h"})

        # VULNERABILITY 2: Broken Authentication
        elif path == "/api/data":
            token = self.headers.get("Authorization", "").replace("Bearer ", "")
            if token in VALID_TOKENS:
                user_info = VALID_TOKENS[token]
                logger.info("Data access by %s (role: %s)", user_info["user"], user_info["role"])
                self.send_json(200, {
                    "message": "Authorized access",
                    "user": user_info,
                    "data": SENSITIVE_DATA["employees"],
                })
            else:
                logger.warning("Unauthorized access attempt to /api/data from %s", self.client_address[0])
                self.send_json(401, {"error": "Unauthorized"})

        # VULNERABILITY 3: Broken Access Control (IDOR)
        elif path == "/api/admin":
            token = self.headers.get("Authorization", "").replace("Bearer ", "")
            if token in VALID_TOKENS:
                user_info = VALID_TOKENS[token]
                # BUG: No role check! Any valid token gets admin access
                logger.warning("Admin endpoint accessed by %s (role: %s)", user_info["user"], user_info["role"])
                self.send_json(200, {
                    "message": "Admin panel",
                    "sensitive": SENSITIVE_DATA,
                })
            else:
                self.send_json(401, {"error": "Unauthorized"})

        # VULNERABILITY 4: Server-Side Request Forgery (SSRF)
        elif path == "/api/search":
            url = params.get("url", [None])[0]
            if url:
                logger.warning("SSRF attempt: URL requested: %s from %s", url, self.client_address[0])
                self.send_json(200, {
                    "message": f"Would fetch: {url}",
                    "note": "SSRF vulnerability - in real app, this would fetch the URL",
                })
            else:
                self.send_json(400, {"error": "Missing url parameter"})

        # VULNERABILITY 5: Debug Endpoint Exposed
        elif path == "/debug/env":
            logger.critical("Debug endpoint accessed from %s - potential recon", self.client_address[0])
            self.send_json(200, {
                "environment": dict(os.environ),
                "warning": "DEBUG ENDPOINT - SHOULD NOT BE IN PRODUCTION",
            })

        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"

        # VULNERABILITY 6: Command Injection (Simulated)
        if path == "/api/ping":
            try:
                data = json.loads(body)
                host = data.get("host", "")
                logger.critical("Command injection attempt: ping %s from %s", host, self.client_address[0])
                self.send_json(200, {
                    "message": f"Simulated ping to: {host}",
                    "warning": "Command injection vulnerability - input not sanitized",
                    "what_would_happen": f"subprocess.run('ping -c 1 {host}', shell=True)",
                })
            except json.JSONDecodeError:
                self.send_json(400, {"error": "Invalid JSON"})
        else:
            self.send_json(404, {"error": "Not found"})

    def send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def log_message(self, format, *args):
        logger.info("%s - %s", self.client_address[0], args[0] if args else "")


if __name__ == "__main__":
    port = 8888
    server = HTTPServer(("0.0.0.0", port), VulnerableHandler)
    logger.info("Vulnerable app starting on port %d", port)
    logger.warning("This app is INTENTIONALLY VULNERABLE - for lab use only!")
    server.serve_forever()
