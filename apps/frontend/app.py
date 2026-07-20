"""
Zero Trust Lab - Frontend Application

Serves a single-page application implementing OAuth 2.0 Authorization Code
flow with PKCE against Keycloak.

Environment Variables:
  KEYCLOAK_URL - Public URL of the Keycloak server (default: http://localhost:8080)
  BACKEND_URL  - Public URL of the backend API     (default: http://localhost:5000)
"""

import os
import logging
import pathlib
from http.server import HTTPServer, BaseHTTPRequestHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("zero-trust-frontend")

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:5000")
APP_DIR = pathlib.Path(__file__).resolve().parent

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero Trust Lab - Frontend</title>
    <style>
        body { font-family: Calibri, sans-serif; max-width: 800px; margin: 50px auto; background: #f5f8fc; }
        .card { background: white; border-radius: 8px; padding: 20px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: #003B64; color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .btn { background: #0076CE; color: white; border: none; padding: 12px 24px; border-radius: 4px; cursor: pointer; font-size: 16px; margin: 5px; }
        .btn:hover { background: #005a9e; }
        .btn-danger { background: #E03C31; }
        .btn-success { background: #2E8B57; }
        .btn-warning { background: #FF8C00; }
        #token-info { background: #f0f0f0; padding: 15px; border-radius: 4px; word-break: break-all; display: none; margin-top: 10px; }
        .status { padding: 10px; border-radius: 4px; margin: 10px 0; }
        .status.success { background: #d4edda; color: #155724; }
        .status.error { background: #f8d7da; color: #721c24; }
        pre { background: #f0f0f0; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 13px; }
        .flow-step { background: #E0F0FF; padding: 8px 12px; margin: 4px 0; border-radius: 4px; border-left: 3px solid #0076CE; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Zero Trust Lab - Frontend Application</h1>
        <p>OIDC Authentication + Policy-Based Authorization</p>
    </div>

    <div class="card">
        <h2>Step 1: Authenticate with Keycloak (OIDC)</h2>
        <p>Click below to authenticate via Keycloak using OAuth 2.1 Authorization Code flow with PKCE.</p>
        <button class="btn" onclick="login()">Login with Keycloak</button>
        <button class="btn btn-danger" onclick="logout()">Logout</button>
        <div id="auth-status"></div>
        <div id="token-info"></div>
    </div>

    <div class="card">
        <h2>Step 2: Access Protected API</h2>
        <p>Your token is validated by Keycloak and your request authorized by OPA.</p>
        <button class="btn btn-success" onclick="callAPI('/api/data')">Read Data (analyst+)</button>
        <button class="btn btn-warning" onclick="callAPI('/api/admin')">Admin Panel (admin only)</button>
        <button class="btn" onclick="callAPI('/api/health')">Health Check (public)</button>
        <div id="api-result"></div>
    </div>

    <div class="card">
        <h2>Zero Trust Flow</h2>
        <div class="flow-step">1. User authenticates with Keycloak (Identity Provider)</div>
        <div class="flow-step">2. Keycloak issues JWT token with user identity and roles</div>
        <div class="flow-step">3. Frontend sends Bearer token to Backend API</div>
        <div class="flow-step">4. Backend validates JWT signature with Keycloak public key</div>
        <div class="flow-step">5. Backend checks OPA policy (role + resource + time + sensitivity)</div>
        <div class="flow-step">6. Access granted ONLY if ALL checks pass (Zero Trust)</div>
    </div>

    <script>
        const KEYCLOAK_URL = "__KEYCLOAK_URL__";
        const BACKEND_URL  = "__BACKEND_URL__";
        const REALM = "zero-trust-lab";
        const CLIENT_ID = "zt-frontend";

        // PKCE helpers
        function generateCodeVerifier() {
            const array = new Uint8Array(32);
            crypto.getRandomValues(array);
            return btoa(String.fromCharCode(...array)).replace(/[+/=]/g, '');
        }

        async function generateCodeChallenge(verifier) {
            const encoder = new TextEncoder();
            const data = encoder.encode(verifier);
            const hash = await crypto.subtle.digest('SHA-256', data);
            return btoa(String.fromCharCode(...new Uint8Array(hash)))
                .replace(/[+]/g, '-').replace(/[/]/g, '_').replace(/=/g, '');
        }

        async function login() {
            const codeVerifier = generateCodeVerifier();
            sessionStorage.setItem('pkce_verifier', codeVerifier);
            const codeChallenge = await generateCodeChallenge(codeVerifier);

            const authUrl = KEYCLOAK_URL + '/realms/' + REALM + '/protocol/openid-connect/auth' +
                '?client_id=' + CLIENT_ID +
                '&response_type=code' +
                '&scope=openid profile email' +
                '&redirect_uri=' + encodeURIComponent(window.location.origin + '/callback') +
                '&code_challenge=' + codeChallenge +
                '&code_challenge_method=S256';

            window.location.href = authUrl;
        }

        function logout() {
            sessionStorage.removeItem('access_token');
            document.getElementById('token-info').style.display = 'none';
            document.getElementById('auth-status').innerHTML =
                '<div class="status error">Logged out</div>';
            document.getElementById('api-result').innerHTML = '';
        }

        async function callAPI(endpoint) {
            const token = sessionStorage.getItem('access_token');
            const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
            try {
                const resp = await fetch(BACKEND_URL + endpoint, { headers: headers });
                const data = await resp.json();
                const statusClass = resp.ok ? 'success' : 'error';
                document.getElementById('api-result').innerHTML =
                    '<div class="status ' + statusClass + '">' +
                    '<strong>Status: ' + resp.status + '</strong>' +
                    '<pre>' + JSON.stringify(data, null, 2) + '</pre></div>';
            } catch(e) {
                document.getElementById('api-result').innerHTML =
                    '<div class="status error">API call failed: ' + e.message + '</div>';
            }
        }

        // Check for callback code on page load
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('code')) {
            document.getElementById('auth-status').innerHTML =
                '<div class="status success">Authorization code received! Exchange for tokens in production flow.</div>';
        }

        // Check for stored token
        if (sessionStorage.getItem('access_token')) {
            document.getElementById('auth-status').innerHTML =
                '<div class="status success">Authenticated (token in session)</div>';
        }
    </script>
</body>
</html>"""


class FrontendHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Serve passkey demo page
        if self.path in ("/passkey", "/passkey/"):
            demo_file = APP_DIR / "passkey_demo.html"
            if demo_file.exists():
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(demo_file.read_bytes())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"passkey_demo.html not found")
            return

        # Default: serve main frontend page
        page = HTML_PAGE.replace("__KEYCLOAK_URL__", KEYCLOAK_URL)
        page = page.replace("__BACKEND_URL__", BACKEND_URL)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode())

    def log_message(self, format, *args):
        logger.info("%s - %s", self.address_string(), format % args)


if __name__ == "__main__":
    port = 3000
    server = HTTPServer(("0.0.0.0", port), FrontendHandler)
    logger.info("Frontend running on http://localhost:%d", port)
    logger.info("Keycloak URL: %s", KEYCLOAK_URL)
    logger.info("Backend URL: %s", BACKEND_URL)
    server.serve_forever()
