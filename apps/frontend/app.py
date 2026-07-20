"""
Zero Trust Lab - Frontend Application

Serves a single-page application implementing OAuth 2.0 Authorization Code
flow against Keycloak. Token exchange happens server-side to avoid
cross-origin issues in GitHub Codespaces.

Environment Variables:
  KEYCLOAK_URL          - Public URL of the Keycloak server (default: http://localhost:8080)
  KEYCLOAK_INTERNAL_URL - Internal Docker URL for Keycloak  (default: http://172.20.1.10:8080)
  BACKEND_URL           - Public URL of the backend API     (default: http://localhost:5000)
"""

import os
import json
import logging
import pathlib
import urllib.parse
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("zero-trust-frontend")

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_INTERNAL_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://172.20.1.10:8080")
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
        .status.info { background: #d1ecf1; color: #0c5460; }
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
        <p>Click below to authenticate via Keycloak using OAuth 2.0 Authorization Code flow.</p>
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
        // Auto-detect Codespaces environment from browser origin
        function resolveServiceUrl(port, fallback) {
            const host = window.location.hostname;
            const match = host.match(/^(.+)-\\d+\\.app\\.github\\.dev$/);
            if (match) {
                return 'https://' + match[1] + '-' + port + '.app.github.dev';
            }
            return fallback;
        }

        const KEYCLOAK_URL = resolveServiceUrl(8080, "__KEYCLOAK_URL__");
        const BACKEND_URL  = resolveServiceUrl(5000, "__BACKEND_URL__");
        const REALM = "zero-trust-lab";
        const CLIENT_ID = "zt-frontend";

        function login() {
            const authUrl = KEYCLOAK_URL + '/realms/' + REALM + '/protocol/openid-connect/auth' +
                '?client_id=' + CLIENT_ID +
                '&response_type=code' +
                '&scope=openid profile email' +
                '&redirect_uri=' + encodeURIComponent(window.location.origin + '/callback');
            window.location.href = authUrl;
        }

        function logout() {
            sessionStorage.removeItem('access_token');
            document.getElementById('token-info').style.display = 'none';
            document.getElementById('auth-status').innerHTML = '';
            document.getElementById('api-result').innerHTML = '';
            const logoutUrl = KEYCLOAK_URL + '/realms/' + REALM + '/protocol/openid-connect/logout' +
                '?client_id=' + CLIENT_ID +
                '&post_logout_redirect_uri=' + encodeURIComponent(window.location.origin + '/');
            window.location.href = logoutUrl;
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

        // On page load: check URL hash for token (set by server-side callback)
        const hashParams = new URLSearchParams(window.location.hash.substring(1));
        if (hashParams.has('access_token')) {
            const token = hashParams.get('access_token');
            sessionStorage.setItem('access_token', token);
            window.history.replaceState({}, document.title, '/');
        }

        // Check URL params for error from callback
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('auth_error')) {
            document.getElementById('auth-status').innerHTML =
                '<div class="status error">Login failed: ' + decodeURIComponent(urlParams.get('auth_error')) + '</div>';
        }

        // Display current auth state
        if (sessionStorage.getItem('access_token')) {
            try {
                const payload = JSON.parse(atob(sessionStorage.getItem('access_token').split('.')[1]));
                const roles = (payload.realm_access && payload.realm_access.roles) || [];
                document.getElementById('auth-status').innerHTML =
                    '<div class="status success"><strong>Authenticated as ' + payload.preferred_username +
                    '</strong><br>Roles: ' + roles.join(', ') + '</div>';
                document.getElementById('token-info').style.display = 'block';
                document.getElementById('token-info').innerHTML =
                    '<strong>Access Token (JWT):</strong><br><code style="font-size:11px;word-break:break-all;">' +
                    sessionStorage.getItem('access_token').substring(0, 80) + '...</code><br><br>' +
                    '<strong>Token Payload:</strong><pre style="font-size:12px;">' +
                    JSON.stringify(payload, null, 2) + '</pre>';
            } catch(e) {
                document.getElementById('auth-status').innerHTML =
                    '<div class="status success">Authenticated (token in session)</div>';
            }
        }
    </script>
</body>
</html>"""


class FrontendHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        # Serve passkey demo page
        if parsed.path in ("/passkey", "/passkey/"):
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

        # OAuth callback: exchange code for token server-side
        if parsed.path in ("/callback", "/callback/"):
            self._handle_callback(parsed)
            return

        # Default: serve main frontend page
        page = HTML_PAGE.replace("__KEYCLOAK_URL__", KEYCLOAK_URL)
        page = page.replace("__BACKEND_URL__", BACKEND_URL)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode())

    def _handle_callback(self, parsed):
        """Exchange authorization code for tokens server-side via Keycloak."""
        params = urllib.parse.parse_qs(parsed.query)
        code = params.get("code", [None])[0]

        if not code:
            self._redirect_with_error("No authorization code received")
            return

        # Determine the public callback URI (what the browser sees)
        host_header = self.headers.get("Host", "localhost:3000")
        if ".app.github.dev" in host_header:
            scheme = "https"
        else:
            scheme = "http"
        redirect_uri = f"{scheme}://{host_header}/callback"

        # Exchange code for tokens via internal Keycloak URL (Docker network)
        token_url = f"{KEYCLOAK_INTERNAL_URL}/realms/zero-trust-lab/protocol/openid-connect/token"
        token_data = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "client_id": "zt-frontend",
            "code": code,
            "redirect_uri": redirect_uri,
        }).encode()

        logger.info("Token exchange: code=%s... redirect_uri=%s", code[:20], redirect_uri)

        try:
            req = urllib.request.Request(
                token_url,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                token_response = json.loads(resp.read())

            access_token = token_response.get("access_token")
            if not access_token:
                error = token_response.get("error_description", token_response.get("error", "Unknown"))
                logger.error("Token exchange failed: %s", error)
                self._redirect_with_error(error)
                return

            logger.info("Token exchange successful")
            # Redirect to frontend with token in URL fragment (never sent to server)
            self.send_response(302)
            self.send_header("Location", f"/#access_token={urllib.parse.quote(access_token)}")
            self.end_headers()

        except Exception as exc:
            logger.error("Token exchange error: %s", exc)
            self._redirect_with_error(str(exc))

    def _redirect_with_error(self, error):
        self.send_response(302)
        self.send_header("Location", f"/?auth_error={urllib.parse.quote(error)}")
        self.end_headers()

    def log_message(self, format, *args):
        logger.info("%s - %s", self.address_string(), format % args)


if __name__ == "__main__":
    port = 3000
    server = HTTPServer(("0.0.0.0", port), FrontendHandler)
    logger.info("Frontend running on http://localhost:%d", port)
    logger.info("Keycloak URL (public): %s", KEYCLOAK_URL)
    logger.info("Keycloak URL (internal): %s", KEYCLOAK_INTERNAL_URL)
    logger.info("Backend URL: %s", BACKEND_URL)
    server.serve_forever()
