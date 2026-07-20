"""
Zero Trust Lab - Lightweight SIEM Dashboard

A memory-efficient alternative to Wazuh for cloud-based lab environments.
Provides the same learning experience (log collection, alerting, rule matching)
using ~50 MB RAM instead of Wazuh's ~3 GB.

Features:
  - Collects logs from all lab containers via Docker API
  - Applies custom detection rules (same MITRE ATT&CK mapping as Wazuh rules)
  - Web dashboard for viewing alerts and security events
  - Syslog receiver on UDP 514 for simulated events
  - REST API for querying alerts programmatically

Port: 5601 (matches Wazuh Dashboard port for consistency)
"""

import os
import re
import json
import time
import logging
import threading
import socketserver
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from collections import deque

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("siem-lite")

# ---------------------------------------------------------------------------
# In-memory storage (lightweight - no Elasticsearch needed)
# ---------------------------------------------------------------------------
MAX_EVENTS = 5000
MAX_ALERTS = 1000

events = deque(maxlen=MAX_EVENTS)
alerts = deque(maxlen=MAX_ALERTS)
stats = {
    "total_events": 0,
    "total_alerts": 0,
    "events_by_level": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    "alerts_by_technique": {},
    "start_time": datetime.now(timezone.utc).isoformat(),
}
lock = threading.Lock()

# ---------------------------------------------------------------------------
# Detection rules (same as Wazuh custom_zt_rules.xml, simplified)
# ---------------------------------------------------------------------------
DETECTION_RULES = [
    {
        "id": "100001",
        "name": "Brute Force Attack",
        "level": "high",
        "pattern": r"(?i)(failed\s+password|authentication.*fail|login.*error|LOGIN_ERROR|invalid.*credential|wrong.*password)",
        "mitre": "T1110",
        "mitre_name": "Brute Force",
        "description": "Multiple authentication failures detected",
        "group": "authentication",
    },
    {
        "id": "100002",
        "name": "Credential Compromise",
        "level": "critical",
        "pattern": r"(?i)(credential.*compromise|multiple.*source.*ip|impossible.*travel)",
        "mitre": "T1078",
        "mitre_name": "Valid Accounts",
        "description": "Possible credential compromise - multiple source IPs",
        "group": "authentication",
    },
    {
        "id": "100003",
        "name": "Post-Brute-Force Login",
        "level": "high",
        "pattern": r"(?i)(successful.*login.*after|authenticated.*after.*fail|access_token)",
        "mitre": "T1110",
        "mitre_name": "Brute Force",
        "description": "Successful login after multiple failures",
        "group": "authentication",
    },
    {
        "id": "100010",
        "name": "Privilege Escalation",
        "level": "high",
        "pattern": r"(?i)(sudo|su\s+root|privilege.*escalat|NOT\s+in\s+sudoers)",
        "mitre": "T1548",
        "mitre_name": "Abuse Elevation Control",
        "description": "Privilege escalation attempt detected",
        "group": "privilege_escalation",
    },
    {
        "id": "100011",
        "name": "Suspicious Account Creation",
        "level": "critical",
        "pattern": r"(?i)(useradd|adduser|new\s+user.*created|net\s+user\s+/add|backdoor)",
        "mitre": "T1136",
        "mitre_name": "Create Account",
        "description": "New user account created - possible persistence",
        "group": "persistence",
    },
    {
        "id": "100020",
        "name": "Lateral Movement",
        "level": "high",
        "pattern": r"(?i)(lateral.*movement|psexec|ssh.*from.*internal|rdp.*pivot)",
        "mitre": "T1021",
        "mitre_name": "Remote Services",
        "description": "Potential lateral movement detected",
        "group": "lateral_movement",
    },
    {
        "id": "100021",
        "name": "Network Reconnaissance",
        "level": "medium",
        "pattern": r"(?i)(nmap|masscan|port\s+scan|SYN\s+scan|network.*scan)",
        "mitre": "T1046",
        "mitre_name": "Network Service Discovery",
        "description": "Network reconnaissance or port scanning detected",
        "group": "reconnaissance",
    },
    {
        "id": "100030",
        "name": "Data Exfiltration",
        "level": "critical",
        "pattern": r"(?i)(exfil|data.*transfer.*external|curl.*pastebin|upload.*external)",
        "mitre": "T1048",
        "mitre_name": "Exfiltration Over Alternative Protocol",
        "description": "Possible data exfiltration attempt",
        "group": "data_exfiltration",
    },
    {
        "id": "100040",
        "name": "API Abuse",
        "level": "medium",
        "pattern": r"(?i)(rate.*limit|too.*many.*request|api.*abuse|flood|rapid.*request)",
        "mitre": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "API rate limit exceeded - possible abuse",
        "group": "api_abuse",
    },
    {
        "id": "100050",
        "name": "SSRF Attempt",
        "level": "high",
        "pattern": r"(?i)(ssrf|169\.254\.169\.254|metadata.*service|internal.*url.*request|server.*side.*request)",
        "mitre": "T1190",
        "mitre_name": "Server-Side Request Forgery",
        "description": "Server-side request forgery attempt",
        "group": "web_attack",
    },
    {
        "id": "100051",
        "name": "Command Injection",
        "level": "critical",
        "pattern": r"(?i)(command.*inject|;.*cat\s+/etc|;\s*id\s*$|\|.*whoami|shell.*inject|unsanitized)",
        "mitre": "T1059",
        "mitre_name": "Command and Scripting Interpreter",
        "description": "Command injection attempt detected",
        "group": "web_attack",
    },
    {
        "id": "100052",
        "name": "Debug Endpoint Access",
        "level": "high",
        "pattern": r"(?i)(debug.*endpoint|/debug/|\.env\s+accessed|environment.*variable.*expos|potential.*recon)",
        "mitre": "T1082",
        "mitre_name": "System Information Discovery",
        "description": "Debug or diagnostic endpoint accessed",
        "group": "reconnaissance",
    },
    {
        "id": "100053",
        "name": "IDOR / Broken Access Control",
        "level": "high",
        "pattern": r"(?i)(admin.*endpoint.*accessed.*by.*user|idor|insecure.*direct|broken.*access.*control|unauthorized.*admin)",
        "mitre": "T1548",
        "mitre_name": "Abuse Elevation Control",
        "description": "Insecure Direct Object Reference or broken access control",
        "group": "access_control",
    },
    {
        "id": "100060",
        "name": "OPA Policy Denial",
        "level": "medium",
        "pattern": r"(?i)(policy.*denied|opa.*denied|authorization.*failed|access.*denied.*policy|deny_reasons)",
        "mitre": "T1078",
        "mitre_name": "Valid Accounts",
        "description": "OPA policy engine denied access request",
        "group": "policy",
    },
]


def analyze_log(source, message):
    """Run detection rules against a log message and generate alerts."""
    timestamp = datetime.now(timezone.utc).isoformat()

    event = {
        "timestamp": timestamp,
        "source": source,
        "message": message[:500],
    }

    with lock:
        events.append(event)
        stats["total_events"] += 1

    for rule in DETECTION_RULES:
        if re.search(rule["pattern"], message):
            alert = {
                "timestamp": timestamp,
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "level": rule["level"],
                "mitre_id": rule["mitre"],
                "mitre_name": rule["mitre_name"],
                "description": rule["description"],
                "group": rule["group"],
                "source": source,
                "log_excerpt": message[:300],
            }
            with lock:
                alerts.append(alert)
                stats["total_alerts"] += 1
                stats["events_by_level"][rule["level"]] = stats["events_by_level"].get(rule["level"], 0) + 1
                stats["alerts_by_technique"][rule["mitre"]] = stats["alerts_by_technique"].get(rule["mitre"], 0) + 1
            logger.info("ALERT [%s] %s: %s (source: %s)", rule["level"].upper(), rule["id"], rule["name"], source)


# ---------------------------------------------------------------------------
# Docker log collector thread
# ---------------------------------------------------------------------------
def docker_log_collector():
    """Collect logs from lab containers via Docker API."""
    import subprocess

    containers = [
        "zt-keycloak", "zt-backend-api", "zt-frontend-app",
        "zt-vulnerable-app", "zt-opa",
    ]

    logger.info("Starting Docker log collector for containers: %s", containers)

    def follow_container(name):
        try:
            proc = subprocess.Popen(
                ["docker", "logs", "-f", "--since", "1m", name],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for line in proc.stdout:
                line = line.strip()
                if line:
                    analyze_log(name, line)
        except Exception as e:
            logger.warning("Log collector for %s stopped: %s", name, e)

    for container in containers:
        t = threading.Thread(target=follow_container, args=(container,), daemon=True)
        t.start()
        logger.info("Collecting logs from: %s", container)


# ---------------------------------------------------------------------------
# Syslog receiver (UDP 514) for simulated events
# ---------------------------------------------------------------------------
class SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].decode("utf-8", errors="replace").strip()
        if data:
            analyze_log(f"syslog/{self.client_address[0]}", data)


def start_syslog_receiver():
    try:
        server = socketserver.UDPServer(("0.0.0.0", 514), SyslogHandler)
        logger.info("Syslog receiver listening on UDP 514")
        server.serve_forever()
    except PermissionError:
        logger.warning("Cannot bind to UDP 514 (no root privileges) - syslog receiver disabled")
    except Exception as e:
        logger.warning("Syslog receiver failed: %s", e)


# ---------------------------------------------------------------------------
# Web Dashboard
# ---------------------------------------------------------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero Trust Lab - SIEM Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: Calibri, 'Segoe UI', sans-serif; background: #1a1a2e; color: #e0e0e0; }
        .header { background: linear-gradient(135deg, #16213e, #0f3460); padding: 15px 25px;
                   display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 20px; color: #00d4ff; }
        .header .stats { display: flex; gap: 20px; font-size: 13px; }
        .stat-box { background: rgba(255,255,255,0.1); padding: 8px 15px; border-radius: 5px; text-align: center; }
        .stat-num { font-size: 22px; font-weight: bold; }
        .stat-num.critical { color: #ff4757; }
        .stat-num.high { color: #ff8c00; }
        .stat-num.medium { color: #ffd700; }
        .stat-num.low { color: #2ed573; }
        .container { display: grid; grid-template-columns: 280px 1fr; gap: 0; min-height: calc(100vh - 60px); }
        .sidebar { background: #16213e; padding: 15px; border-right: 1px solid #2a2a4a; }
        .sidebar h3 { color: #00d4ff; margin-bottom: 10px; font-size: 14px; }
        .mitre-item { padding: 6px 10px; margin: 3px 0; border-radius: 4px; font-size: 12px;
                       display: flex; justify-content: space-between; background: rgba(255,255,255,0.05); }
        .mitre-item .count { background: #ff4757; color: white; padding: 1px 8px;
                             border-radius: 10px; font-size: 11px; min-width: 24px; text-align: center; }
        .main { padding: 15px; overflow-y: auto; max-height: calc(100vh - 60px); }
        .tabs { display: flex; gap: 0; margin-bottom: 15px; }
        .tab { padding: 8px 18px; cursor: pointer; background: #2a2a4a; border: none; color: #aaa;
               font-size: 13px; transition: 0.2s; }
        .tab:first-child { border-radius: 5px 0 0 5px; }
        .tab:last-child { border-radius: 0 5px 5px 0; }
        .tab.active { background: #0f3460; color: #00d4ff; font-weight: bold; }
        .alert-card { background: #16213e; border-radius: 6px; padding: 12px 15px; margin: 8px 0;
                      border-left: 4px solid #666; font-size: 13px; }
        .alert-card.critical { border-left-color: #ff4757; }
        .alert-card.high { border-left-color: #ff8c00; }
        .alert-card.medium { border-left-color: #ffd700; }
        .alert-card.low { border-left-color: #2ed573; }
        .alert-header { display: flex; justify-content: space-between; margin-bottom: 6px; }
        .alert-title { font-weight: bold; }
        .alert-level { padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
        .alert-level.critical { background: #ff4757; color: white; }
        .alert-level.high { background: #ff8c00; color: white; }
        .alert-level.medium { background: #ffd700; color: #333; }
        .alert-level.low { background: #2ed573; color: #333; }
        .alert-meta { color: #888; font-size: 11px; margin-top: 4px; }
        .alert-mitre { background: #2a2a4a; display: inline-block; padding: 2px 6px;
                       border-radius: 3px; font-size: 11px; color: #00d4ff; margin-top: 4px; }
        .log-line { font-family: 'Consolas', monospace; font-size: 11px; padding: 4px 8px;
                    border-bottom: 1px solid #2a2a4a; color: #aaa; word-break: break-all; }
        .log-line:hover { background: rgba(255,255,255,0.05); }
        .log-source { color: #00d4ff; margin-right: 8px; }
        .refresh-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .btn-refresh { background: #0076CE; color: white; border: none; padding: 6px 14px;
                       border-radius: 4px; cursor: pointer; font-size: 12px; }
        .btn-refresh:hover { background: #005a9e; }
        .empty { color: #666; text-align: center; padding: 40px; font-style: italic; }
        .rules-table { width: 100%; border-collapse: collapse; font-size: 12px; }
        .rules-table th { background: #0f3460; padding: 8px; text-align: left; color: #00d4ff; }
        .rules-table td { padding: 6px 8px; border-bottom: 1px solid #2a2a4a; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SIEM Dashboard - Zero Trust Lab</h1>
        <div class="stats" id="stats-bar">
            <div class="stat-box"><div class="stat-num" id="total-alerts">0</div>Total Alerts</div>
            <div class="stat-box"><div class="stat-num critical" id="critical-count">0</div>Critical</div>
            <div class="stat-box"><div class="stat-num high" id="high-count">0</div>High</div>
            <div class="stat-box"><div class="stat-num medium" id="medium-count">0</div>Medium</div>
            <div class="stat-box"><div class="stat-num" id="total-events">0</div>Events</div>
        </div>
    </div>
    <div class="container">
        <div class="sidebar">
            <h3>MITRE ATT&CK Techniques</h3>
            <div id="mitre-list"></div>
            <br>
            <h3>Detection Rules</h3>
            <div id="rules-summary"></div>
        </div>
        <div class="main">
            <div class="tabs">
                <button class="tab active" onclick="switchTab('alerts')">Security Alerts</button>
                <button class="tab" onclick="switchTab('events')">Raw Events</button>
                <button class="tab" onclick="switchTab('rules')">Detection Rules</button>
            </div>
            <div class="refresh-bar">
                <span id="last-refresh" style="font-size:12px;color:#666;">Loading...</span>
                <div>
                    <label style="font-size:12px;color:#888;"><input type="checkbox" id="auto-refresh" checked> Auto-refresh (5s)</label>
                    <button class="btn-refresh" onclick="refresh()">Refresh Now</button>
                </div>
            </div>
            <div id="tab-alerts"></div>
            <div id="tab-events" style="display:none;"></div>
            <div id="tab-rules" style="display:none;"></div>
        </div>
    </div>
    <script>
        function switchTab(name) {
            document.querySelectorAll('.main > div[id^="tab-"]').forEach(d => d.style.display = 'none');
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById('tab-' + name).style.display = 'block';
            event.target.classList.add('active');
        }

        async function refresh() {
            try {
                const [alertsRes, eventsRes, statsRes, rulesRes] = await Promise.all([
                    fetch('/api/alerts?limit=50'), fetch('/api/events?limit=100'),
                    fetch('/api/stats'), fetch('/api/rules')
                ]);
                const alertsData = await alertsRes.json();
                const eventsData = await eventsRes.json();
                const statsData = await statsRes.json();
                const rulesData = await rulesRes.json();

                // Update stats bar
                document.getElementById('total-alerts').textContent = statsData.total_alerts;
                document.getElementById('total-events').textContent = statsData.total_events;
                document.getElementById('critical-count').textContent = statsData.events_by_level.critical || 0;
                document.getElementById('high-count').textContent = statsData.events_by_level.high || 0;
                document.getElementById('medium-count').textContent = statsData.events_by_level.medium || 0;

                // Update MITRE sidebar
                const mitreHtml = Object.entries(statsData.alerts_by_technique || {})
                    .sort((a,b) => b[1] - a[1])
                    .map(([id, count]) => `<div class="mitre-item"><span>${id}</span><span class="count">${count}</span></div>`)
                    .join('');
                document.getElementById('mitre-list').innerHTML = mitreHtml || '<div style="color:#666;font-size:12px;">No techniques detected yet</div>';

                // Update alerts tab
                if (alertsData.alerts && alertsData.alerts.length > 0) {
                    document.getElementById('tab-alerts').innerHTML = alertsData.alerts.map(a => `
                        <div class="alert-card ${a.level}">
                            <div class="alert-header">
                                <span class="alert-title">[${a.rule_id}] ${a.rule_name}</span>
                                <span class="alert-level ${a.level}">${a.level}</span>
                            </div>
                            <div>${a.description}</div>
                            <div class="alert-meta">Source: ${a.source} | ${a.timestamp}</div>
                            <span class="alert-mitre">${a.mitre_id} - ${a.mitre_name}</span>
                            <div style="margin-top:5px;color:#666;font-size:11px;">${a.log_excerpt.substring(0,200)}</div>
                        </div>
                    `).join('');
                } else {
                    document.getElementById('tab-alerts').innerHTML = '<div class="empty">No alerts yet. Run the attack scripts to generate security events!<br><br><code>bash scripts/generate_events.sh</code><br><code>bash scripts/red_team_attack.sh</code></div>';
                }

                // Update events tab
                if (eventsData.events && eventsData.events.length > 0) {
                    document.getElementById('tab-events').innerHTML = eventsData.events.map(e =>
                        `<div class="log-line"><span class="log-source">[${e.source}]</span>${e.message.substring(0,200)}</div>`
                    ).join('');
                } else {
                    document.getElementById('tab-events').innerHTML = '<div class="empty">No events collected yet. Services may still be starting.</div>';
                }

                // Update rules tab
                document.getElementById('tab-rules').innerHTML = `
                    <table class="rules-table">
                        <tr><th>ID</th><th>Name</th><th>Level</th><th>MITRE</th><th>Group</th><th>Pattern</th></tr>
                        ${rulesData.rules.map(r => `
                            <tr>
                                <td>${r.id}</td><td>${r.name}</td>
                                <td><span class="alert-level ${r.level}">${r.level}</span></td>
                                <td><span class="alert-mitre">${r.mitre}</span></td>
                                <td>${r.group}</td>
                                <td style="font-family:monospace;font-size:10px;max-width:300px;overflow:hidden;text-overflow:ellipsis;">${r.pattern}</td>
                            </tr>
                        `).join('')}
                    </table>`;

                document.getElementById('last-refresh').textContent = 'Last refresh: ' + new Date().toLocaleTimeString();
            } catch(e) {
                document.getElementById('last-refresh').textContent = 'Refresh failed: ' + e.message;
            }
        }

        // Auto-refresh
        setInterval(() => { if (document.getElementById('auto-refresh').checked) refresh(); }, 5000);
        refresh();
    </script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/" or path == "/dashboard":
            self.send_html(200, DASHBOARD_HTML)

        elif path == "/api/alerts":
            limit = int(params.get("limit", [50])[0])
            with lock:
                data = list(alerts)[-limit:]
            data.reverse()
            self.send_json(200, {"alerts": data, "total": len(alerts)})

        elif path == "/api/events":
            limit = int(params.get("limit", [100])[0])
            with lock:
                data = list(events)[-limit:]
            data.reverse()
            self.send_json(200, {"events": data, "total": len(events)})

        elif path == "/api/stats":
            with lock:
                self.send_json(200, dict(stats))

        elif path == "/api/rules":
            rules_info = [
                {"id": r["id"], "name": r["name"], "level": r["level"],
                 "mitre": r["mitre"], "group": r["group"], "pattern": r["pattern"]}
                for r in DETECTION_RULES
            ]
            self.send_json(200, {"rules": rules_info})

        elif path == "/api/health":
            self.send_json(200, {"status": "healthy", "events": len(events), "alerts": len(alerts)})

        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else "{}"

        if parsed.path == "/api/ingest":
            try:
                data = json.loads(body)
                source = data.get("source", "api")
                message = data.get("message", "")
                if message:
                    analyze_log(source, message)
                    self.send_json(200, {"status": "ingested"})
                else:
                    self.send_json(400, {"error": "Missing 'message' field"})
            except json.JSONDecodeError:
                self.send_json(400, {"error": "Invalid JSON"})
        else:
            self.send_json(404, {"error": "Not found"})

    def send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_html(self, status, html):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, format, *args):
        pass  # Suppress default logging


if __name__ == "__main__":
    port = int(os.environ.get("SIEM_PORT", "5601"))

    # Start syslog receiver in background
    syslog_thread = threading.Thread(target=start_syslog_receiver, daemon=True)
    syslog_thread.start()

    # Start Docker log collector in background
    collector_thread = threading.Thread(target=docker_log_collector, daemon=True)
    collector_thread.start()

    # Start web dashboard
    server = HTTPServer(("0.0.0.0", port), DashboardHandler)
    logger.info("SIEM Lite Dashboard running on http://localhost:%d", port)
    logger.info("Detection rules loaded: %d", len(DETECTION_RULES))
    server.serve_forever()
