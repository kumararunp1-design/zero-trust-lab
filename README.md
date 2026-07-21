# Zero Trust Architecture - Hands-On Lab (GitHub Codespaces)

A hands-on cybersecurity lab environment demonstrating Zero Trust Architecture principles using Docker containers. Designed for educational workshops and faculty development programs, it covers identity verification (OIDC/OAuth2), policy-as-code (OPA/Rego), network micro-segmentation, SOC monitoring, and red team/blue team exercises.

Optimized for **GitHub Codespaces** (4-8 GB RAM) using a lightweight SIEM (~50 MB) instead of a full Wazuh stack (~3 GB).

**Duration:** ~2 Hours | **Difficulty:** Intermediate

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Setup Instructions (GitHub Codespaces)](#setup-instructions-github-codespaces)
- [Setup Instructions (Local)](#setup-instructions-local)
- [Service URLs and Credentials](#service-urls-and-credentials)
- [Lab Exercises](#lab-exercises)
  - [Lab 1: OIDC/OAuth2 Identity Provider (Keycloak)](#lab-1-oidcoauth2-identity-provider-keycloak---20-minutes)
  - [Lab 1 Extension: Passkeys and WebAuthn](#lab-1-extension-passkeys--webauthn-optional---15-minutes)
  - [Lab 2: Policy-Based Access Control (OPA)](#lab-2-policy-based-access-control-with-opa---20-minutes)
  - [Lab 3: Network Micro-segmentation](#lab-3-network-micro-segmentation---20-minutes)
  - [Lab 4: SOC Simulation with SIEM](#lab-4-soc-simulation-with-siem---20-minutes)
  - [Lab 5: Red Team / Blue Team Exercise](#lab-5-red-team--blue-team-exercise---20-minutes)
- [Components Reference](#components-reference)
- [Quick Reference Commands](#quick-reference-commands)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)

---

## Architecture Overview

```
+-----------------------------------------------------------------+
|                  Zero Trust Lab Environment                      |
|                                                                  |
|  +-------------+   +-------------+   +-------------+            |
|  |  Keycloak   |   | OPA Policy  |   |  SIEM-Lite  |            |
|  |  (IdP)      |<->|  Engine     |   |  Dashboard  |            |
|  | Port: 8080  |   | Port: 8181  |   | Port: 5601  |            |
|  +------+------+   +------+------+   +------+------+            |
|         |                 |                  |                    |
|  +------v------+   +------v------+   +------v------+            |
|  |  Frontend   |   | Backend API |   | Vulnerable  |            |
|  |  App        |<->| (Protected) |   | Target App  |            |
|  | Port: 3000  |   | Port: 5000  |   | Port: 8888  |            |
|  +-------------+   +-------------+   +-------------+            |
|                                                                  |
|  Networks: zt-frontend | zt-backend | zt-monitoring | zt-dmz    |
+-----------------------------------------------------------------+
```

### Request Flow

```
User -> Frontend (3000) -> Keycloak OIDC login (8080)
                           <- JWT access token (RS256, 5-min TTL)

User -> Frontend -> Backend API (5000) with Bearer token
                    -> Verify JWT against Keycloak public key
                    -> POST to OPA (8181) with {user, roles, resource, action, sensitivity, time}
                    -> OPA evaluates ABAC policy (default-deny)
                    <- 200 OK / 403 Forbidden / 401 Unauthorized
```

### Network Segments (Micro-segmentation)

| Network | Subnet | Purpose | Containers |
|---------|--------|---------|------------|
| zt-frontend | 172.20.1.0/24 | User-facing services | Keycloak (172.20.1.10), Frontend (172.20.1.20) |
| zt-backend | 172.20.2.0/24 | Internal APIs & policy engines | Keycloak (172.20.2.10), OPA (172.20.2.20), Backend (172.20.2.30), SIEM (172.20.2.40) |
| zt-monitoring | 172.20.3.0/24 | Security monitoring | SIEM-Lite (172.20.3.10), Vulnerable App (172.20.3.40) |
| zt-dmz | 172.20.4.0/24 | Isolated attack targets | Vulnerable App (172.20.4.10) |

### Test Users

| Username | Password | Role | Access Level |
|----------|----------|------|-------------|
| alice | alice123 | admin | Full access, 24/7, all sensitivity levels |
| bob | bob123 | analyst | Read-only, business hours (6AM-10PM), up to confidential |
| charlie | charlie123 | developer | Read/write code, business hours, public/internal only |

---

## Prerequisites

### For GitHub Codespaces (Recommended)

- A GitHub account with Codespaces access
- A modern web browser (Chrome recommended for the Passkey/WebAuthn lab)
- No local installation required -- everything runs in the cloud

### For Local Setup

- **Docker Desktop** installed and running (Docker 24+ and Docker Compose v2+)
- **4 GB RAM** minimum (8 GB recommended)
- **Terminal access** (bash/zsh)
- **curl** and **python3** available on the host

---

## Setup Instructions (GitHub Codespaces)

### Step 1: Launch the Codespace

1. Navigate to the repository on GitHub
2. Click the green **"Code"** button > **"Codespaces"** tab > **"Create codespace on main"**
3. Wait for the Codespace to build (~2-3 minutes on first launch)

The devcontainer automatically:
- Installs Docker-in-Docker, Python 3.11, and VS Code extensions
- Builds and starts all 6 services via the post-create script
- Configures Keycloak redirect URIs for the Codespaces environment
- Forwards ports 3000, 5000, 5601, 8080, 8181, and 8888

### Step 2: Wait for Services to Start

The setup script runs automatically. Watch the terminal for the "Lab Environment Ready!" message. Keycloak takes ~60-90 seconds to start.

If you need to check status manually:

```bash
docker compose ps
```

All 6 containers should show "Up" status, with Keycloak showing "(healthy)".

### Step 3: Access Services

In GitHub Codespaces, services are accessed via forwarded port URLs (not `localhost`).

**Finding your URLs:**
1. Click the **"Ports"** tab in the VS Code bottom panel
2. Each service has a forwarded URL in the format:
   `https://<codespace-name>-<port>.app.github.dev`
3. Click the globe icon next to any port to open it in the browser

**Important:** For the frontend and Keycloak to work in the browser, set the following ports to **Public** visibility:
1. In the **Ports** tab, right-click on port **3000** (Frontend) > **Port Visibility** > **Public**
2. Right-click on port **8080** (Keycloak) > **Port Visibility** > **Public**
3. Right-click on port **5000** (Backend API) > **Port Visibility** > **Public**
4. Right-click on port **5601** (SIEM Dashboard) > **Port Visibility** > **Public**
5. Right-click on port **8888** (Vulnerable App) > **Port Visibility** > **Public**

> **Note:** The frontend app auto-detects the Codespaces environment and rewrites URLs for Keycloak and Backend API automatically. Terminal `curl` commands in the labs still use `localhost` since they run inside the Codespace.

### Step 4: Verify All Services

Run this in the Codespace terminal:

```bash
# Frontend
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 && echo " OK"

# Keycloak
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/realms/zero-trust-lab && echo " OK"

# Backend API
curl -s http://localhost:5000/api/health | python3 -m json.tool

# OPA
curl -s -o /dev/null -w "%{http_code}" http://localhost:8181/v1/policies && echo " OK"

# Vulnerable App
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888 && echo " OK"

# SIEM Dashboard
curl -s -o /dev/null -w "%{http_code}" http://localhost:5601 && echo " OK"
```

All services should return `200 OK`.

---

## Setup Instructions (Local)

```bash
# 1. Clone the repository
git clone https://github.com/kumararunp1-design/zero-trust-lab.git
cd zero-trust-lab

# 2. Build all container images
docker compose build

# 3. Start all 6 services
docker compose up -d

# 4. Wait for Keycloak to become healthy (~60-90 seconds)
docker compose ps
docker compose logs -f keycloak | grep -i "started"
```

For local setup, all services are accessed via `http://localhost:<port>`.

---

## Service URLs and Credentials

| Service | Local URL | Codespaces URL Pattern | Credentials |
|---------|-----------|----------------------|-------------|
| Frontend App | http://localhost:3000 | `https://<codespace>-3000.app.github.dev` | Login via Keycloak |
| Keycloak Admin | http://localhost:8080/admin | `https://<codespace>-8080.app.github.dev/admin` | admin / admin123 |
| Backend API | http://localhost:5000 | `https://<codespace>-5000.app.github.dev` | Bearer token required |
| OPA API | http://localhost:8181 | `https://<codespace>-8181.app.github.dev` | No auth required |
| Vulnerable App | http://localhost:8888 | `https://<codespace>-8888.app.github.dev` | See Lab 5 |
| SIEM Dashboard | http://localhost:5601 | `https://<codespace>-5601.app.github.dev` | No auth required |
| Passkey Demo | http://localhost:3000/passkey | `https://<codespace>-3000.app.github.dev/passkey` | N/A |

> **Codespaces Tip:** All `curl` commands in the labs use `localhost` and work as-is in the Codespace terminal, since they execute inside the container environment. Only browser access requires the forwarded URLs.

---

## Lab Exercises

### Lab 1: OIDC/OAuth2 Identity Provider (Keycloak) - 20 Minutes

> **Real-World Parallel:** This lab replicates what Okta, Auth0, and Azure AD provide as a service. Keycloak is the open-source alternative used by government agencies, universities, and enterprises.

**Learning Objectives:**
- Understand OIDC realms, clients, roles, and user federation
- Test OAuth 2.0 Authorization Code flow
- Decode and analyze JWT tokens
- Configure Multi-Factor Authentication (TOTP)

#### 1.1 Explore Keycloak Admin Console

1. Open the Keycloak Admin Console (port 8080, path `/admin`)
2. Login with `admin` / `admin123`
3. Select the **zero-trust-lab** realm (dropdown top-left)
4. Explore:
   - **Users**: See alice (admin), bob (analyst), charlie (developer)
   - **Clients**: See zt-frontend (public client), zt-backend (bearer-only)
   - **Realm Roles**: admin, analyst, developer, auditor

#### 1.2 Get an OIDC Access Token

```bash
# Get an access token using Resource Owner Password Grant (for testing only!)
# In production, ALWAYS use Authorization Code flow with PKCE
curl -s -X POST "http://localhost:8080/realms/zero-trust-lab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=zt-frontend" \
  -d "username=alice" \
  -d "password=alice123" \
  -d "grant_type=password" \
  -d "scope=openid profile email" | python3 -m json.tool
```

#### 1.3 Decode the JWT Token

```bash
# Save token to variable
TOKEN=$(curl -s -X POST "http://localhost:8080/realms/zero-trust-lab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=zt-frontend" \
  -d "username=alice" \
  -d "password=alice123" \
  -d "grant_type=password" \
  -d "scope=openid profile email" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Decode JWT payload
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

**Expected:** JWT claims including `sub`, `email`, `realm_access.roles`, `exp`, `iss`.

#### 1.4 Test the Frontend Login Flow

1. Open the Frontend App (port 3000) in your browser
2. Click **"Login with Keycloak"** and login as `alice` / `alice123`
3. After redirect, you should see: **"Authenticated as alice"** with roles displayed
4. Click **"Read Data"** -- should show data with `policy_check: PASSED`
5. Click **"Admin Panel"** -- should succeed (alice is admin)
6. **Logout**, then login as `bob` / `bob123`
7. Click **"Read Data"** -- should succeed (analyst can read data)
8. Click **"Admin Panel"** -- should show **"Insufficient privileges"** (bob is analyst, not admin)

#### 1.5 Configure MFA (TOTP)

1. In Keycloak Admin: **Authentication** > **Flows** > **Browser**
2. Set **OTP Form** to **Required**
3. Users will now be prompted to set up TOTP (Google Authenticator compatible) on next login

#### Exercise 1 Questions

1. **What claims are in the JWT token? Which ones are used for authorization?**
2. **Why is PKCE mandatory in OAuth 2.1? What attack does it prevent?**
3. **What happens if a token expires? How does the refresh token flow work?**

---

### Lab 1 Extension: Passkeys & WebAuthn (Optional) - 15 Minutes

> **Real-World Adoption:** Apple, Google, and Microsoft have shipped passkey support. GitHub, AWS IAM, and Shopify support passkeys. NIST SP 800-63B-4 recommends phishing-resistant authenticators.

**Learning Objectives:**
- Understand how FIDO2/WebAuthn replaces passwords with asymmetric cryptography
- Experience the WebAuthn registration and authentication ceremonies
- See why passkeys are phishing-proof (origin-bound credentials)

#### Background: How Passkeys Work

| Generation | Method | Weakness |
|-----------|--------|----------|
| 1st | Passwords | Phishable, reusable, stored as hashes |
| 2nd | Passwords + TOTP/SMS MFA | Still phishable (real-time relay attacks) |
| 3rd | **Passkeys (FIDO2/WebAuthn)** | **Phishing-proof**, origin-bound, no shared secrets |

1. **Registration:** Browser generates asymmetric keypair (ES256). Private key stays in authenticator. Public key sent to server.
2. **Authentication:** Server sends random challenge. Authenticator signs it with private key. Server verifies signature.
3. **Phishing protection:** Credential bound to the origin (e.g., `localhost`). Phishing site at `evil.com` cannot trigger it.

#### Setup Chrome Virtual Authenticator

1. Open the Passkey Demo page (port 3000, path `/passkey`) in Chrome
2. Open DevTools (F12) > **...** (three-dot menu) > **More tools** > **WebAuthn**
3. Check **"Enable virtual authenticator environment"**
4. Click **"Add"** with settings:
   - Protocol: ctap2
   - Transport: internal
   - Supports resident keys: checked
   - Supports user verification: checked

#### Interactive Demo

1. Click **"Register Passkey"** -- a credential appears in the WebAuthn panel
2. Click **"Authenticate with Passkey"** to verify
3. Click **"Inspect Credential"** to see origin binding and signature data

#### Exercise 1 Extension Questions

1. **Why can't a phishing site at `evil.com` use a passkey registered for `localhost`?**
2. **What happens if a server's passkey database is breached? Can the attacker authenticate?**
3. **Compare TOTP vs. passkeys for phishing resistance. Can a real-time relay attack defeat each?**

---

### Lab 2: Policy-Based Access Control with OPA - 20 Minutes

> **Real-World Parallel:** Netflix uses OPA to authorize millions of API requests per second. Goldman Sachs uses it for data access policies. OPA is a CNCF graduated project.

**Learning Objectives:**
- Understand Rego policies for attribute-based access control (ABAC)
- Test context-aware authorization (role + time + resource + sensitivity)
- Run OPA unit tests

#### 2.1 View Loaded Policies

```bash
curl -s http://localhost:8181/v1/policies | python3 -c "
import sys, json
policies = json.load(sys.stdin)['result']
for p in policies:
    print(f'  - {p[\"id\"]}')
"
```

You should see:
- `policies/authz.rego` -- Main ABAC authorization policy
- `policies/data_classification.rego` -- Data handling rules

#### 2.2 Test Policy Decisions

```bash
# Test 1: Admin accessing confidential alerts (SHOULD ALLOW)
echo "=== Test 1: Admin accessing confidential alerts ==="
curl -s -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"username": "alice", "roles": ["admin"]},
      "resource": "alerts",
      "action": "write",
      "sensitivity": "confidential",
      "time": {"hour": 14, "day": "wednesday"}
    }
  }' | python3 -m json.tool

# Test 2: Analyst trying to write (SHOULD DENY - read-only role)
echo "=== Test 2: Analyst trying to write ==="
curl -s -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"username": "bob", "roles": ["analyst"]},
      "resource": "alerts",
      "action": "write",
      "sensitivity": "internal",
      "time": {"hour": 14, "day": "wednesday"}
    }
  }' | python3 -m json.tool

# Test 3: Developer accessing secret data (SHOULD DENY - insufficient clearance)
echo "=== Test 3: Developer accessing secret data ==="
curl -s -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"username": "charlie", "roles": ["developer"]},
      "resource": "code",
      "action": "read",
      "sensitivity": "secret",
      "time": {"hour": 14, "day": "wednesday"}
    }
  }' | python3 -m json.tool

# Test 4: Analyst accessing at 3 AM (SHOULD DENY - outside business hours)
echo "=== Test 4: Analyst at 3 AM ==="
curl -s -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"username": "bob", "roles": ["analyst"]},
      "resource": "data",
      "action": "read",
      "sensitivity": "internal",
      "time": {"hour": 3, "day": "wednesday"}
    }
  }' | python3 -m json.tool

# Test 5: Admin at 3 AM (SHOULD ALLOW - 24/7 access)
echo "=== Test 5: Admin at 3 AM (24/7 access) ==="
curl -s -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"username": "alice", "roles": ["admin"]},
      "resource": "data",
      "action": "read",
      "sensitivity": "internal",
      "time": {"hour": 3, "day": "wednesday"}
    }
  }' | python3 -m json.tool

# Test 6: Get deny reasons
echo "=== Test 6: Deny reasons ==="
curl -s -X POST http://localhost:8181/v1/data/authz/deny_reasons \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {"username": "charlie", "roles": ["developer"]},
      "resource": "admin",
      "action": "admin",
      "sensitivity": "internal",
      "time": {"hour": 14, "day": "wednesday"}
    }
  }' | python3 -m json.tool
```

#### 2.3 Run OPA Unit Tests

```bash
docker exec zt-opa /opa test /policies -v
```

#### 2.4 End-to-End Test (Keycloak Token + Backend API + OPA)

```bash
# Get alice's token and call protected API
ALICE_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/zero-trust-lab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=zt-frontend&grant_type=password&username=alice&password=alice123" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "=== alice /api/data (should succeed) ==="
curl -s -H "Authorization: Bearer $ALICE_TOKEN" http://localhost:5000/api/data | python3 -m json.tool

echo "=== alice /api/admin (should succeed) ==="
curl -s -H "Authorization: Bearer $ALICE_TOKEN" http://localhost:5000/api/admin | python3 -m json.tool

# Get bob's token
BOB_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/zero-trust-lab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=zt-frontend&grant_type=password&username=bob&password=bob123" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "=== bob /api/data (should succeed - analyst can read) ==="
curl -s -H "Authorization: Bearer $BOB_TOKEN" http://localhost:5000/api/data | python3 -m json.tool

echo "=== bob /api/admin (should be DENIED) ==="
curl -s -H "Authorization: Bearer $BOB_TOKEN" http://localhost:5000/api/admin | python3 -m json.tool
```

#### OPA Policy Reference

| Role | Resources | Actions | Sensitivity Clearance | Hours |
|------|-----------|---------|----------------------|-------|
| admin | All (`*`) | read, write, delete, admin | public - secret | 24/7 |
| analyst | alerts, logs, reports, dashboards, data | read | public - confidential | 6AM-10PM |
| developer | code, deployments, configs, logs | read, write | public, internal | 6AM-10PM |
| auditor | audit_logs, compliance_reports, access_logs | read | public - secret | 6AM-10PM |

#### Exercise 2 Questions

1. **How does ABAC differ from RBAC? What additional context does ABAC consider?**
2. **Why is "default deny" important in Zero Trust? What happens if we used "default allow"?**
3. **How would you add a geolocation-based policy (e.g., deny access from certain countries)?**

---

### Lab 3: Network Micro-segmentation - 20 Minutes

> **Real-World Parallel:** This lab demonstrates the same concepts that Illumio (used by 60% of Fortune 500 financial firms) and Cilium (used by Google, Netflix, AWS EKS) implement at enterprise scale.

**Learning Objectives:**
- Understand network isolation via Docker networks
- Test lateral movement prevention
- Visualize network topology

#### 3.1 Verify Network Isolation

```bash
# List zero trust networks
docker network ls | grep zt-

# Inspect container assignments
echo "=== Frontend Network (172.20.1.0/24) ==="
docker network inspect zero-trust-lab_zt-frontend \
  --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'

echo "=== Backend Network (172.20.2.0/24) ==="
docker network inspect zero-trust-lab_zt-backend \
  --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'
```

#### 3.2 Test Network Segmentation

```bash
# Frontend CANNOT reach Backend directly (different network - should FAIL)
echo "=== Frontend -> Backend (should FAIL) ==="
docker exec zt-frontend-app python3 -c "
import urllib.request
try:
    urllib.request.urlopen('http://172.20.2.30:5000/api/health', timeout=3)
    print('CONNECTED - Segmentation BROKEN!')
except Exception as e:
    print('BLOCKED - Segmentation working!')
"

# Frontend CAN reach Keycloak (shared zt-frontend network - should SUCCEED)
echo "=== Frontend -> Keycloak (should SUCCEED) ==="
docker exec zt-frontend-app python3 -c "
import urllib.request
try:
    resp = urllib.request.urlopen('http://172.20.1.10:8080/health/ready', timeout=3)
    print('CONNECTED - OK (shared network)')
except Exception as e:
    print(f'FAILED: {e}')
"

# Backend CAN reach OPA (same zt-backend network - should SUCCEED)
echo "=== Backend -> OPA (should SUCCEED) ==="
docker exec zt-backend-api python3 -c "
import urllib.request
resp = urllib.request.urlopen('http://172.20.2.20:8181/health', timeout=3)
print('CONNECTED - OK (same backend network)')
"
```

#### 3.3 Visualize Network Topology

```bash
bash scripts/network_map.sh
```

This runs live connectivity probes between containers and displays allowed vs. blocked paths.

#### 3.4 Simulate Lateral Movement Attack

```bash
echo "=== Lateral Movement Test ==="
echo "Scenario: Attacker has shell on frontend container..."

docker exec zt-frontend-app python3 -c "
import urllib.request

targets = [
    ('Backend API', 'http://172.20.2.30:5000/api/health'),
    ('OPA', 'http://172.20.2.20:8181/health'),
    ('Vulnerable App', 'http://172.20.4.10:8888'),
]

for name, url in targets:
    try:
        urllib.request.urlopen(url, timeout=2)
        print(f'  [FAIL] Can reach {name} - Segmentation BROKEN!')
    except:
        print(f'  [BLOCKED] Cannot reach {name} - Segmentation working!')
"

echo ""
echo "RESULT: Micro-segmentation prevents lateral movement!"
```

#### Exercise 3 Questions

1. **In Kubernetes, what resource replaces Docker networks for segmentation?** (Hint: NetworkPolicy)
2. **What is the difference between network-based and identity-based segmentation?**
3. **How would an attacker bypass micro-segmentation? What additional controls are needed?**

---

### Lab 4: SOC Simulation with SIEM - 20 Minutes

> **Real-World Parallel:** This lightweight SIEM demonstrates the same concepts as Splunk ($150K+/year license), Microsoft Sentinel, or Wazuh, using ~50 MB RAM.

**Learning Objectives:**
- Understand SIEM event collection and analysis
- Generate and analyze security events
- Understand alert triage and MITRE ATT&CK technique mapping

#### 4.1 Access SIEM Dashboard

Open the SIEM Dashboard (port 5601) in your browser. You'll see:
- **Stats bar** showing total alerts, critical/high/medium counts
- **MITRE ATT&CK sidebar** with detected techniques
- **Security Alerts tab** with severity-coded alerts
- **Raw Events tab** for log inspection
- **Detection Rules tab** listing all 14 rules

#### 4.2 Generate Security Events

```bash
bash scripts/generate_events.sh
```

This simulates:
- **Brute force attacks** (10 failed logins against Keycloak)
- **Successful login after failures** (suspicious pattern)
- **API rate limit abuse** (25 rapid requests)
- **System events** via SIEM ingest API:
  - SSH authentication failures
  - Unauthorized sudo attempt
  - Suspicious user creation (backdoor account)
  - Lateral movement detection
  - Network scan detection
  - Data exfiltration attempt

#### 4.3 Analyze Events in the Dashboard

1. Open the SIEM Dashboard and click **"Refresh Now"**
2. Review the **Security Alerts tab** -- alerts are color-coded by severity
3. Check the **MITRE ATT&CK sidebar** for technique counts (T1110, T1548, T1136, etc.)
4. Switch to **Raw Events** to see the underlying log entries

#### 4.4 Analyze Events via CLI

```bash
# Check Keycloak login events
echo "=== Failed Login Events ==="
docker logs zt-keycloak 2>&1 | grep -i "LOGIN_ERROR" | tail -10

# Check backend API logs
echo "=== Backend API Activity ==="
docker logs zt-backend-api 2>&1 | tail -15

# Check vulnerable app logs
echo "=== Vulnerable App Logs ==="
docker logs zt-vulnerable-app 2>&1 | grep -i "security\|warning\|critical" | tail -10

# Query SIEM alerts via API
echo "=== Recent SIEM Alerts ==="
curl -s http://localhost:5601/api/alerts?limit=5 | python3 -m json.tool
```

#### Exercise 4 Questions

1. **What is the difference between a SIEM alert and an incident?**
2. **How would you reduce false positives in detection rules?**
3. **What additional data sources would improve detection accuracy?**

---

### Lab 5: Red Team / Blue Team Exercise - 20 Minutes

> **Real-World Parallel:** This exercise mirrors what penetration testing firms like Mandiant, CrowdStrike, and Rapid7 do for Fortune 500 clients.

**Learning Objectives:**
- Execute controlled attacks mapped to MITRE ATT&CK
- Detect and respond to attacks using NIST SP 800-61r2 workflow
- Compare vulnerable app (no auth) vs. protected backend (Keycloak + OPA)

#### 5.1 Red Team Attack

```bash
bash scripts/red_team_attack.sh
```

This runs a 6-phase attack chain against the vulnerable app:

| Phase | MITRE ATT&CK | Description |
|-------|---------------|-------------|
| 1 | T1595, T1082 | **Reconnaissance** - Discover endpoints, debug info |
| 2 | T1190 | **Initial Access** - Authentication bypass with known tokens |
| 3 | T1548 | **Privilege Escalation** - IDOR: user token accesses admin endpoint |
| 4 | T1552 | **Credential Access** - Extract DB passwords and API keys |
| 5 | T1190 | **SSRF** - Server-side request forgery to internal services |
| 6 | T1059 | **Command Injection** - Unsanitized input |

#### 5.2 Blue Team Response

```bash
bash scripts/blue_team_response.sh
```

Walks through the NIST SP 800-61r2 incident response process:
1. **Detection** - Review SIEM alerts and identify attack patterns
2. **Analysis** - Investigate Keycloak logs, vulnerable app logs, network connections
3. **Containment** - Isolate compromised containers, rotate credentials, preserve evidence
4. **Documentation** - Complete the incident report template (CWE/OWASP/MITRE mapping)

#### 5.3 Compare Vulnerable vs. Protected

```bash
# VULNERABLE APP: No role check -- user token gets admin access
echo "=== VULNERABLE APP: user-token gets admin ==="
curl -s -H "Authorization: Bearer user-token-67890" http://localhost:8888/api/admin | python3 -m json.tool | head -10

echo ""
# PROTECTED APP: OPA denies bob (analyst) from admin
echo "=== PROTECTED APP: OPA denies bob from admin ==="
BOB_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/zero-trust-lab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=zt-frontend&grant_type=password&username=bob&password=bob123" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -H "Authorization: Bearer $BOB_TOKEN" http://localhost:5000/api/admin | python3 -m json.tool
```

#### Exercise 5 Questions

1. **Map each vulnerability to an OWASP Top 10 (2025) category.**
2. **How would Zero Trust principles prevent each attack phase?**
3. **Design a detection rule for the SSRF attack pattern.**

---

## Components Reference

### Backend API (`apps/backend/`)

Python/Flask API enforcing Zero Trust on every request:
1. **JWT validation** - RS256 token verified against Keycloak's public key
2. **OPA policy check** - ABAC evaluation of role, resource, action, sensitivity, and time
3. **Default deny** - OPA unreachable = deny

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/health` | Public | Health check |
| `GET /api/data` | JWT + OPA | Returns sample data (sensitivity: internal) |
| `GET /api/admin` | JWT + OPA | Admin panel (sensitivity: confidential) |

### Frontend (`apps/frontend/`)

Python HTTP server serving a single-page dashboard:
- OAuth 2.0 Authorization Code flow with Keycloak
- Server-side token exchange (avoids cross-origin issues in Codespaces)
- Auto-detects Codespaces environment and rewrites URLs
- Passkey/WebAuthn demo page at `/passkey`

### OPA Policies (`opa/policies/`)

Rego-based ABAC with default-deny posture:
- `authz.rego` - Main authorization policy with role matrix, time checks, deny reasons, audit metadata
- `authz_test.rego` - Unit tests for policy validation
- `data_classification.rego` - Data handling rules by sensitivity level

### Vulnerable App (`apps/vulnerable/`)

Intentionally insecure application isolated in the DMZ network:
- Broken authentication (hardcoded tokens)
- Broken access control / IDOR (no role checks)
- SSRF simulation
- Environment variable disclosure (`/debug/env`)
- Command injection simulation

### SIEM-Lite (`apps/siem-lite/`)

Lightweight SIEM (~50 MB RAM) with:
- Docker log collection from all 5 containers
- 14 regex-based detection rules mapped to MITRE ATT&CK techniques
- Web dashboard with auto-refresh, severity-coded alerts, and raw event viewer
- REST API for querying alerts (`/api/alerts`, `/api/events`, `/api/stats`)
- Manual event ingestion via `POST /api/ingest`

### Keycloak (`keycloak/`)

Pre-configured OIDC Identity Provider with:
- `zero-trust-lab` realm with 3 users and 4 roles
- Brute force protection (lockout after 5 failures)
- Short-lived access tokens (5-minute TTL)
- WebAuthn/Passkey authentication flow
- Event auditing enabled

---

## Zero Trust Principles Demonstrated

| Principle | Implementation |
|-----------|---------------|
| Never trust, always verify | Every API call requires JWT + OPA policy check |
| Least privilege | Role-based permissions with sensitivity clearance levels |
| Assume breach | Vulnerable app isolated in DMZ; SIEM monitors all activity |
| Network segmentation | 4 separate subnets with trust-based service placement |
| Short-lived credentials | 5-minute access tokens |
| Default deny | OPA policy defaults to deny; OPA unreachable = deny |
| Continuous monitoring | SIEM with 14 MITRE ATT&CK detection rules |
| Phishing-resistant auth | WebAuthn/Passkey support via Keycloak |

---

## Quick Reference Commands

```bash
# Start all services
docker compose up -d

# Check container status
docker compose ps

# View logs for a specific service
docker compose logs -f frontend
docker compose logs -f backend-api
docker compose logs -f keycloak

# Run OPA policy tests
docker exec zt-opa /opa test /policies -v

# Run lab scripts
bash scripts/generate_events.sh
bash scripts/red_team_attack.sh
bash scripts/blue_team_response.sh
bash scripts/network_map.sh

# Stop all services
docker compose down

# Stop and remove all data (clean slate)
docker compose down -v

# Rebuild after code changes
docker compose build --quiet frontend backend-api
docker compose up -d frontend backend-api
```

---

## Troubleshooting

| Issue | Solution |
|-------|---------|
| **Keycloak slow to start** | Takes ~60-90 seconds for JVM warmup and realm import. Check: `docker compose logs -f keycloak` |
| **Out of memory** | Lab is optimized for 4 GB. If OOM, stop unused services: `docker compose stop siem-lite vulnerable-app` |
| **Port conflicts** | Change ports in `docker-compose.yml`. Common conflicts: 8080, 5000 |
| **Token rejected (401)** | Token expires after 5 minutes. Get a new one. |
| **"Access denied by policy"** | Check OPA policy matches the resource/action/role. Test with curl against OPA directly. |
| **Frontend login loop** | Clear browser sessionStorage, try again |
| **Containers not starting** | Run `docker compose down && docker compose up -d` |
| **Codespaces: Login redirect fails** | Ensure ports 3000 and 8080 are set to **Public** visibility in the Ports tab |
| **Codespaces: "Invalid redirect_uri"** | The setup script auto-configures redirect URIs. If it failed, restart: `bash .devcontainer/setup.sh` |
| **Codespaces: CORS errors in browser** | Set port 5000 (Backend API) to **Public** visibility |
| **OPA policy errors** | Check syntax: `docker exec zt-opa /opa check /policies` |

### Check Service Health

```bash
docker compose ps
curl http://localhost:8080/health/ready   # Keycloak
curl http://localhost:8181/health          # OPA
curl http://localhost:5000/api/health      # Backend API
curl http://localhost:5601/api/health      # SIEM
```

---

## Project Structure

```
zero-trust-lab/
├── .devcontainer/
│   ├── devcontainer.json               # Codespaces configuration (ports, extensions, resources)
│   └── setup.sh                        # Auto-setup script (builds, starts, configures Keycloak)
├── docker-compose.yml                  # All 6 services + 4 isolated networks
├── README.md                           # This file
├── apps/
│   ├── backend/                        # Protected API (Flask + Keycloak JWT + OPA policy)
│   │   ├── app.py
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── frontend/                       # User-facing app with OIDC login + Codespaces auto-detect
│   │   ├── app.py
│   │   ├── passkey_demo.html
│   │   └── Dockerfile
│   ├── vulnerable/                     # Intentionally insecure app (attack target in DMZ)
│   │   ├── app.py
│   │   └── Dockerfile
│   └── siem-lite/                      # Lightweight SIEM dashboard (~50 MB)
│       ├── app.py
│       └── Dockerfile
├── keycloak/
│   └── realm-export.json               # Pre-configured realm with users, roles, clients
├── opa/
│   └── policies/
│       ├── authz.rego                  # ABAC authorization policy (default-deny)
│       ├── authz_test.rego             # OPA unit tests
│       └── data_classification.rego    # Data handling rules by sensitivity
├── scripts/
│   ├── generate_events.sh              # Security event generator for SIEM
│   ├── red_team_attack.sh              # MITRE ATT&CK mapped 6-phase attack chain
│   ├── blue_team_response.sh           # NIST SP 800-61r2 incident response guide
│   └── network_map.sh                  # Network topology visualization + live probes
└── ppt/
    ├── CyberSecurity_ZeroTrust_Lecture.pptx  # Lecture slides
    └── ZeroTrust_Lab_Instructions.md         # Extended lab guide (build-from-scratch version)
```

---

## Industry Mapping

| Lab Component | Industry Equivalent | Production Tools |
|---------------|-------------------|------------------|
| Keycloak (IdP) | Okta, Azure AD, Auth0 | Okta, Entra ID, Ping Identity |
| OPA (Policy) | Enterprise policy engines | OPA, HashiCorp Sentinel, AWS Cedar |
| Docker Networks | Micro-segmentation | Cilium, Illumio, VMware NSX |
| SIEM-Lite | Enterprise SIEM | Splunk, Microsoft Sentinel, Elastic SIEM |
| Red/Blue Exercise | Penetration testing | Metasploit, Cobalt Strike, Atomic Red Team |
| Passkeys/WebAuthn | Passwordless auth | FIDO2 keys, Apple/Google Passkeys |

---

## Take-Home Challenges

1. **Add HTTPS/TLS** to all services (use mkcert for local CA)
2. **Implement mutual TLS (mTLS)** between backend services
3. **Add a rate limiter** to the backend API using OPA policies
4. **Create Kubernetes NetworkPolicy** equivalents for the Docker network rules
5. **Write a custom OPA policy** for geolocation-based access control
6. **Add a new SIEM detection rule** for SQL injection patterns

---

*Zero Trust Lab - GitHub Codespaces Edition*
*Covering: Zero Trust Architecture, Modern IAM (OIDC/OAuth2/Passkeys), Policy-as-Code (OPA/Rego), Micro-segmentation, SOC Operations, Red Team/Blue Team*
