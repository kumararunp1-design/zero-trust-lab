# Zero Trust Lab

A hands-on Zero Trust security lab environment built with Docker Compose. Designed for educational workshops and faculty development programs, it demonstrates identity verification, policy-based access control, network segmentation, SIEM monitoring, and attack simulation.

Optimized for GitHub Codespaces (4-8 GB RAM) using a lightweight SIEM instead of a full Wazuh stack.

## Architecture

```
                        Zero Trust Lab Environment

  zt-frontend (172.20.1.0/24)         zt-backend (172.20.2.0/24)
  +--------------------------+        +------------------------------+
  |                          |        |                              |
  |  Keycloak (IdP)  :8080 --|--------|-- Keycloak    172.20.2.10   |
  |  172.20.1.10             |        |  OPA (Policy) 172.20.2.20   |
  |                          |        |  Backend API  172.20.2.30   |
  |  Frontend App    :3000   |        |  SIEM Lite    172.20.2.40   |
  |  172.20.1.20             |        |                              |
  +--------------------------+        +------------------------------+

  zt-monitoring (172.20.3.0/24)       zt-dmz (172.20.4.0/24)
  +--------------------------+        +------------------------------+
  |                          |        |                              |
  |  SIEM Lite  172.20.3.10 -|--------|  Vulnerable App 172.20.4.10 |
  |  Vuln App   172.20.3.40  |        |                              |
  +--------------------------+        +------------------------------+
```

**Request flow:**

```
User -> Frontend (3000) -> Keycloak OIDC login (8080)
                           <- JWT access token (RS256, 5-min TTL)

User -> Frontend -> Backend API (5000) with Bearer token
                    -> Verify JWT against Keycloak public key
                    -> POST to OPA (8181) with {user, roles, resource, action, sensitivity, time}
                    -> OPA evaluates ABAC policy (default-deny)
                    <- 200 OK / 403 Forbidden / 401 Unauthorized
```

## Prerequisites

- Docker Engine 24+ and Docker Compose v2+
- 4 GB RAM minimum (8 GB recommended)
- Terminal access

Verify your setup:

```bash
docker --version
docker compose version
```

## Quick Start

### Option 1: GitHub Codespaces (Recommended)

Open the repository in GitHub Codespaces. The devcontainer will automatically build and start all services via the post-create script. No manual setup required.

### Option 2: Local Setup

```bash
# 1. Clone the repository
git clone <repo-url>
cd zero-trust-lab

# 2. Build all container images
docker compose build

# 3. Start all 6 services in the background
docker compose up -d

# 4. Wait for services to become healthy (Keycloak takes ~90s on first boot)
docker compose ps
docker compose logs -f keycloak | grep -i "started"
```

To stop the lab:

```bash
docker compose down
```

## Services

| Service | Port | URL | Description |
|---|---|---|---|
| Frontend | 3000 | http://localhost:3000 | Dashboard with OIDC login and API interaction |
| Backend API | 5000 | http://localhost:5000 | Zero Trust-enforced REST API (Flask) |
| Keycloak | 8080 | http://localhost:8080 | OIDC/OAuth2 Identity Provider |
| OPA | 8181 | http://localhost:8181 | Policy engine (Rego-based ABAC) |
| Vulnerable App | 8888 | http://localhost:8888 | Intentionally insecure app for attack simulation |
| SIEM Dashboard | 5601 | http://localhost:5601 | Lightweight SIEM with MITRE ATT&CK detection |
| Passkey Demo | 3000 | http://localhost:3000/passkey | Interactive WebAuthn/FIDO2 demo |

## Credentials

| User | Password | Role | Description |
|---|---|---|---|
| admin | admin123 | - | Keycloak admin console |
| alice | alice123 | admin | Full system administrator (24/7 access) |
| bob | bob123 | analyst | SOC analyst with read access |
| charlie | charlie123 | developer | Developer with limited access |

## Components

### Backend API (`apps/backend/`)

Python/Flask API enforcing Zero Trust on every request:

1. **JWT validation** - RS256 token verified against Keycloak's public key
2. **OPA policy check** - ABAC evaluation of role, resource, action, sensitivity level, and time

| Endpoint | Auth | Description |
|---|---|---|
| `GET /api/health` | Public | Health check |
| `GET /api/data` | JWT + OPA | Returns sample data (sensitivity: internal) |
| `GET /api/admin` | JWT + OPA | Admin panel (sensitivity: confidential) |

### Frontend (`apps/frontend/`)

Python HTTP server serving a single-page dashboard:

- OAuth 2.0 Authorization Code Flow with Keycloak
- Buttons to test role-based access to backend endpoints
- Auto-detects GitHub Codespaces environment and rewrites URLs
- Passkey/WebAuthn demo page at `/passkey`

### OPA Policies (`opa/policies/`)

Rego-based Attribute-Based Access Control (ABAC) with default-deny:

| Role | Resources | Actions | Sensitivity Clearance | Hours |
|---|---|---|---|---|
| admin | All (`*`) | read, write, delete, admin | public - secret | 24/7 |
| analyst | alerts, logs, reports, dashboards | read | public - confidential | 6 AM - 10 PM |
| developer | code, deployments, configs, logs | read, write | public, internal | 6 AM - 10 PM |
| auditor | audit_logs, compliance_reports, access_logs | read | public - secret | 6 AM - 10 PM |

Run policy unit tests:

```bash
docker exec zt-opa /opa test /policies -v
```

### Vulnerable App (`apps/vulnerable/`)

Intentionally insecure application isolated in the DMZ network. Used as an attack target for red team exercises and SIEM detection testing.

Deliberate vulnerabilities include:
- Broken authentication (hardcoded tokens)
- Broken access control (no role checks)
- SSRF (simulated)
- Environment variable disclosure
- Command injection (simulated)

### SIEM Lite (`apps/siem-lite/`)

Lightweight SIEM (~50 MB RAM) replacing the full Wazuh stack (~3 GB). Features:

- Docker log collection from all 5 containers
- 14 regex-based detection rules mapped to MITRE ATT&CK techniques
- Web dashboard with auto-refresh, severity-coded alerts, and raw event viewer
- Syslog receiver (UDP 514) for simulated events
- Manual event ingestion via `POST /api/ingest`

### Keycloak (`keycloak/`)

Pre-configured OIDC Identity Provider with:

- `zero-trust-lab` realm with 3 users and 4 roles
- Brute force protection (lockout after 5 failures)
- Short-lived access tokens (5-minute TTL)
- WebAuthn/Passkey authentication flow
- Event auditing enabled

## Lab Scripts

Exercise scripts are in the `scripts/` directory:

| Script | Description |
|---|---|
| `red_team_attack.sh` | Simulate attacks against the vulnerable app |
| `blue_team_response.sh` | Incident response and investigation |
| `generate_events.sh` | Generate security events for SIEM analysis |
| `network_map.sh` | Map and visualize network segments |

Run any script:

```bash
./scripts/red_team_attack.sh
```

## Lab Exercises

Detailed lab instructions are in [`ppt/ZeroTrust_Lab_Instructions.md`](ppt/ZeroTrust_Lab_Instructions.md). The labs cover:

1. **OIDC/OAuth2 Identity Provider Setup** - Configure Keycloak, issue and decode JWT tokens, set up MFA
2. **Passkeys & WebAuthn** (optional) - FIDO2 registration/authentication, phishing resistance
3. **Policy-Based Access Control with OPA** - Write Rego policies, test ABAC rules
4. **Red Team / Blue Team** - Attack simulation, SIEM detection, incident response
5. **Network Segmentation** - Explore micro-segmented networks and Zero Trust boundaries

## Zero Trust Principles Demonstrated

| Principle | Implementation |
|---|---|
| Never trust, always verify | Every API call requires JWT + OPA policy check |
| Least privilege | Role-based permissions with sensitivity clearance levels |
| Assume breach | Vulnerable app isolated in DMZ; SIEM monitors all activity |
| Network segmentation | 4 separate subnets with trust-based service placement |
| Short-lived credentials | 5-minute access tokens |
| Default deny | OPA policy defaults to deny; OPA unreachable = deny |
| Continuous monitoring | SIEM with 14 MITRE ATT&CK detection rules |
| Phishing-resistant auth | WebAuthn/Passkey support via Keycloak |

## Troubleshooting

**Keycloak slow to start:**
Keycloak requires ~90 seconds on first boot for JVM warmup and realm import. Monitor with:
```bash
docker compose logs -f keycloak
```

**Out of memory:**
The environment is optimized for 4 GB RAM. If containers are being OOM-killed, stop unused services:
```bash
docker compose stop siem-lite vulnerable-app
```

**Port conflicts:**
If ports 3000, 5000, 8080, 8181, 8888, or 5601 are in use, stop the conflicting services or modify the port mappings in `docker-compose.yml`.

**Check service health:**
```bash
docker compose ps
curl http://localhost:8080/health/ready   # Keycloak
curl http://localhost:8181/health          # OPA
curl http://localhost:5000/api/health      # Backend API
curl http://localhost:5601/api/health      # SIEM
```
