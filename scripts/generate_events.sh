#!/usr/bin/env bash
# =============================================================================
# generate_events.sh - Security Event Generator for Zero Trust Lab
# =============================================================================
# Simulates attack patterns to generate alerts in the SIEM Dashboard:
#   1. Brute-force login attempts against Keycloak
#   2. Successful login after failures
#   3. API abuse via rapid requests
#   4. System-level events (SSH failures, sudo, user creation)
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SIEM_URL="http://localhost:5601"

header() {
    echo ""
    echo -e "${YELLOW}${BOLD}============================================================${NC}"
    echo -e "${YELLOW}${BOLD}  $1${NC}"
    echo -e "${YELLOW}${BOLD}============================================================${NC}"
    echo ""
}

# ==========================================================================
header "PHASE 1: BRUTE-FORCE LOGIN SIMULATION"

echo -e "  ${CYAN}[*]${NC} Sending 10 failed login attempts to Keycloak..."
echo ""

for i in $(seq 1 10); do
    curl -s -o /dev/null -X POST \
        "http://localhost:8080/realms/zero-trust-lab/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=zt-frontend" \
        -d "username=alice" \
        -d "password=wrongpassword${i}" \
        -d "grant_type=password" 2>/dev/null || true
    echo -e "  ${RED}[-]${NC} Failed login attempt $i/10"
    sleep 0.3
done

echo -e "  ${GREEN}[+]${NC} Brute-force simulation complete"

# ==========================================================================
header "PHASE 2: SUCCESSFUL LOGIN AFTER FAILURES"

echo -e "  ${CYAN}[*]${NC} Attempting login with valid credentials..."
curl -s -o /dev/null -X POST \
    "http://localhost:8080/realms/zero-trust-lab/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=zt-frontend" \
    -d "username=alice" \
    -d "password=alice123" \
    -d "grant_type=password" 2>/dev/null || true
echo -e "  ${GREEN}[+]${NC} Successful login after brute-force"

# ==========================================================================
header "PHASE 3: API ABUSE - RAPID REQUEST FLOODING"

echo -e "  ${CYAN}[*]${NC} Sending 25 rapid API requests..."
for i in $(seq 1 25); do
    curl -s -o /dev/null http://localhost:5000/api/health 2>/dev/null || true
done
echo -e "  ${GREEN}[+]${NC} 25 rapid API requests sent"

# ==========================================================================
header "PHASE 4: SYSTEM EVENT GENERATION (via SIEM Ingest API)"

echo -e "  ${CYAN}[*]${NC} Injecting simulated events into SIEM..."
echo ""

# SSH failure events
echo -e "  ${RED}[-]${NC} Generating SSH authentication failures..."
for i in $(seq 1 5); do
    curl -s -o /dev/null -X POST "${SIEM_URL}/api/ingest" \
        -H "Content-Type: application/json" \
        -d "{\"source\": \"syslog/simulated\", \"message\": \"Failed password for invalid user attacker${i} from 192.168.1.$((RANDOM % 254 + 1)) port 22 ssh2\"}" 2>/dev/null || true
done

# Sudo attempt
echo -e "  ${RED}[-]${NC} Generating unauthorized sudo attempt..."
curl -s -o /dev/null -X POST "${SIEM_URL}/api/ingest" \
    -H "Content-Type: application/json" \
    -d '{"source": "syslog/simulated", "message": "hacker : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/hacker ; USER=root ; COMMAND=/bin/bash"}' 2>/dev/null || true

# User creation
echo -e "  ${RED}[-]${NC} Generating suspicious user creation..."
curl -s -o /dev/null -X POST "${SIEM_URL}/api/ingest" \
    -H "Content-Type: application/json" \
    -d '{"source": "syslog/simulated", "message": "useradd: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor"}' 2>/dev/null || true

# Lateral movement
echo -e "  ${RED}[-]${NC} Generating lateral movement event..."
curl -s -o /dev/null -X POST "${SIEM_URL}/api/ingest" \
    -H "Content-Type: application/json" \
    -d '{"source": "syslog/simulated", "message": "Lateral movement detected: ssh from internal host 172.20.2.30 to 172.20.4.10 via pivot"}' 2>/dev/null || true

# Network scan
echo -e "  ${RED}[-]${NC} Generating network scan event..."
curl -s -o /dev/null -X POST "${SIEM_URL}/api/ingest" \
    -H "Content-Type: application/json" \
    -d '{"source": "syslog/simulated", "message": "nmap SYN scan detected from 192.168.1.100 against 172.20.0.0/16 - 1000 ports scanned"}' 2>/dev/null || true

# Data exfiltration
echo -e "  ${RED}[-]${NC} Generating data exfiltration event..."
curl -s -o /dev/null -X POST "${SIEM_URL}/api/ingest" \
    -H "Content-Type: application/json" \
    -d '{"source": "syslog/simulated", "message": "Data exfiltration attempt: curl upload to external pastebin detected from 172.20.4.10"}' 2>/dev/null || true

# ==========================================================================
header "EVENT GENERATION SUMMARY"

echo -e "  ${BOLD}Events Generated:${NC}"
echo -e "    ${RED}Brute-force attempts:${NC}     10 failed logins"
echo -e "    ${GREEN}Post-brute login:${NC}         1 successful authentication"
echo -e "    ${YELLOW}API abuse requests:${NC}       25 rapid requests"
echo -e "    ${RED}SSH failures:${NC}             5 events"
echo -e "    ${RED}Sudo violations:${NC}          1 event"
echo -e "    ${RED}Suspicious user creation:${NC} 1 event"
echo -e "    ${RED}Lateral movement:${NC}         1 event"
echo -e "    ${RED}Network scan:${NC}             1 event"
echo -e "    ${RED}Data exfiltration:${NC}        1 event"
echo ""
echo -e "  ${CYAN}${BOLD}Next Steps:${NC}"
echo -e "    1. Open SIEM Dashboard: ${CYAN}http://localhost:5601${NC}"
echo -e "    2. View the Security Alerts tab"
echo -e "    3. Check MITRE ATT&CK technique mappings in the sidebar"
echo ""
