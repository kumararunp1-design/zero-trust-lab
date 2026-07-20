#!/usr/bin/env bash
# =============================================================================
# network_map.sh - Zero Trust Lab Network Topology Visualization
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

header() {
    echo ""
    echo -e "${BLUE}${BOLD}============================================================${NC}"
    echo -e "${BLUE}${BOLD}  $1${NC}"
    echo -e "${BLUE}${BOLD}============================================================${NC}"
}

ok()   { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "  ${RED}[BLOCKED]${NC} $1"; }

header "ZERO TRUST LAB - NETWORK TOPOLOGY"

echo -e "
${BOLD}Network Segments:${NC}
  ${GREEN}[zt-frontend]${NC}   172.20.1.0/24 - DMZ / User-facing
  ${YELLOW}[zt-backend]${NC}    172.20.2.0/24 - Application tier
  ${BLUE}[zt-monitoring]${NC} 172.20.3.0/24 - Security monitoring
  ${RED}[zt-dmz]${NC}        172.20.4.0/24 - Isolated / Vulnerable apps
"

header "CONTAINER-TO-NETWORK ASSIGNMENTS"

echo -e "
  ${CYAN}Container${NC}              ${CYAN}Networks${NC}
  zt-keycloak            zt-frontend (172.20.1.10) + zt-backend (172.20.2.10)
  zt-frontend-app        zt-frontend (172.20.1.20)
  zt-backend-api         zt-backend  (172.20.2.30)
  zt-opa                 zt-backend  (172.20.2.20)
  zt-siem-lite           zt-monitoring (172.20.3.10) + zt-backend (172.20.2.40)
  zt-vulnerable-app      zt-dmz (172.20.4.10) + zt-monitoring (172.20.3.40)
"

header "ALLOWED COMMUNICATION PATHS"

echo -e "  ${GREEN}[ALLOWED]${NC} Frontend     --> Keycloak    (via zt-frontend) [Authentication]"
echo -e "  ${GREEN}[ALLOWED]${NC} Backend API  --> Keycloak    (via zt-backend)  [Token validation]"
echo -e "  ${GREEN}[ALLOWED]${NC} Backend API  --> OPA         (via zt-backend)  [Policy check]"
echo -e "  ${GREEN}[ALLOWED]${NC} SIEM Lite    --> Backend     (via zt-backend)  [Log collection]"
echo -e "  ${GREEN}[ALLOWED]${NC} Vulnerable   --> SIEM Lite   (via zt-monitoring) [Log forwarding]"

header "BLOCKED COMMUNICATION PATHS"

echo -e "  ${RED}[BLOCKED]${NC} Frontend  -X-> Backend API   (different networks)"
echo -e "  ${RED}[BLOCKED]${NC} Frontend  -X-> OPA           (different networks)"
echo -e "  ${RED}[BLOCKED]${NC} OPA       -X-> Frontend      (different networks)"
echo -e "  ${RED}[BLOCKED]${NC} Vuln App  -X-> Backend API   (different networks)"
echo -e "  ${RED}[BLOCKED]${NC} Vuln App  -X-> Keycloak FE   (different networks)"

header "LIVE CONNECTIVITY TESTS"

echo -e "${YELLOW}Running connectivity probes between containers...${NC}"
echo ""

test_connection() {
    local from=$1
    local to_ip=$2
    local to_port=$3
    local label=$4
    local expected=$5

    result=$(docker exec "$from" wget -q -O /dev/null --timeout=3 "http://${to_ip}:${to_port}/" 2>&1 && echo "REACHABLE" || echo "UNREACHABLE")

    if [[ "$result" == *"REACHABLE"* ]]; then
        if [[ "$expected" == "pass" ]]; then
            ok "$label (reachable - expected)"
        else
            echo -e "  ${RED}[BREACH!]${NC} $label (reachable - UNEXPECTED!)"
        fi
    else
        if [[ "$expected" == "fail" ]]; then
            ok "$label (blocked - expected)"
        else
            fail "$label (blocked - UNEXPECTED)"
        fi
    fi
}

echo -e "${CYAN}--- Same-segment tests (should PASS) ---${NC}"
test_connection "zt-frontend-app" "172.20.1.10" "8080" "Frontend -> Keycloak" "pass"
test_connection "zt-backend-api"  "172.20.2.10" "8080" "Backend  -> Keycloak" "pass"
test_connection "zt-backend-api"  "172.20.2.20" "8181" "Backend  -> OPA"      "pass"

echo ""
echo -e "${CYAN}--- Cross-segment tests (should FAIL) ---${NC}"
test_connection "zt-frontend-app" "172.20.2.30" "5000" "Frontend -> Backend (cross-seg)" "fail"
test_connection "zt-frontend-app" "172.20.2.20" "8181" "Frontend -> OPA (cross-seg)"     "fail"
test_connection "zt-opa"          "172.20.1.20" "3000" "OPA      -> Frontend (cross-seg)" "fail"

header "SUMMARY"

echo -e "  ${BOLD}Total Networks:${NC}      4"
echo -e "  ${BOLD}Total Containers:${NC}    6"
echo -e "  ${BOLD}Multi-homed:${NC}         Keycloak (frontend+backend)"
echo -e "                       SIEM Lite (monitoring+backend)"
echo -e "                       Vulnerable App (dmz+monitoring)"
echo ""
echo -e "  ${GREEN}Zero Trust Principle:${NC} Default deny between segments."
echo -e "  Each container only reaches what it strictly needs."
echo ""
