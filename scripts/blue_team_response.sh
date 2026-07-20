#!/usr/bin/env bash
# =============================================================================
# blue_team_response.sh - Blue Team Incident Response Guide
# =============================================================================
# NIST SP 800-61r2 workflow: Detection -> Analysis -> Containment -> Documentation
# =============================================================================

set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

step_header() {
    echo ""
    echo -e "${BLUE}${BOLD}================================================================${NC}"
    echo -e "${BLUE}${BOLD}  STEP $1: $2${NC}"
    echo -e "${BLUE}${BOLD}================================================================${NC}"
    echo ""
}

# ==========================================================================
step_header "1" "DETECTION - Check SIEM Alerts"

echo -e "  ${BLUE}[ACTION]${NC} Open SIEM Dashboard: ${CYAN}http://localhost:5601${NC}"
echo ""
echo -e "  ${YELLOW}[DETECT]${NC} Key alert patterns to look for:"
echo -e "    -> Rule 100001: Brute force attack (5+ failures in 2 min)"
echo -e "    -> Rule 100003: Successful login after failures"
echo -e "    -> Rule 100010: Privilege escalation attempt"
echo -e "    -> Rule 100011: New user account created"
echo -e "    -> Rule 100020: Lateral movement detected"
echo -e "    -> Rule 100030: Data exfiltration attempt"
echo -e "    -> Rule 100040: API rate limit exceeded"
echo ""

echo -e "  ${BLUE}[ACTION]${NC} Checking SIEM for recent alerts..."
curl -s http://localhost:5601/api/alerts?limit=5 2>/dev/null | python3 -m json.tool 2>/dev/null || echo -e "  ${CYAN}[INFO]${NC} Alerts will appear in the SIEM Dashboard"

# ==========================================================================
step_header "2" "ANALYSIS - Investigate the Attack"

echo -e "  ${BLUE}[ACTION]${NC} Checking Keycloak login events..."
docker logs zt-keycloak 2>&1 | grep -i "LOGIN_ERROR\|WARN\|ERROR" | tail -10 2>/dev/null || echo -e "  ${CYAN}[INFO]${NC} Check Keycloak Admin > Events tab"
echo ""

echo -e "  ${BLUE}[ACTION]${NC} Checking vulnerable app logs..."
docker logs zt-vulnerable-app 2>&1 | grep -i "security\|warning\|critical" | tail -15 2>/dev/null || echo -e "  ${CYAN}[INFO]${NC} Vulnerable app may not be running"
echo ""

echo -e "  ${BLUE}[ACTION]${NC} Checking active network connections..."
for container in zt-keycloak zt-backend-api zt-vulnerable-app; do
    CONNS=$(docker exec "$container" sh -c "ss -tnp 2>/dev/null | grep -c ESTAB" 2>/dev/null || echo "N/A")
    echo -e "  ${YELLOW}[DETECT]${NC} Active connections on ${container}: ${CONNS}"
done

# ==========================================================================
step_header "3" "CONTAINMENT - Limit the Damage"

echo -e "  ${CYAN}[INFO]${NC} Commands shown but NOT auto-executed for safety."
echo ""

echo -e "  ${BLUE}[ACTION]${NC} Isolate compromised containers:"
echo -e "  ${CYAN}\$${NC} docker network disconnect zero-trust-lab_zt-dmz zt-vulnerable-app"
echo -e "  ${CYAN}\$${NC} docker stop zt-vulnerable-app"
echo ""

echo -e "  ${BLUE}[ACTION]${NC} Rotate compromised credentials:"
echo -e "  ${CYAN}\$${NC} # Rotate all API keys and database passwords"
echo -e "  ${CYAN}\$${NC} # Revoke compromised Keycloak tokens"
echo -e "  ${CYAN}\$${NC} # Force password reset for affected users"
echo ""

echo -e "  ${BLUE}[ACTION]${NC} Preserve evidence:"
echo -e "  ${CYAN}\$${NC} docker commit zt-vulnerable-app evidence-vuln-app:\$(date +%Y%m%d)"
echo -e "  ${CYAN}\$${NC} docker logs zt-vulnerable-app > /tmp/vuln-app-evidence.log 2>&1"

# ==========================================================================
step_header "4" "DOCUMENTATION - Incident Report"

echo -e "${BLUE}${BOLD}"
cat << 'REPORT'
+================================================================+
|                    INCIDENT REPORT                              |
+================================================================+
|                                                                 |
|  Date:       ____-__-__                                         |
|  Severity:   [ ] Critical  [ ] High  [ ] Medium  [ ] Low       |
|  Analyst:    _______________________                            |
|                                                                 |
+-----------------------------------------------------------------+
|  VULNERABILITIES IDENTIFIED                                     |
+-----------------------------------------------------------------+
|  [ ] CWE-489  - Debug endpoint exposed                         |
|  [ ] CWE-284  - Broken access control (OWASP A01)              |
|  [ ] CWE-918  - Server-side request forgery (OWASP A10)        |
|  [ ] CWE-78   - Command injection (OWASP A03)                  |
|  [ ] CWE-312  - Credential exposure in responses               |
|                                                                 |
+-----------------------------------------------------------------+
|  MITRE ATT&CK TECHNIQUES DETECTED                              |
+-----------------------------------------------------------------+
|  [ ] T1595  - Active Scanning                                   |
|  [ ] T1190  - Exploit Public-Facing Application                 |
|  [ ] T1548  - Privilege Escalation                              |
|  [ ] T1552  - Unsecured Credentials                             |
|  [ ] T1059  - Command Injection                                 |
|                                                                 |
+-----------------------------------------------------------------+
|  REMEDIATION REQUIRED                                           |
+-----------------------------------------------------------------+
|  [ ] Remove debug endpoint from production                      |
|  [ ] Implement proper RBAC (not just token existence check)     |
|  [ ] Add input validation for SSRF prevention                   |
|  [ ] Sanitize all user inputs against injection                 |
|  [ ] Move credentials to vault (e.g. HashiCorp Vault)           |
|  [ ] Implement Zero Trust: Keycloak + OPA for all endpoints     |
|                                                                 |
+================================================================+
REPORT
echo -e "${NC}"

# ==========================================================================
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo -e "${GREEN}${BOLD}  HOW ZERO TRUST MITIGATES EACH ATTACK${NC}"
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo ""
echo -e "  ${BOLD}Attack${NC}                    ${BOLD}Zero Trust Mitigation${NC}"
echo -e "  -------------------------  --------------------------------"
echo -e "  Reconnaissance            Network segmentation limits"
echo -e "   (T1595)                   visible attack surface"
echo ""
echo -e "  Auth Bypass               Keycloak enforces identity at"
echo -e "   (T1190)                   every request; OPA validates tokens"
echo ""
echo -e "  Privilege Escalation      OPA policies enforce least-privilege"
echo -e "   (T1548)                   RBAC checked on every API call"
echo ""
echo -e "  Credential Theft          Secrets never in responses;"
echo -e "   (T1552)                   Short-lived tokens; vault storage"
echo ""
echo -e "  SSRF                      Backend network isolated;"
echo -e "   (T1190)                   Egress filtering blocks internal access"
echo ""
echo -e "  Command Injection         Input validation + WAF;"
echo -e "   (T1059)                   Containers run as non-root"
echo ""
echo -e "  ${BOLD}Continuous Monitoring${NC}      SIEM detects and alerts on"
echo -e "                             all suspicious activity in real-time"
echo ""
echo -e "  ${BLUE}${BOLD}Core Zero Trust Principles Applied:${NC}"
echo -e "    1. Never trust, always verify  - Keycloak authenticates every request"
echo -e "    2. Least privilege access       - OPA enforces minimal permissions"
echo -e "    3. Assume breach               - Segmentation limits blast radius"
echo -e "    4. Continuous monitoring        - SIEM provides real-time detection"
echo ""
