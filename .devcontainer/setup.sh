#!/usr/bin/env bash
# =============================================================================
# Zero Trust Lab - GitHub Codespaces Setup Script
# =============================================================================
# Automatically provisions the lab environment in GitHub Codespaces.
# Uses lightweight SIEM (siem-lite) instead of Wazuh to fit within
# Codespaces memory limits (~4-8 GB).
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${GREEN}[SETUP]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; }

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  Zero Trust Lab - GitHub Codespaces Setup${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

# ---------------------------------------------------------------------------
# Check available RAM
# ---------------------------------------------------------------------------
TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
info "Available RAM: ${TOTAL_RAM_MB} MB"

# ---------------------------------------------------------------------------
# Wait for Docker to be ready
# ---------------------------------------------------------------------------
log "Waiting for Docker daemon..."
RETRIES=30
while ! docker info > /dev/null 2>&1; do
    RETRIES=$((RETRIES - 1))
    if (( RETRIES == 0 )); then
        err "Docker daemon not available after 30 seconds"
        exit 1
    fi
    sleep 1
done
log "Docker is ready"

# ---------------------------------------------------------------------------
# Navigate to lab directory
# ---------------------------------------------------------------------------
# In Codespaces the repo is cloned under /workspaces/<repo-name>
cd "$(dirname "$0")/.." || cd /workspaces/zero-trust-lab 2>/dev/null

log "Working directory: $(pwd)"

# ---------------------------------------------------------------------------
# Build and start all services
# ---------------------------------------------------------------------------
log "Starting lab deployment (6 services: Keycloak, OPA, Backend, Frontend, Vulnerable App, SIEM)..."

docker compose build --quiet 2>&1 | tail -5 || true
docker compose up -d

# ---------------------------------------------------------------------------
# Wait for services to be healthy
# ---------------------------------------------------------------------------
log "Waiting for services to start (this takes 1-2 minutes)..."
echo ""

wait_for_service() {
    local name=$1
    local url=$2
    local max_wait=$3
    local elapsed=0

    printf "  Waiting for %-20s" "$name..."
    while ! curl -sf -o /dev/null --max-time 3 "$url" 2>/dev/null; do
        elapsed=$((elapsed + 3))
        if (( elapsed >= max_wait )); then
            echo -e " ${YELLOW}SLOW (may still be starting)${NC}"
            return 1
        fi
        sleep 3
    done
    echo -e " ${GREEN}READY${NC}"
    return 0
}

wait_for_service "Keycloak" "http://localhost:8080/health/ready" 180 || warn "Keycloak may still be starting - it needs ~90s on first boot"
wait_for_service "OPA" "http://localhost:8181/health" 60 || true
wait_for_service "Backend API" "http://localhost:5000/api/health" 90 || true
wait_for_service "Frontend" "http://localhost:3000" 60 || true
wait_for_service "Vulnerable App" "http://localhost:8888" 60 || true
wait_for_service "SIEM Dashboard" "http://localhost:5601/api/health" 60 || true

# ---------------------------------------------------------------------------
# Configure Keycloak redirect URIs for Codespaces
# ---------------------------------------------------------------------------
CODESPACE_NAME="${CODESPACE_NAME:-}"
GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN="${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-app.github.dev}"

if [[ -n "$CODESPACE_NAME" ]]; then
    log "Configuring Keycloak redirect URIs for Codespaces..."
    SUFFIX="${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}"
    CS_FRONTEND="https://${CODESPACE_NAME}-3000.${SUFFIX}"

    # Get admin token
    KC_TOKEN=$(curl -sf -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=admin-cli" \
        -d "username=admin" \
        -d "password=admin123" \
        -d "grant_type=password" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null) || true

    if [[ -n "$KC_TOKEN" ]]; then
        # Find the zt-frontend client ID (UUID)
        CLIENT_UUID=$(curl -sf -H "Authorization: Bearer $KC_TOKEN" \
            "http://localhost:8080/admin/realms/zero-trust-lab/clients?clientId=zt-frontend" \
            | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null) || true

        if [[ -n "$CLIENT_UUID" ]]; then
            # Update redirect URIs with exact Codespaces URLs
            curl -sf -X PUT \
                -H "Authorization: Bearer $KC_TOKEN" \
                -H "Content-Type: application/json" \
                "http://localhost:8080/admin/realms/zero-trust-lab/clients/$CLIENT_UUID" \
                -d "{
                    \"redirectUris\": [\"http://localhost:3000/*\", \"${CS_FRONTEND}/*\"],
                    \"webOrigins\": [\"http://localhost:3000\", \"${CS_FRONTEND}\"],
                    \"attributes\": {
                        \"post.logout.redirect.uris\": \"http://localhost:3000/*##${CS_FRONTEND}/*\"
                    }
                }" > /dev/null 2>&1 && log "Keycloak redirect URIs updated for ${CS_FRONTEND}" \
                || warn "Could not update Keycloak redirect URIs (non-critical)"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Print access information
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  Lab Environment Ready!${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

if [[ -n "$CODESPACE_NAME" ]]; then
    echo -e "  ${BOLD}Service URLs (click to open in browser):${NC}"
    echo -e "  ${CYAN}Frontend:${NC}       https://${CODESPACE_NAME}-3000.${SUFFIX}"
    echo -e "  ${CYAN}Backend API:${NC}    https://${CODESPACE_NAME}-5000.${SUFFIX}"
    echo -e "  ${CYAN}Keycloak:${NC}       https://${CODESPACE_NAME}-8080.${SUFFIX}"
    echo -e "  ${CYAN}OPA:${NC}            https://${CODESPACE_NAME}-8181.${SUFFIX}"
    echo -e "  ${CYAN}Vulnerable App:${NC} https://${CODESPACE_NAME}-8888.${SUFFIX}"
    echo -e "  ${CYAN}SIEM Dashboard:${NC} https://${CODESPACE_NAME}-5601.${SUFFIX}"
    echo -e "  ${CYAN}Passkey Demo:${NC}   https://${CODESPACE_NAME}-3000.${SUFFIX}/passkey"
else
    echo -e "  ${BOLD}Service URLs:${NC}"
    echo -e "  ${CYAN}Frontend:${NC}       http://localhost:3000"
    echo -e "  ${CYAN}Backend API:${NC}    http://localhost:5000"
    echo -e "  ${CYAN}Keycloak:${NC}       http://localhost:8080"
    echo -e "  ${CYAN}OPA:${NC}            http://localhost:8181"
    echo -e "  ${CYAN}Vulnerable App:${NC} http://localhost:8888"
    echo -e "  ${CYAN}SIEM Dashboard:${NC} http://localhost:5601"
    echo -e "  ${CYAN}Passkey Demo:${NC}   http://localhost:3000/passkey"
fi

echo ""
echo -e "  ${BOLD}Credentials:${NC}"
echo -e "  Keycloak Admin:   admin / admin123"
echo -e "  Lab User Alice:   alice / alice123  (role: admin)"
echo -e "  Lab User Bob:     bob / bob123      (role: analyst)"
echo -e "  Lab User Charlie: charlie / charlie123 (role: developer)"
echo ""
echo -e "  ${BOLD}RAM Available:${NC}   ${TOTAL_RAM_MB} MB"
echo ""
echo -e "  ${GREEN}You can now follow the lab instructions!${NC}"
echo -e "  ${GREEN}All scripts are in the ./scripts/ directory.${NC}"
echo ""
