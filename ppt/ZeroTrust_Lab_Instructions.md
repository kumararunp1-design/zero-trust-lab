# Cybersecurity & Zero Trust Architecture - Hands-On Lab

## Industry Connect Program | Faculty Development Workshop

**Duration:** 2 Hours (120 Minutes)  
**Prerequisites:** Docker Desktop installed, 8GB+ RAM, terminal access  
**Difficulty:** Intermediate  

---

## Lab Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Zero Trust Lab Environment                        │
│                                                                      │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐            │
│  │   Keycloak    │   │  OPA Policy  │   │   Wazuh      │            │
│  │   (IdP)       │◄─►│   Engine     │   │   SIEM       │            │
│  │  Port: 8080   │   │  Port: 8181  │   │ Port: 443/55000│          │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘            │
│         │                  │                    │                     │
│  ┌──────▼───────┐   ┌──────▼───────┐   ┌──────▼───────┐            │
│  │  Frontend     │   │  Backend API │   │  Vulnerable   │            │
│  │  App          │◄─►│  (Protected) │   │  Target App   │            │
│  │  Port: 3000   │   │  Port: 5000  │   │  Port: 8888   │            │
│  └──────────────┘   └──────────────┘   └──────────────┘            │
│                                                                      │
│  Networks: zt-frontend | zt-backend | zt-monitoring | zt-dmz        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Lab Setup (15 Minutes)

### Step 1: Create Project Directory

```bash
mkdir -p zero-trust-lab/{keycloak,opa,wazuh,apps,scripts}
cd zero-trust-lab
```

### Step 2: Create Docker Compose File

Create `docker-compose.yml`:

```yaml
version: '3.8'

# ============================================================
# Zero Trust Lab - Docker Compose
# Networks simulate micro-segmented enterprise environment
# ============================================================

networks:
  zt-frontend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.1.0/24
  zt-backend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.2.0/24
  zt-monitoring:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.3.0/24
  zt-dmz:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.4.0/24

services:
  # ============================================================
  # Identity Provider - Keycloak (OIDC/OAuth2)
  # ============================================================
  keycloak:
    image: quay.io/keycloak/keycloak:24.0
    container_name: zt-keycloak
    command: start-dev --import-realm
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin123
      KC_HEALTH_ENABLED: true
    ports:
      - "8080:8080"
    volumes:
      - ./keycloak/realm-export.json:/opt/keycloak/data/import/realm-export.json
    networks:
      zt-frontend:
        ipv4_address: 172.20.1.10
      zt-backend:
        ipv4_address: 172.20.2.10
    healthcheck:
      test: ["CMD-SHELL", "exec 3<>/dev/tcp/localhost/8080 && echo -e 'GET /health/ready HTTP/1.1\r\nHost: localhost\r\n\r\n' >&3 && cat <&3 | grep -q '200'"]
      interval: 10s
      timeout: 5s
      retries: 20

  # ============================================================
  # Policy Engine - Open Policy Agent (OPA)
  # ============================================================
  opa:
    image: openpolicyagent/opa:0.64.0
    container_name: zt-opa
    command:
      - run
      - --server
      - --addr=0.0.0.0:8181
      - --log-level=info
      - /policies
    ports:
      - "8181:8181"
    volumes:
      - ./opa/policies:/policies
    networks:
      zt-backend:
        ipv4_address: 172.20.2.20

  # ============================================================
  # Protected Backend API (Flask)
  # ============================================================
  backend-api:
    build:
      context: ./apps/backend
      dockerfile: Dockerfile
    container_name: zt-backend-api
    environment:
      KEYCLOAK_URL: http://172.20.2.10:8080
      OPA_URL: http://172.20.2.20:8181
      KEYCLOAK_REALM: zero-trust-lab
      FLASK_ENV: development
    ports:
      - "5000:5000"
    networks:
      zt-backend:
        ipv4_address: 172.20.2.30
    depends_on:
      keycloak:
        condition: service_healthy

  # ============================================================
  # Frontend Application
  # ============================================================
  frontend:
    build:
      context: ./apps/frontend
      dockerfile: Dockerfile
    container_name: zt-frontend-app
    environment:
      BACKEND_URL: http://172.20.2.30:5000
      KEYCLOAK_URL: http://localhost:8080
    ports:
      - "3000:3000"
    networks:
      zt-frontend:
        ipv4_address: 172.20.1.20
    depends_on:
      - backend-api

  # ============================================================
  # Wazuh Manager (SIEM)
  # ============================================================
  wazuh-manager:
    image: wazuh/wazuh-manager:4.8.0
    container_name: zt-wazuh-manager
    environment:
      INDEXER_URL: https://172.20.3.20:9200
      INDEXER_USERNAME: admin
      INDEXER_PASSWORD: SecretPassword
      FILEBEAT_SSL_VERIFICATION_MODE: none
      API_USERNAME: wazuh-wui
      API_PASSWORD: MyS3cr3tP4ssw0rd
    ports:
      - "1514:1514"
      - "1515:1515"
      - "514:514/udp"
      - "55000:55000"
    volumes:
      - ./wazuh/ossec.conf:/var/ossec/etc/ossec.conf
      - ./wazuh/rules:/var/ossec/etc/rules
      - wazuh-api-configuration:/var/ossec/api/configuration
      - wazuh-etc:/var/ossec/etc
      - wazuh-logs:/var/ossec/logs
      - wazuh-queue:/var/ossec/queue
    networks:
      zt-monitoring:
        ipv4_address: 172.20.3.10
      zt-backend:
        ipv4_address: 172.20.2.40

  # ============================================================
  # Wazuh Indexer (OpenSearch)
  # ============================================================
  wazuh-indexer:
    image: wazuh/wazuh-indexer:4.8.0
    container_name: zt-wazuh-indexer
    environment:
      OPENSEARCH_JAVA_OPTS: "-Xms512m -Xmx512m"
      bootstrap.memory_lock: "true"
      discovery.type: single-node
      plugins.security.ssl.http.enabled: "false"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - wazuh-indexer-data:/var/lib/wazuh-indexer
    networks:
      zt-monitoring:
        ipv4_address: 172.20.3.20

  # ============================================================
  # Wazuh Dashboard
  # ============================================================
  wazuh-dashboard:
    image: wazuh/wazuh-dashboard:4.8.0
    container_name: zt-wazuh-dashboard
    environment:
      INDEXER_USERNAME: admin
      INDEXER_PASSWORD: SecretPassword
      WAZUH_API_URL: https://172.20.3.10
      DASHBOARD_USERNAME: kibanaserver
      DASHBOARD_PASSWORD: kibanaserver
      API_USERNAME: wazuh-wui
      API_PASSWORD: MyS3cr3tP4ssw0rd
    ports:
      - "443:5601"
    depends_on:
      - wazuh-indexer
      - wazuh-manager
    networks:
      zt-monitoring:
        ipv4_address: 172.20.3.30

  # ============================================================
  # Vulnerable Target App (for Red Team exercise)
  # ============================================================
  vulnerable-app:
    build:
      context: ./apps/vulnerable
      dockerfile: Dockerfile
    container_name: zt-vulnerable-app
    ports:
      - "8888:8888"
    networks:
      zt-dmz:
        ipv4_address: 172.20.4.10
      zt-monitoring:
        ipv4_address: 172.20.3.40

volumes:
  wazuh-api-configuration:
  wazuh-etc:
  wazuh-logs:
  wazuh-queue:
  wazuh-indexer-data:
```

### Step 3: Verify Docker Setup

```bash
docker --version
docker compose version
```

Expected output: Docker 24+ and Docker Compose v2+

---

## Lab 1: OIDC/OAuth2 Identity Provider Setup (20 Minutes)

### Industry Context
> **Real-World Parallel:** This lab replicates what companies like Okta, Auth0, and Azure AD provide as a service. Keycloak is the open-source alternative used by government agencies, universities, and enterprises including the German federal government and the US Army.

### Learning Objectives
- Configure an OIDC Identity Provider from scratch
- Understand realms, clients, roles, and user federation
- Implement the OAuth 2.1 Authorization Code flow with PKCE
- Configure Multi-Factor Authentication (TOTP)

### Step 1.1: Create Keycloak Realm Configuration

Create `keycloak/realm-export.json`:

```json
{
  "realm": "zero-trust-lab",
  "enabled": true,
  "sslRequired": "none",
  "registrationAllowed": false,
  "bruteForceProtected": true,
  "failureFactor": 5,
  "permanentLockout": false,
  "maxFailureWaitSeconds": 300,
  "minimumQuickLoginWaitSeconds": 60,
  "waitIncrementSeconds": 60,
  "roles": {
    "realm": [
      {
        "name": "admin",
        "description": "Full system administrator"
      },
      {
        "name": "analyst",
        "description": "SOC analyst with read access"
      },
      {
        "name": "developer",
        "description": "Developer with limited access"
      },
      {
        "name": "auditor",
        "description": "Read-only audit access"
      }
    ]
  },
  "users": [
    {
      "username": "alice",
      "enabled": true,
      "email": "alice@zerotrust.lab",
      "firstName": "Alice",
      "lastName": "Admin",
      "credentials": [
        {
          "type": "password",
          "value": "alice123",
          "temporary": false
        }
      ],
      "realmRoles": ["admin"]
    },
    {
      "username": "bob",
      "enabled": true,
      "email": "bob@zerotrust.lab",
      "firstName": "Bob",
      "lastName": "Analyst",
      "credentials": [
        {
          "type": "password",
          "value": "bob123",
          "temporary": false
        }
      ],
      "realmRoles": ["analyst"]
    },
    {
      "username": "charlie",
      "enabled": true,
      "email": "charlie@zerotrust.lab",
      "firstName": "Charlie",
      "lastName": "Developer",
      "credentials": [
        {
          "type": "password",
          "value": "charlie123",
          "temporary": false
        }
      ],
      "realmRoles": ["developer"]
    }
  ],
  "clients": [
    {
      "clientId": "zt-frontend",
      "enabled": true,
      "publicClient": true,
      "redirectUris": ["http://localhost:3000/*"],
      "webOrigins": ["http://localhost:3000"],
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": false,
      "protocol": "openid-connect",
      "attributes": {
        "pkce.code.challenge.method": "S256",
        "post.logout.redirect.uris": "http://localhost:3000/*"
      },
      "defaultClientScopes": [
        "openid",
        "profile",
        "email",
        "roles"
      ]
    },
    {
      "clientId": "zt-backend",
      "enabled": true,
      "publicClient": false,
      "secret": "backend-secret-change-me",
      "bearerOnly": true,
      "protocol": "openid-connect"
    }
  ],
  "components": {
    "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy": [
      {
        "name": "Allowed Protocol Mapper Types",
        "providerId": "allowed-protocol-mappers",
        "subType": "authenticated",
        "config": {
          "allowed-protocol-mapper-types": [
            "oidc-full-name-mapper",
            "oidc-usermodel-attribute-mapper",
            "oidc-usermodel-property-mapper"
          ]
        }
      }
    ]
  },
  "browserSecurityHeaders": {
    "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
    "xContentTypeOptions": "nosniff",
    "xRobotsTag": "none",
    "xFrameOptions": "SAMEORIGIN",
    "strictTransportSecurity": "max-age=31536000; includeSubDomains"
  }
}
```

### Step 1.2: Start Keycloak

```bash
docker compose up keycloak -d
# Wait for Keycloak to be healthy (1-2 minutes)
docker compose logs -f keycloak | grep -i "started"
```

### Step 1.3: Explore Keycloak Admin Console

1. Open browser: `http://localhost:8080/admin`
2. Login: `admin` / `admin123`
3. Navigate to the **zero-trust-lab** realm
4. Explore:
   - **Users**: See alice (admin), bob (analyst), charlie (developer)
   - **Clients**: See zt-frontend (public, PKCE), zt-backend (bearer-only)
   - **Realm Roles**: admin, analyst, developer, auditor

### Step 1.4: Test OIDC Token Issuance

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

### Step 1.5: Decode the JWT Token

```bash
# Save token to variable
TOKEN=$(curl -s -X POST "http://localhost:8080/realms/zero-trust-lab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=zt-frontend" \
  -d "username=alice" \
  -d "password=alice123" \
  -d "grant_type=password" \
  -d "scope=openid profile email" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Decode JWT payload (base64)
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

**Expected output:** You'll see the JWT claims including `sub`, `email`, `realm_access.roles`, `exp`, `iss`.

### Step 1.6: Configure MFA (TOTP)

1. In Keycloak Admin: Go to **Authentication** > **Flows**
2. Select **Browser** flow
3. Click on **OTP Form** and set to **Required**
4. Now when alice logs in, she'll be prompted to set up TOTP (Google Authenticator compatible)

### Exercise 1 Questions
1. **What claims are in the JWT token? Which ones are used for authorization?**
2. **Why is PKCE mandatory in OAuth 2.1? What attack does it prevent?**
3. **What happens if a token expires? How does the refresh token flow work?**

> **Industry Insight:** In 2024, the Okta breach showed that even IAM providers can be compromised. This is why defense-in-depth matters - IAM is just one layer of Zero Trust.

---

## Lab 1 Extension: Passkeys & WebAuthn (Optional - 15 Minutes)

### Industry Context
> **Real-World Adoption (2024-2025):** Apple, Google, and Microsoft have all shipped passkey support across their platforms. Google reports 50% fewer sign-in issues with passkeys. GitHub, AWS IAM, and Shopify now support passkeys for account login. NIST SP 800-63B-4 (draft) recommends phishing-resistant authenticators. This is the future of authentication - and it builds directly on the OIDC/OAuth2 foundations you just explored in Lab 1.

### Learning Objectives
- Understand how FIDO2/WebAuthn replaces passwords with asymmetric cryptography
- Experience the WebAuthn registration and authentication ceremonies
- See why passkeys are phishing-proof (origin-bound credentials)
- Configure Keycloak to support WebAuthn as a second factor
- Use Chrome's virtual authenticator (no physical hardware needed)

### Background: Passwords to Passkeys

| Generation | Method | Weakness |
|-----------|--------|----------|
| 1st | Passwords | Phishable, reusable, stored as hashes |
| 2nd | Passwords + TOTP/SMS MFA | Still phishable (real-time relay attacks) |
| 3rd | **Passkeys (FIDO2/WebAuthn)** | **Phishing-proof**, origin-bound, no shared secrets |

**How passkeys work:**
1. **Registration**: Browser generates an asymmetric keypair (ES256). Private key stays in the authenticator (TPM, Secure Enclave, or security key). Public key is sent to the server.
2. **Authentication**: Server sends a random challenge. Authenticator signs it with the private key (after biometric/PIN verification). Server verifies the signature with the stored public key.
3. **Phishing protection**: The credential is bound to the **origin** (e.g., `localhost`). A phishing site at `evil.com` cannot trigger the key for `localhost` - the browser enforces this.

### Step 1: Set Up Chrome Virtual Authenticator

No physical security key needed. Chrome DevTools provides a software authenticator:

1. Open Chrome and navigate to `http://localhost:3000/passkey`
2. Open DevTools: **F12** (or Ctrl+Shift+I / Cmd+Option+I)
3. Click the **...** (three-dot menu) in DevTools toolbar
4. Select **More tools** → **WebAuthn**
5. Check **"Enable virtual authenticator environment"**
6. Click **"Add"** to create a virtual authenticator with these settings:
   - **Protocol**: ctap2
   - **Transport**: internal
   - **Supports resident keys**: checked
   - **Supports user verification**: checked

```
┌──────────────────────────────────────────────────┐
│  Chrome DevTools → WebAuthn Panel                │
│                                                  │
│  [x] Enable virtual authenticator environment    │
│                                                  │
│  Virtual Authenticator #1                        │
│  Protocol: ctap2  Transport: internal            │
│  [x] Supports resident keys                     │
│  [x] Supports user verification                 │
│  Credentials: (none yet)                         │
└──────────────────────────────────────────────────┘
```

### Step 2: Interactive Passkey Demo

The demo page at `http://localhost:3000/passkey` provides a full interactive WebAuthn walkthrough:

**2a. Register a Passkey**

Click **"Register Passkey"** on the demo page. Under the hood, the browser calls:

```javascript
const credential = await navigator.credentials.create({
    publicKey: {
        challenge: serverChallenge,                    // Random bytes from server
        rp: { name: "Zero Trust Lab", id: "localhost" },
        user: {
            id: userId,                                // Opaque user handle
            name: "alice@zerotrust.lab",
            displayName: "Alice Admin"
        },
        pubKeyCredParams: [
            { type: "public-key", alg: -7 }            // ES256 (ECDSA w/ P-256)
        ],
        authenticatorSelection: {
            authenticatorAttachment: "platform",        // Built-in authenticator
            residentKey: "preferred",                   // Discoverable credential
            userVerification: "preferred"               // Biometric if available
        }
    }
});
// credential.response contains the PUBLIC key → sent to server
// Private key NEVER leaves the authenticator
```

Watch the **WebAuthn DevTools panel** - you'll see the credential appear with its ID and public key.

**2b. Authenticate with Passkey**

Click **"Authenticate with Passkey"**. The browser calls:

```javascript
const assertion = await navigator.credentials.get({
    publicKey: {
        challenge: newChallenge,        // Fresh random challenge
        rpId: "localhost",              // Must match registration origin
        allowCredentials: [{
            type: "public-key",
            id: credentialId             // From registration
        }],
        userVerification: "preferred"
    }
});
// assertion.response.signature → signed challenge, verified by server
```

**2c. Inspect the Credential**

Switch to the **"Inspect Credential"** tab to examine:
- The `clientDataJSON` showing origin binding (`"origin": "http://localhost:3000"`)
- The credential ID (base64url-encoded)
- The signature (proves possession of private key)
- The sign counter (increments each use - detects cloned authenticators)

### Step 3: Enable WebAuthn in Keycloak

The lab's Keycloak realm comes pre-configured with a WebAuthn authentication flow. Enable it:

1. Open Keycloak Admin Console: `http://localhost:8080/admin` (admin / admin123)
2. Select the **"zero-trust-lab"** realm
3. Navigate to **Authentication** → **Flows**
4. Find the **"browser-with-webauthn"** flow (pre-configured in the realm import)
5. Go to **Authentication** → **Bindings**
6. Change **Browser Flow** from "browser" to **"browser-with-webauthn"**
7. Click **Save**

Now test it:

```bash
# Open the frontend and try to log in
# After username/password, Keycloak will offer WebAuthn registration
open http://localhost:3000

# Login as alice (alice / alice123)
# You'll see the option to register a security key
# Chrome's virtual authenticator will handle the registration automatically
```

**What to observe:**
- After password login, Keycloak prompts to register a security key
- The virtual authenticator in DevTools handles the ceremony automatically
- On subsequent logins, Keycloak offers both password+WebAuthn or just password
- Check the Keycloak admin → Users → alice → Credentials tab to see the registered WebAuthn credential

### Step 4: Understand the Security Properties

Examine why this is phishing-proof by reviewing the credential data:

| Property | How It Prevents Attacks |
|----------|------------------------|
| **Origin binding** | Key bound to `localhost` - phishing site at `evil.com` cannot use it |
| **Challenge-response** | Fresh random challenge each time - replay attacks impossible |
| **No shared secrets** | Server only stores public key - database breach doesn't help attacker |
| **User verification** | Biometric/PIN required = inherent 2FA in a single gesture |
| **Sign counter** | Increments each use - detects if authenticator was cloned |

### Exercise 1 Extension Questions
1. **Why can't a phishing site at `https://evil-bank.com` use a passkey registered for `https://real-bank.com`?** (Hint: look at the `clientDataJSON.origin` field in the Inspect tab)
2. **What happens if a server's database is breached and all stored passkey data is stolen?** Can the attacker authenticate? Why or why not?
3. **Compare TOTP (Google Authenticator) vs. passkeys for phishing resistance.** Can a real-time phishing relay attack defeat TOTP? Can it defeat passkeys?
4. **What is the "sign counter" and how does it detect cloned authenticators?**

> **Industry Insight:** Google's internal data shows that passkeys are 4x faster than passwords and have a 50% lower sign-in failure rate. The FIDO Alliance reports that passkeys eliminate over 80% of credential-based attacks. Major enterprises (Shopify, Cloudflare, Coinbase) are rolling out passkeys as their primary authentication method in 2024-2025.

---

## Lab 2: Policy-Based Access Control with OPA (20 Minutes)

### Industry Context
> **Real-World Parallel:** Netflix uses OPA to authorize millions of API requests per second. Goldman Sachs uses it for data access policies. OPA is a CNCF graduated project - the standard for cloud-native policy enforcement.

### Learning Objectives
- Write Rego policies for attribute-based access control (ABAC)
- Implement context-aware authorization (role + time + resource sensitivity)
- Test policies with synthetic data
- Understand policy-as-code principles

### Step 2.1: Create OPA Policies

Create `opa/policies/authz.rego`:

```rego
# ============================================================
# Zero Trust Authorization Policy
# Implements ABAC (Attribute-Based Access Control)
# ============================================================

package authz

import future.keywords.if
import future.keywords.in

# Default deny - Zero Trust principle
default allow := false

# ============================================================
# Role-based permissions matrix
# ============================================================
role_permissions := {
    "admin": {
        "resources": ["*"],
        "actions": ["read", "write", "delete", "admin"],
        "sensitivity_levels": ["public", "internal", "confidential", "secret"]
    },
    "analyst": {
        "resources": ["alerts", "logs", "reports", "dashboards"],
        "actions": ["read"],
        "sensitivity_levels": ["public", "internal", "confidential"]
    },
    "developer": {
        "resources": ["code", "deployments", "configs", "logs"],
        "actions": ["read", "write"],
        "sensitivity_levels": ["public", "internal"]
    },
    "auditor": {
        "resources": ["audit_logs", "compliance_reports", "access_logs"],
        "actions": ["read"],
        "sensitivity_levels": ["public", "internal", "confidential", "secret"]
    }
}

# ============================================================
# Main authorization rule
# Combines role, resource, action, time, and sensitivity
# ============================================================
allow if {
    # 1. User has a valid role
    some role in input.user.roles
    permissions := role_permissions[role]

    # 2. Role has access to the requested resource (or wildcard)
    resource_allowed(permissions.resources, input.resource)

    # 3. Action is permitted for this role
    input.action in permissions.actions

    # 4. Sensitivity level is within role's clearance
    input.sensitivity in permissions.sensitivity_levels

    # 5. Time-based access control (business hours check)
    time_check_passed
}

# ============================================================
# Helper: Resource matching (with wildcard support)
# ============================================================
resource_allowed(allowed_resources, requested) if {
    "*" in allowed_resources
}

resource_allowed(allowed_resources, requested) if {
    requested in allowed_resources
}

# ============================================================
# Time-based access control
# Admins: 24/7 access
# Others: Business hours only (6 AM - 10 PM)
# ============================================================
time_check_passed if {
    "admin" in input.user.roles
}

time_check_passed if {
    not "admin" in input.user.roles
    input.time.hour >= 6
    input.time.hour < 22
}

# ============================================================
# Deny reasons (for audit logging)
# ============================================================
deny_reasons[reason] if {
    not some role in input.user.roles
    _ := role_permissions[role]
    reason := "No valid role found for user"
}

deny_reasons[reason] if {
    some role in input.user.roles
    permissions := role_permissions[role]
    not resource_allowed(permissions.resources, input.resource)
    reason := sprintf("Role '%s' does not have access to resource '%s'", [role, input.resource])
}

deny_reasons[reason] if {
    some role in input.user.roles
    permissions := role_permissions[role]
    not input.action in permissions.actions
    reason := sprintf("Role '%s' cannot perform action '%s'", [role, input.action])
}

deny_reasons[reason] if {
    some role in input.user.roles
    permissions := role_permissions[role]
    not input.sensitivity in permissions.sensitivity_levels
    reason := sprintf("Role '%s' does not have clearance for sensitivity level '%s'", [role, input.sensitivity])
}

deny_reasons[reason] if {
    not time_check_passed
    reason := "Access denied: Outside permitted hours (6 AM - 10 PM)"
}

# ============================================================
# Audit metadata
# ============================================================
audit := {
    "allowed": allow,
    "user": input.user.username,
    "roles": input.user.roles,
    "resource": input.resource,
    "action": input.action,
    "sensitivity": input.sensitivity,
    "deny_reasons": deny_reasons,
    "policy_version": "1.0.0"
}
```

### Step 2.2: Create Additional Policy - Data Classification

Create `opa/policies/data_classification.rego`:

```rego
# ============================================================
# Data Classification Policy
# Enforces data handling based on sensitivity labels
# ============================================================

package data_classification

import future.keywords.if
import future.keywords.in

# Data classification rules
classification_rules := {
    "public": {
        "encryption_required": false,
        "audit_logging": false,
        "retention_days": 30,
        "export_allowed": true
    },
    "internal": {
        "encryption_required": true,
        "audit_logging": true,
        "retention_days": 90,
        "export_allowed": true
    },
    "confidential": {
        "encryption_required": true,
        "audit_logging": true,
        "retention_days": 365,
        "export_allowed": false
    },
    "secret": {
        "encryption_required": true,
        "audit_logging": true,
        "retention_days": 2555,
        "export_allowed": false
    }
}

# Get data handling requirements for a classification level
requirements := classification_rules[input.classification]

# Check if data export is allowed
export_allowed if {
    requirements.export_allowed
}

# Check if encryption is required
encryption_required if {
    requirements.encryption_required
}
```

### Step 2.3: Start OPA and Test Policies

```bash
# Start OPA
docker compose up opa -d

# Wait for OPA to be ready
sleep 3

# Test 1: Admin accessing confidential alerts (SHOULD ALLOW)
echo "=== Test 1: Admin accessing confidential alerts ==="
curl -s -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {
        "username": "alice",
        "roles": ["admin"]
      },
      "resource": "alerts",
      "action": "write",
      "sensitivity": "confidential",
      "time": {"hour": 14, "day": "wednesday"}
    }
  }' | python3 -m json.tool

# Test 2: Analyst trying to write alerts (SHOULD DENY - analysts are read-only)
echo "=== Test 2: Analyst trying to write ==="
curl -s -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {
        "username": "bob",
        "roles": ["analyst"]
      },
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
      "user": {
        "username": "charlie",
        "roles": ["developer"]
      },
      "resource": "code",
      "action": "read",
      "sensitivity": "secret",
      "time": {"hour": 14, "day": "wednesday"}
    }
  }' | python3 -m json.tool

# Test 4: Analyst accessing at 3 AM (SHOULD DENY - outside business hours)
echo "=== Test 4: Analyst accessing at 3 AM ==="
curl -s -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {
        "username": "bob",
        "roles": ["analyst"]
      },
      "resource": "alerts",
      "action": "read",
      "sensitivity": "internal",
      "time": {"hour": 3, "day": "wednesday"}
    }
  }' | python3 -m json.tool

# Test 5: Get deny reasons for failed request
echo "=== Test 5: Deny reasons ==="
curl -s -X POST http://localhost:8181/v1/data/authz/deny_reasons \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user": {
        "username": "charlie",
        "roles": ["developer"]
      },
      "resource": "code",
      "action": "read",
      "sensitivity": "secret",
      "time": {"hour": 14, "day": "wednesday"}
    }
  }' | python3 -m json.tool
```

### Step 2.4: Policy Testing with OPA's Built-in Test Framework

Create `opa/policies/authz_test.rego`:

```rego
package authz

import future.keywords.if

# Test: Admin should have full access
test_admin_full_access if {
    allow with input as {
        "user": {"username": "alice", "roles": ["admin"]},
        "resource": "anything",
        "action": "admin",
        "sensitivity": "secret",
        "time": {"hour": 3, "day": "sunday"}
    }
}

# Test: Analyst should read alerts
test_analyst_read_alerts if {
    allow with input as {
        "user": {"username": "bob", "roles": ["analyst"]},
        "resource": "alerts",
        "action": "read",
        "sensitivity": "internal",
        "time": {"hour": 14, "day": "monday"}
    }
}

# Test: Analyst should NOT write
test_analyst_cannot_write if {
    not allow with input as {
        "user": {"username": "bob", "roles": ["analyst"]},
        "resource": "alerts",
        "action": "write",
        "sensitivity": "internal",
        "time": {"hour": 14, "day": "monday"}
    }
}

# Test: Developer cannot access secret data
test_developer_no_secret if {
    not allow with input as {
        "user": {"username": "charlie", "roles": ["developer"]},
        "resource": "code",
        "action": "read",
        "sensitivity": "secret",
        "time": {"hour": 14, "day": "monday"}
    }
}

# Test: Non-admin denied outside business hours
test_non_admin_after_hours if {
    not allow with input as {
        "user": {"username": "bob", "roles": ["analyst"]},
        "resource": "alerts",
        "action": "read",
        "sensitivity": "internal",
        "time": {"hour": 23, "day": "monday"}
    }
}
```

Run tests:
```bash
docker exec zt-opa /opa test /policies -v
```

### Exercise 2 Questions
1. **How does ABAC differ from RBAC? What additional context does ABAC consider?**
2. **Why is "default deny" important in Zero Trust? What happens if we used "default allow"?**
3. **How would you add a geolocation-based policy (e.g., deny access from certain countries)?**

> **Industry Insight:** Netflix evaluates OPA policies for every API call - millions per second. Policy-as-code means policies are version-controlled, tested, and reviewed like application code. This is a fundamental shift from GUI-based firewall rules.

---

## Lab 3: Network Micro-segmentation (20 Minutes)

### Industry Context
> **Real-World Parallel:** This lab demonstrates the same concepts that Illumio (used by 60% of Fortune 500 financial firms) and Cilium (used by Google, Netflix, AWS EKS) implement at enterprise scale. In production, you'd use Kubernetes NetworkPolicy or eBPF-based tools.

### Learning Objectives
- Create isolated network segments using Docker networks
- Implement and verify inter-segment communication rules
- Test lateral movement prevention
- Monitor network traffic between segments

### Step 3.1: Verify Network Isolation

```bash
# Start all services
docker compose up -d keycloak opa backend-api frontend

# List networks
echo "=== Docker Networks ==="
docker network ls | grep zt-

# Inspect network assignments
echo "=== Frontend Network (172.20.1.0/24) ==="
docker network inspect zero-trust-lab_zt-frontend --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'

echo "=== Backend Network (172.20.2.0/24) ==="
docker network inspect zero-trust-lab_zt-backend --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'
```

### Step 3.2: Test Network Segmentation

```bash
# Test 1: Frontend CANNOT reach Backend API directly (different network)
echo "=== Test 1: Frontend -> Backend (should fail) ==="
docker exec zt-frontend-app wget -q -O - --timeout=3 http://172.20.2.30:5000/health 2>&1 || echo "BLOCKED - Segmentation working!"

# Test 2: Frontend CAN reach Keycloak (shared network)
echo "=== Test 2: Frontend -> Keycloak (should succeed) ==="
docker exec zt-frontend-app wget -q -O - --timeout=3 http://172.20.1.10:8080/health/ready 2>&1 | head -5

# Test 3: Backend CAN reach OPA (same backend network)
echo "=== Test 3: Backend -> OPA (should succeed) ==="
docker exec zt-backend-api wget -q -O - --timeout=3 http://172.20.2.20:8181/health 2>&1

# Test 4: OPA CANNOT reach Frontend (different network)
echo "=== Test 4: OPA -> Frontend (should fail) ==="
docker exec zt-opa wget -q -O - --timeout=3 http://172.20.1.20:3000 2>&1 || echo "BLOCKED - Segmentation working!"
```

### Step 3.3: Visualize Network Topology

Create `scripts/network_map.sh`:

```bash
#!/bin/bash
# ============================================================
# Network Topology Mapper
# Visualizes which containers can communicate
# ============================================================

echo "============================================"
echo "  Zero Trust Lab - Network Topology Map"
echo "============================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}Network Segments:${NC}"
echo "  [zt-frontend]  172.20.1.0/24 - DMZ/User-facing"
echo "  [zt-backend]   172.20.2.0/24 - Application tier"
echo "  [zt-monitoring] 172.20.3.0/24 - Security monitoring"
echo "  [zt-dmz]       172.20.4.0/24 - Isolated/Vulnerable apps"
echo ""

echo -e "${YELLOW}Container Network Assignments:${NC}"
echo "  Keycloak:    zt-frontend (172.20.1.10) + zt-backend (172.20.2.10)"
echo "  Frontend:    zt-frontend (172.20.1.20)"
echo "  Backend API: zt-backend  (172.20.2.30)"
echo "  OPA:         zt-backend  (172.20.2.20)"
echo "  Wazuh:       zt-monitoring (172.20.3.10) + zt-backend (172.20.2.40)"
echo "  Vulnerable:  zt-dmz (172.20.4.10) + zt-monitoring (172.20.3.40)"
echo ""

echo -e "${GREEN}Allowed Communication Paths:${NC}"
echo "  Frontend  --> Keycloak  (via zt-frontend) [Authentication]"
echo "  Backend   --> Keycloak  (via zt-backend)  [Token validation]"
echo "  Backend   --> OPA       (via zt-backend)  [Policy check]"
echo "  Wazuh     --> Backend   (via zt-backend)  [Log collection]"
echo "  Vulnerable --> Wazuh   (via zt-monitoring) [Log forwarding]"
echo ""

echo -e "${RED}Blocked Communication Paths:${NC}"
echo "  Frontend  -X-> Backend  (different networks) [No direct DB access]"
echo "  Frontend  -X-> OPA      (different networks) [No policy bypass]"
echo "  OPA       -X-> Frontend (different networks) [Isolation]"
echo "  Vulnerable -X-> Backend (different networks) [DMZ isolation]"
echo ""

echo "============================================"
echo "  Connectivity Test Results"
echo "============================================"

# Run connectivity tests
test_connection() {
    local from=$1
    local to_ip=$2
    local to_port=$3
    local label=$4
    
    result=$(docker exec $from wget -q -O - --timeout=2 http://$to_ip:$to_port 2>&1)
    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}[PASS]${NC} $label"
    else
        echo -e "  ${RED}[BLOCKED]${NC} $label"
    fi
}

test_connection "zt-frontend-app" "172.20.1.10" "8080" "Frontend -> Keycloak"
test_connection "zt-frontend-app" "172.20.2.30" "5000" "Frontend -> Backend (should be blocked)"
test_connection "zt-backend-api" "172.20.2.20" "8181" "Backend -> OPA"
test_connection "zt-backend-api" "172.20.2.10" "8080" "Backend -> Keycloak"
test_connection "zt-opa" "172.20.1.20" "3000" "OPA -> Frontend (should be blocked)"
```

```bash
chmod +x scripts/network_map.sh
bash scripts/network_map.sh
```

### Step 3.4: Simulate Lateral Movement Attack

```bash
# Scenario: Attacker compromises the frontend container
# Can they reach the backend database?

echo "=== Lateral Movement Test ==="
echo "Attacker has shell on frontend container..."

# Try to reach backend API
docker exec zt-frontend-app sh -c "
echo 'Attempting to reach backend...'
wget -q -O - --timeout=2 http://172.20.2.30:5000/health 2>&1 || echo 'FAILED: Cannot reach backend from frontend'

echo 'Attempting to reach OPA...'
wget -q -O - --timeout=2 http://172.20.2.20:8181/health 2>&1 || echo 'FAILED: Cannot reach OPA from frontend'

echo 'Attempting to reach Wazuh...'
wget -q -O - --timeout=2 http://172.20.3.10:55000 2>&1 || echo 'FAILED: Cannot reach Wazuh from frontend'

echo 'Attempting to reach vulnerable app...'
wget -q -O - --timeout=2 http://172.20.4.10:8888 2>&1 || echo 'FAILED: Cannot reach vulnerable app from frontend'
"

echo ""
echo "RESULT: Micro-segmentation prevents lateral movement!"
echo "Even with full shell access on frontend, attacker cannot reach backend services."
```

### Exercise 3 Questions
1. **In a Kubernetes environment, what resource would you use instead of Docker networks?** (Answer: NetworkPolicy)
2. **What is the difference between network-based and identity-based segmentation?**
3. **How would an attacker bypass micro-segmentation? What additional controls are needed?**

> **Industry Insight:** After the Target breach (2013), where HVAC contractors were on the same network as payment systems, micro-segmentation became mandatory for PCI-DSS compliance. Modern payment processors use identity-based micro-segmentation with mTLS.

---

## Lab 4: SOC Simulation with Wazuh SIEM (20 Minutes)

### Industry Context
> **Real-World Parallel:** Wazuh has 10M+ installations and is used by NASA, Siemens, and many government agencies. This lab gives you the same experience as working with Splunk ($150K+/year license) or Microsoft Sentinel, but using open-source tools.

### Learning Objectives
- Deploy and configure a SIEM system
- Create custom detection rules using Sigma/Wazuh format
- Generate and analyze security events
- Understand alert triage and incident investigation

### Step 4.1: Create Wazuh Configuration

Create `wazuh/ossec.conf`:

```xml
<!--
  Wazuh Manager Configuration
  Zero Trust Lab - Custom Rules for Detection
-->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
  </global>

  <!-- Log collection from Docker containers -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/containers/*.log</location>
  </localfile>

  <!-- Syslog collection -->
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
  </remote>

  <!-- Active response for brute force -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100010</rules_id>
    <timeout>300</timeout>
  </active-response>

  <!-- Vulnerability detection -->
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_interval>1h</update_interval>
    </provider>
  </vulnerability-detector>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <directories check_all="yes" report_changes="yes">/etc</directories>
    <directories check_all="yes" report_changes="yes">/usr/bin</directories>
    <directories check_all="yes" report_changes="yes">/usr/sbin</directories>
  </syscheck>
</ossec_config>
```

### Step 4.2: Create Custom Detection Rules

Create `wazuh/rules/custom_zt_rules.xml`:

```xml
<!--
  Custom Zero Trust Detection Rules
  Rule IDs: 100001 - 100100
-->
<group name="zero_trust,authentication,">

  <!-- ================================================ -->
  <!-- Authentication Monitoring Rules -->
  <!-- ================================================ -->
  
  <!-- Brute force detection: 5+ failed logins in 2 minutes -->
  <rule id="100001" level="10" frequency="5" timeframe="120">
    <if_matched_group>authentication_failed</if_matched_group>
    <description>Zero Trust Alert: Brute force attack detected - $(srcip)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>brute_force,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

  <!-- Impossible travel: Login from different geolocations -->
  <rule id="100002" level="12">
    <if_sid>100001</if_sid>
    <match>authentication|login</match>
    <description>Zero Trust Alert: Possible credential compromise - multiple source IPs</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>credential_compromise,</group>
  </rule>

  <!-- Successful login after multiple failures (may indicate success after brute force) -->
  <rule id="100003" level="8">
    <if_matched_group>authentication_success</if_matched_group>
    <same_source_ip />
    <description>Zero Trust Alert: Successful login after failures from $(srcip)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <!-- ================================================ -->
  <!-- Privilege Escalation Detection -->
  <!-- ================================================ -->
  
  <!-- Sudo to root -->
  <rule id="100010" level="10">
    <if_group>syslog</if_group>
    <match>sudo|su root|privilege</match>
    <description>Zero Trust Alert: Privilege escalation attempt detected</description>
    <mitre>
      <id>T1548</id>
    </mitre>
    <group>privilege_escalation,</group>
  </rule>

  <!-- New admin account creation -->
  <rule id="100011" level="12">
    <if_group>syslog</if_group>
    <match>useradd|adduser|net user /add</match>
    <description>Zero Trust Alert: New user account created - possible persistence</description>
    <mitre>
      <id>T1136</id>
    </mitre>
    <group>persistence,account_creation,</group>
  </rule>

  <!-- ================================================ -->
  <!-- Lateral Movement Detection -->
  <!-- ================================================ -->
  
  <rule id="100020" level="10">
    <if_group>syslog</if_group>
    <match>ssh|rdp|lateral|psexec</match>
    <description>Zero Trust Alert: Potential lateral movement detected</description>
    <mitre>
      <id>T1021</id>
    </mitre>
    <group>lateral_movement,</group>
  </rule>

  <!-- Network scan detection -->
  <rule id="100021" level="8">
    <if_group>syslog</if_group>
    <match>nmap|masscan|port scan|SYN scan</match>
    <description>Zero Trust Alert: Network reconnaissance/port scanning detected</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>reconnaissance,network_scan,</group>
  </rule>

  <!-- ================================================ -->
  <!-- Data Exfiltration Detection -->
  <!-- ================================================ -->
  
  <rule id="100030" level="12">
    <if_group>syslog</if_group>
    <match>curl.*pastebin|wget.*external|exfil|data transfer</match>
    <description>Zero Trust Alert: Possible data exfiltration attempt</description>
    <mitre>
      <id>T1048</id>
    </mitre>
    <group>data_exfiltration,</group>
  </rule>

  <!-- Large file transfer -->
  <rule id="100031" level="8">
    <if_group>syslog</if_group>
    <match>scp|rsync|large transfer</match>
    <description>Zero Trust Alert: Large file transfer detected - review for exfiltration</description>
    <mitre>
      <id>T1041</id>
    </mitre>
    <group>data_exfiltration,</group>
  </rule>

  <!-- ================================================ -->
  <!-- API Abuse Detection -->
  <!-- ================================================ -->
  
  <rule id="100040" level="8" frequency="20" timeframe="60">
    <if_group>web</if_group>
    <match>api|REST|endpoint</match>
    <description>Zero Trust Alert: API rate limit exceeded - possible abuse</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>api_abuse,rate_limiting,</group>
  </rule>

</group>
```

### Step 4.3: Start Wazuh Stack

```bash
# Start Wazuh components
docker compose up wazuh-indexer wazuh-manager wazuh-dashboard -d

# Wait for initialization (this takes 2-3 minutes)
echo "Waiting for Wazuh to initialize..."
sleep 30

# Check Wazuh Manager status
docker exec zt-wazuh-manager /var/ossec/bin/wazuh-control status
```

### Step 4.4: Access Wazuh Dashboard

1. Open browser: `https://localhost:443` (accept self-signed certificate)
2. Login: `admin` / `SecretPassword`
3. Navigate to: **Security Events** > **Events**

### Step 4.5: Generate Security Events

Create `scripts/generate_events.sh`:

```bash
#!/bin/bash
# ============================================================
# Security Event Generator
# Simulates various attack patterns for SIEM detection
# ============================================================

echo "=== Generating Security Events for Wazuh ==="

# 1. Simulate brute force (multiple failed logins)
echo "[*] Simulating brute force attack..."
for i in {1..10}; do
  curl -s -o /dev/null -X POST "http://localhost:8080/realms/zero-trust-lab/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=zt-frontend" \
    -d "username=alice" \
    -d "password=wrongpassword${i}" \
    -d "grant_type=password"
  echo "  Failed login attempt $i"
done

# 2. Simulate successful login after failures
echo "[*] Simulating successful login after brute force..."
curl -s -o /dev/null -X POST "http://localhost:8080/realms/zero-trust-lab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=zt-frontend" \
  -d "username=alice" \
  -d "password=alice123" \
  -d "grant_type=password"
echo "  Successful login after failures"

# 3. Simulate API abuse (rapid requests)
echo "[*] Simulating API rate limit abuse..."
for i in {1..25}; do
  curl -s -o /dev/null http://localhost:5000/api/health 2>/dev/null
done
echo "  25 rapid API requests sent"

# 4. Generate system events via Wazuh
echo "[*] Generating system-level events..."
docker exec zt-wazuh-manager /var/ossec/bin/wazuh-logtest <<EOF
Mar 15 14:30:00 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Mar 15 14:30:05 server sshd[1235]: Failed password for invalid user root from 192.168.1.100 port 22 ssh2
Mar 15 14:30:10 server sshd[1236]: Failed password for invalid user test from 192.168.1.100 port 22 ssh2
Mar 15 14:30:15 server sudo: hacker : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/hacker ; USER=root ; COMMAND=/bin/bash
Mar 15 14:30:20 server useradd[1240]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor
EOF

echo ""
echo "=== Events Generated ==="
echo "Check Wazuh Dashboard: https://localhost:443"
echo "Navigate to: Security Events > Events"
echo "Look for alerts with rule IDs: 100001-100040"
```

```bash
chmod +x scripts/generate_events.sh
bash scripts/generate_events.sh
```

### Step 4.6: Analyze Events in Wazuh Dashboard

In the Wazuh Dashboard:
1. Go to **Modules** > **Security Events**
2. Filter by: `rule.id: 100001 OR rule.id: 100010 OR rule.id: 100011`
3. Click on an event to see:
   - MITRE ATT&CK mapping
   - Source IP
   - Timestamp
   - Rule description
   - Event details

### Exercise 4 Questions
1. **What is the difference between a SIEM alert and an incident?**
2. **How would you reduce false positives in these detection rules?**
3. **What additional data sources would improve detection accuracy?**

> **Industry Insight:** The average SOC receives 11,000 alerts per day but can only investigate ~25. This is why AI-powered triage (Microsoft Copilot for Security, Google Gemini) is transforming SOC operations - reducing noise by 60%+.

---

## Lab 5: Red Team / Blue Team Exercise (20 Minutes)

### Industry Context
> **Real-World Parallel:** This exercise mirrors what penetration testing firms like Mandiant, CrowdStrike Services, and Rapid7 do for Fortune 500 clients. Purple team exercises (combined red+blue) are now the gold standard - adopted by financial regulators (TIBER-EU), healthcare (HITRUST), and government (CISA).

### Learning Objectives
- Execute controlled attack techniques mapped to MITRE ATT&CK
- Detect and respond to attacks using SIEM
- Practice incident response procedures
- Understand the attacker's perspective and defender's response

### Team Setup

| Role | Tasks | Tools |
|------|-------|-------|
| **Red Team** (Offense) | Execute attack scripts, attempt to access sensitive data | curl, nmap simulation, custom scripts |
| **Blue Team** (Defense) | Monitor SIEM, detect attacks, document findings | Wazuh Dashboard, log analysis |

> **Note:** Faculty can split into teams or one person can play both roles.

### Step 5.1: Start the Vulnerable Application

Create `apps/vulnerable/app.py`:

```python
"""
Deliberately Vulnerable Application for Red/Blue Team Exercise
WARNING: This app contains intentional vulnerabilities for educational purposes.
DO NOT deploy in any real environment.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import urllib.parse
import subprocess
import logging
import sys

# Configure logging to stdout (for Wazuh to collect)
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [security] %(message)s'
)
logger = logging.getLogger('vulnerable-app')

# Simulated "sensitive data"
SENSITIVE_DATA = {
    "employees": [
        {"name": "Alice Admin", "ssn": "***-**-1234", "salary": "$150,000"},
        {"name": "Bob Analyst", "ssn": "***-**-5678", "salary": "$95,000"},
    ],
    "api_keys": {
        "production": "sk-REDACTED-prod-key-do-not-expose",
        "staging": "sk-REDACTED-staging-key",
    },
    "database_credentials": {
        "host": "internal-db.company.local",
        "username": "db_admin",
        "password": "REDACTED-password-123"
    }
}

# Simple auth (intentionally weak for the exercise)
VALID_TOKENS = {
    "admin-token-12345": {"role": "admin", "user": "alice"},
    "user-token-67890": {"role": "user", "user": "bob"},
}

class VulnerableHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)
        
        # --- VULNERABILITY 1: Information Disclosure ---
        if path == '/':
            self.send_json(200, {
                "app": "Vulnerable Demo App",
                "version": "1.0.0",
                "endpoints": ["/api/data", "/api/admin", "/api/health", "/api/search", "/debug/env"],
                "auth": "Send token in Authorization header"
            })
        
        # --- Health check ---
        elif path == '/api/health':
            self.send_json(200, {"status": "healthy", "uptime": "24h"})
        
        # --- VULNERABILITY 2: Broken Authentication ---
        elif path == '/api/data':
            token = self.headers.get('Authorization', '').replace('Bearer ', '')
            if token in VALID_TOKENS:
                user_info = VALID_TOKENS[token]
                logger.info(f"Data access by {user_info['user']} (role: {user_info['role']})")
                self.send_json(200, {
                    "message": "Authorized access",
                    "user": user_info,
                    "data": SENSITIVE_DATA["employees"]
                })
            else:
                logger.warning(f"Unauthorized access attempt to /api/data from {self.client_address[0]}")
                self.send_json(401, {"error": "Unauthorized"})
        
        # --- VULNERABILITY 3: Broken Access Control (IDOR) ---
        elif path == '/api/admin':
            token = self.headers.get('Authorization', '').replace('Bearer ', '')
            if token in VALID_TOKENS:
                # BUG: No role check! Any valid token gets admin access
                user_info = VALID_TOKENS[token]
                logger.warning(f"Admin endpoint accessed by {user_info['user']} (role: {user_info['role']})")
                self.send_json(200, {
                    "message": "Admin panel",
                    "sensitive": SENSITIVE_DATA
                })
            else:
                self.send_json(401, {"error": "Unauthorized"})
        
        # --- VULNERABILITY 4: Server-Side Request Forgery (SSRF) ---
        elif path == '/api/search':
            url = params.get('url', [None])[0]
            if url:
                logger.warning(f"SSRF attempt: Search URL requested: {url} from {self.client_address[0]}")
                self.send_json(200, {
                    "message": f"Would fetch: {url}",
                    "note": "SSRF vulnerability - in real app, this would fetch the URL"
                })
            else:
                self.send_json(400, {"error": "Missing url parameter"})
        
        # --- VULNERABILITY 5: Debug Endpoint Exposed ---
        elif path == '/debug/env':
            logger.critical(f"Debug endpoint accessed from {self.client_address[0]} - potential recon")
            self.send_json(200, {
                "environment": dict(os.environ),
                "warning": "DEBUG ENDPOINT - SHOULD NOT BE IN PRODUCTION"
            })
        
        else:
            self.send_json(404, {"error": "Not found"})
    
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
        
        # --- VULNERABILITY 6: Command Injection (Simulated) ---
        if path == '/api/ping':
            try:
                data = json.loads(body)
                host = data.get('host', '')
                logger.critical(f"Command injection attempt: ping {host} from {self.client_address[0]}")
                # Intentionally vulnerable (simulated - doesn't actually execute)
                self.send_json(200, {
                    "message": f"Simulated ping to: {host}",
                    "warning": "Command injection vulnerability - input not sanitized",
                    "what_would_happen": f"subprocess.run('ping -c 1 {host}', shell=True)"
                })
            except json.JSONDecodeError:
                self.send_json(400, {"error": "Invalid JSON"})
        else:
            self.send_json(404, {"error": "Not found"})
    
    def send_json(self, status, data):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())
    
    def log_message(self, format, *args):
        logger.info(f"{self.client_address[0]} - {args[0]}")

if __name__ == '__main__':
    port = 8888
    server = HTTPServer(('0.0.0.0', port), VulnerableHandler)
    logger.info(f"Vulnerable app starting on port {port}")
    server.serve_forever()
```

Create `apps/vulnerable/Dockerfile`:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY app.py .
EXPOSE 8888
CMD ["python", "app.py"]
```

### Step 5.2: Red Team Attack Script

Create `scripts/red_team_attack.sh`:

```bash
#!/bin/bash
# ============================================================
# RED TEAM ATTACK SCRIPT
# MITRE ATT&CK Mapped Attacks
# ============================================================

TARGET="http://localhost:8888"
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}========================================${NC}"
echo -e "${RED}  RED TEAM ATTACK SIMULATION${NC}"
echo -e "${RED}  Target: ${TARGET}${NC}"
echo -e "${RED}========================================${NC}"
echo ""

# ================================================
# PHASE 1: RECONNAISSANCE (MITRE ATT&CK: T1595, T1592)
# ================================================
echo -e "${YELLOW}[PHASE 1] RECONNAISSANCE${NC}"
echo "  MITRE ATT&CK: T1595 - Active Scanning"
echo ""

echo "  [1.1] Discovering endpoints..."
RECON=$(curl -s $TARGET)
echo "  Response: $(echo $RECON | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("endpoints", []))')"
echo ""

echo "  [1.2] Checking for debug endpoints..."
DEBUG=$(curl -s $TARGET/debug/env)
echo "  DEBUG ENDPOINT FOUND! Environment variables exposed."
echo "  MITRE ATT&CK: T1082 - System Information Discovery"
echo ""

# ================================================
# PHASE 2: INITIAL ACCESS (MITRE ATT&CK: T1190)
# ================================================
echo -e "${YELLOW}[PHASE 2] INITIAL ACCESS${NC}"
echo "  MITRE ATT&CK: T1190 - Exploit Public-Facing Application"
echo ""

echo "  [2.1] Testing authentication bypass..."
echo "  Trying known token patterns..."
curl -s -H "Authorization: Bearer admin-token-12345" $TARGET/api/data | python3 -m json.tool
echo ""

# ================================================
# PHASE 3: PRIVILEGE ESCALATION (MITRE ATT&CK: T1548)
# ================================================
echo -e "${YELLOW}[PHASE 3] PRIVILEGE ESCALATION${NC}"
echo "  MITRE ATT&CK: T1548 - Abuse Elevation Control Mechanism"
echo ""

echo "  [3.1] Testing Broken Access Control (IDOR)..."
echo "  Using USER token to access ADMIN endpoint..."
ADMIN_RESPONSE=$(curl -s -H "Authorization: Bearer user-token-67890" $TARGET/api/admin)
echo "  VULNERABILITY FOUND: User token grants admin access!"
echo "  Sensitive data retrieved: $(echo $ADMIN_RESPONSE | python3 -c 'import sys,json; d=json.load(sys.stdin); print(list(d.get("sensitive", {}).keys()))')"
echo ""

# ================================================
# PHASE 4: CREDENTIAL ACCESS (MITRE ATT&CK: T1552)
# ================================================
echo -e "${YELLOW}[PHASE 4] CREDENTIAL ACCESS${NC}"
echo "  MITRE ATT&CK: T1552 - Unsecured Credentials"
echo ""

echo "  [4.1] Extracting credentials from admin endpoint..."
echo "  Database credentials found:"
echo "$ADMIN_RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
creds = d.get('sensitive', {}).get('database_credentials', {})
for k, v in creds.items():
    print(f'    {k}: {v}')
"
echo ""

echo "  [4.2] API keys found:"
echo "$ADMIN_RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
keys = d.get('sensitive', {}).get('api_keys', {})
for k, v in keys.items():
    print(f'    {k}: {v}')
"
echo ""

# ================================================
# PHASE 5: SSRF ATTEMPT (MITRE ATT&CK: T1190)
# ================================================
echo -e "${YELLOW}[PHASE 5] SSRF ATTACK${NC}"
echo "  MITRE ATT&CK: T1190 - Server-Side Request Forgery"
echo ""

echo "  [5.1] Attempting SSRF to internal services..."
curl -s "$TARGET/api/search?url=http://172.20.2.30:5000/api/secrets" | python3 -m json.tool
echo ""

echo "  [5.2] Attempting SSRF to cloud metadata..."
curl -s "$TARGET/api/search?url=http://169.254.169.254/latest/meta-data/" | python3 -m json.tool
echo ""

# ================================================
# PHASE 6: COMMAND INJECTION (MITRE ATT&CK: T1059)
# ================================================
echo -e "${YELLOW}[PHASE 6] COMMAND INJECTION${NC}"
echo "  MITRE ATT&CK: T1059 - Command and Scripting Interpreter"
echo ""

echo "  [6.1] Testing command injection via ping endpoint..."
curl -s -X POST $TARGET/api/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "8.8.8.8; cat /etc/passwd"}' | python3 -m json.tool
echo ""

# ================================================
# SUMMARY
# ================================================
echo -e "${RED}========================================${NC}"
echo -e "${RED}  ATTACK SUMMARY${NC}"
echo -e "${RED}========================================${NC}"
echo "  Vulnerabilities Found: 6"
echo ""
echo "  1. Information Disclosure - Debug endpoint exposed"
echo "  2. Broken Authentication - Weak token mechanism"
echo "  3. Broken Access Control - IDOR (user can access admin)"
echo "  4. Unsecured Credentials - API keys and DB creds in response"
echo "  5. SSRF - Server-side request forgery possible"
echo "  6. Command Injection - Unsanitized input to system commands"
echo ""
echo "  MITRE ATT&CK Techniques Used:"
echo "    T1595 - Active Scanning"
echo "    T1082 - System Information Discovery"
echo "    T1190 - Exploit Public-Facing Application"
echo "    T1548 - Abuse Elevation Control"
echo "    T1552 - Unsecured Credentials"
echo "    T1059 - Command Injection"
echo ""
echo -e "${YELLOW}  Blue Team: Check Wazuh Dashboard for alerts!${NC}"
```

### Step 5.3: Blue Team Response Script

Create `scripts/blue_team_response.sh`:

```bash
#!/bin/bash
# ============================================================
# BLUE TEAM RESPONSE GUIDE
# Incident Detection & Response Procedures
# ============================================================

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  BLUE TEAM - INCIDENT RESPONSE${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# ================================================
# STEP 1: DETECTION
# ================================================
echo -e "${GREEN}[STEP 1] DETECTION - Check SIEM Alerts${NC}"
echo ""
echo "  1. Open Wazuh Dashboard: https://localhost:443"
echo "  2. Go to: Modules > Security Events"
echo "  3. Look for these alert patterns:"
echo "     - Rule 100001: Brute force detection"
echo "     - Rule 100010: Privilege escalation"
echo "     - Rule 100020: Lateral movement"
echo "     - Rule 100030: Data exfiltration"
echo ""

echo "  Checking Wazuh manager for recent alerts..."
docker exec zt-wazuh-manager cat /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -5 | python3 -m json.tool 2>/dev/null || echo "  (Alerts will appear in Wazuh Dashboard)"
echo ""

# ================================================
# STEP 2: ANALYSIS
# ================================================
echo -e "${GREEN}[STEP 2] ANALYSIS - Investigate the Attack${NC}"
echo ""
echo "  2.1. Check Keycloak login events:"
docker exec zt-keycloak cat /opt/keycloak/data/log/keycloak.log 2>/dev/null | grep -i "LOGIN_ERROR\|LOGIN" | tail -10 || echo "  Check Keycloak Admin > Events"
echo ""

echo "  2.2. Check vulnerable app logs:"
docker logs zt-vulnerable-app 2>&1 | grep -i "security\|warning\|critical" | tail -15
echo ""

echo "  2.3. Check for unusual network activity:"
echo "  Active connections from vulnerable app:"
docker exec zt-vulnerable-app ss -tnp 2>/dev/null || docker exec zt-vulnerable-app netstat -tnp 2>/dev/null || echo "  (Install net-tools for detailed connection info)"
echo ""

# ================================================
# STEP 3: CONTAINMENT
# ================================================
echo -e "${GREEN}[STEP 3] CONTAINMENT - Limit the Damage${NC}"
echo ""
echo "  3.1. Block the attacking IP (simulated):"
echo "  In production: Update firewall rules, WAF, or network ACLs"
echo ""

echo "  3.2. Disable compromised accounts:"
echo "  Would disable user accounts that were compromised"
echo ""

echo "  3.3. Rotate exposed credentials:"
echo "  Would rotate all API keys and database passwords found in the attack"
echo ""

echo "  3.4. Isolate affected containers:"
echo "  docker network disconnect zero-trust-lab_zt-dmz zt-vulnerable-app"
echo "  (This disconnects the vulnerable app from the network)"
echo ""

# ================================================
# STEP 4: DOCUMENTATION
# ================================================
echo -e "${GREEN}[STEP 4] DOCUMENTATION - Record Findings${NC}"
echo ""
echo "  Fill in the Incident Report:"
echo ""
echo "  ┌────────────────────────────────────────────────────┐"
echo "  │ INCIDENT REPORT                                     │"
echo "  │                                                      │"
echo "  │ Date/Time: $(date)                                   │"
echo "  │ Severity: HIGH                                       │"
echo "  │ Type: Application Exploitation                       │"
echo "  │                                                      │"
echo "  │ Vulnerabilities Found:                               │"
echo "  │  □ Debug endpoint exposed (CWE-489)                 │"
echo "  │  □ Broken access control (CWE-284, OWASP A01)      │"
echo "  │  □ SSRF vulnerability (CWE-918, OWASP A10)         │"
echo "  │  □ Command injection (CWE-78, OWASP A03)           │"
echo "  │  □ Credential exposure (CWE-312)                    │"
echo "  │                                                      │"
echo "  │ MITRE ATT&CK Techniques Detected:                   │"
echo "  │  □ T1595 - Active Scanning                          │"
echo "  │  □ T1190 - Exploit Public-Facing App                │"
echo "  │  □ T1548 - Privilege Escalation                     │"
echo "  │  □ T1552 - Unsecured Credentials                   │"
echo "  │                                                      │"
echo "  │ Remediation Required:                                │"
echo "  │  □ Remove debug endpoint                            │"
echo "  │  □ Implement proper RBAC (not just token check)     │"
echo "  │  □ Add input validation for SSRF prevention         │"
echo "  │  □ Sanitize all user inputs                         │"
echo "  │  □ Move credentials to vault (HashiCorp Vault)      │"
echo "  │  □ Implement Zero Trust: Keycloak + OPA for auth    │"
echo "  │                                                      │"
echo "  └────────────────────────────────────────────────────┘"
echo ""

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  KEY LESSON: Every vulnerability above${NC}"
echo -e "${BLUE}  would be mitigated by Zero Trust:${NC}"
echo -e "${BLUE}  - Identity verification (Keycloak)${NC}"
echo -e "${BLUE}  - Policy enforcement (OPA)${NC}"
echo -e "${BLUE}  - Network segmentation (Isolated nets)${NC}"
echo -e "${BLUE}  - Continuous monitoring (Wazuh SIEM)${NC}"
echo -e "${BLUE}========================================${NC}"
```

### Step 5.4: Run the Exercise

```bash
# Start the vulnerable app
docker compose up vulnerable-app -d
sleep 5

# Red Team: Run attack script
chmod +x scripts/red_team_attack.sh
bash scripts/red_team_attack.sh

# Blue Team: Run response script
chmod +x scripts/blue_team_response.sh
bash scripts/blue_team_response.sh
```

### Exercise 5 Questions
1. **Map each vulnerability to an OWASP Top 10 (2025) category.**
2. **How would Zero Trust principles prevent each attack phase?**
3. **Design a Wazuh rule to detect the SSRF attack pattern.**

> **Industry Insight:** In 2024, Microsoft's red team discovered 20,000+ vulnerabilities across their products. Google's Project Zero has a strict 90-day disclosure policy - if vendors don't patch within 90 days, the vulnerability goes public. This "responsible pressure" has dramatically improved patching times industry-wide.

---

## Wrap-Up & Discussion (5 Minutes)

### What You Built Today

| Component | Industry Equivalent | Production Tools |
|-----------|-------------------|------------------|
| Keycloak (IdP) | Okta, Azure AD, Auth0 | Okta, Entra ID, Ping Identity |
| OPA (Policy) | Enterprise policy engines | OPA, HashiCorp Sentinel, AWS Cedar |
| Docker Networks (Segmentation) | Micro-segmentation | Cilium, Illumio, VMware NSX |
| Wazuh (SIEM) | Enterprise SIEM | Splunk, Microsoft Sentinel, Elastic |
| Red/Blue Exercise | Penetration testing | Metasploit, Cobalt Strike, Atomic Red Team |

### Take-Home Challenges

1. **Add HTTPS/TLS** to all services (use mkcert for local CA)
2. **Implement mutual TLS (mTLS)** between backend services
3. **Add a rate limiter** to the backend API using OPA policies
4. **Create Kubernetes NetworkPolicy** equivalents for the Docker network rules
5. **Implement FIDO2/WebAuthn** passwordless authentication in Keycloak
6. **Add post-quantum TLS** using Open Quantum Safe (liboqs) library

### Recommended Resources

| Resource | URL | Why It Matters |
|----------|-----|---------------|
| NIST SP 800-207 | csrc.nist.gov | THE Zero Trust standard |
| MITRE ATT&CK | attack.mitre.org | Adversary behavior framework |
| NIST PQC Standards | csrc.nist.gov/pqc | Post-quantum crypto standards |
| CISA ZT Maturity | cisa.gov/zero-trust | Maturity assessment model |
| OWASP Top 10 (2025) | owasp.org | Web application security |
| Open Policy Agent | openpolicyagent.org | Policy-as-code standard |
| Keycloak Docs | keycloak.org | Open-source IAM |
| Wazuh Documentation | wazuh.com | Open-source SIEM |
| Atomic Red Team | github.com/redcanaryco | Open-source attack tests |

### Certifications to Recommend to Students

| Certification | Level | Focus |
|--------------|-------|-------|
| CompTIA Security+ | Entry | Broad cybersecurity fundamentals |
| CKS (Kubernetes Security) | Intermediate | Container/cloud security |
| CISSP | Advanced | Enterprise security architecture |
| OSCP | Advanced | Penetration testing |
| GCIH | Intermediate | Incident handling |

---

## Appendix A: Backend API Application

Create `apps/backend/app.py`:

```python
"""
Zero Trust Protected Backend API
Demonstrates: OIDC token validation + OPA policy enforcement
"""
from flask import Flask, request, jsonify
import requests
import jwt
import os
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('zt-backend')

KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'http://172.20.2.10:8080')
OPA_URL = os.getenv('OPA_URL', 'http://172.20.2.20:8181')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'zero-trust-lab')

def get_keycloak_public_key():
    """Fetch Keycloak's public key for JWT validation."""
    try:
        url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"
        response = requests.get(url, timeout=5)
        realm_info = response.json()
        public_key = realm_info.get('public_key', '')
        return f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
    except Exception as e:
        logger.error(f"Failed to get Keycloak public key: {e}")
        return None

def validate_token(token):
    """Validate JWT token from Keycloak."""
    try:
        public_key = get_keycloak_public_key()
        if not public_key:
            return None
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],
            audience='account',
            options={"verify_exp": True}
        )
        return decoded
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        return None

def check_opa_policy(user_info, resource, action, sensitivity="internal"):
    """Check OPA policy for authorization."""
    try:
        from datetime import datetime
        now = datetime.now()
        
        payload = {
            "input": {
                "user": {
                    "username": user_info.get("preferred_username", "unknown"),
                    "roles": user_info.get("realm_access", {}).get("roles", [])
                },
                "resource": resource,
                "action": action,
                "sensitivity": sensitivity,
                "time": {
                    "hour": now.hour,
                    "day": now.strftime("%A").lower()
                }
            }
        }
        
        response = requests.post(
            f"{OPA_URL}/v1/data/authz/allow",
            json=payload,
            timeout=2
        )
        result = response.json()
        return result.get("result", False)
    except Exception as e:
        logger.error(f"OPA policy check failed: {e}")
        return False  # Default deny on policy engine failure

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "service": "zt-backend-api"})

@app.route('/api/data', methods=['GET'])
def get_data():
    """Protected endpoint - requires valid token + OPA policy approval."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401
    
    token = auth_header.replace('Bearer ', '')
    user_info = validate_token(token)
    
    if not user_info:
        logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
        return jsonify({"error": "Invalid or expired token"}), 401
    
    # Check OPA policy
    if not check_opa_policy(user_info, "data", "read"):
        logger.warning(f"Policy denied: {user_info.get('preferred_username')} -> data:read")
        return jsonify({"error": "Access denied by policy"}), 403
    
    logger.info(f"Authorized access: {user_info.get('preferred_username')} -> data:read")
    return jsonify({
        "message": "Zero Trust verified access",
        "user": user_info.get('preferred_username'),
        "roles": user_info.get('realm_access', {}).get('roles', []),
        "data": {"items": ["item1", "item2", "item3"]},
        "policy_check": "PASSED"
    })

@app.route('/api/admin', methods=['GET'])
def admin_panel():
    """Admin endpoint - requires admin role + OPA policy."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing Authorization header"}), 401
    
    token = auth_header.replace('Bearer ', '')
    user_info = validate_token(token)
    
    if not user_info:
        return jsonify({"error": "Invalid token"}), 401
    
    # Check OPA policy for admin action
    if not check_opa_policy(user_info, "admin_panel", "admin", "confidential"):
        logger.warning(f"Admin access denied: {user_info.get('preferred_username')}")
        return jsonify({"error": "Insufficient privileges"}), 403
    
    return jsonify({
        "message": "Admin panel - Zero Trust verified",
        "user": user_info.get('preferred_username'),
        "admin_data": "This data is only accessible to verified admin users"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
```

Create `apps/backend/requirements.txt`:

```
flask==3.0.3
requests==2.32.3
PyJWT==2.8.0
cryptography==42.0.8
```

Create `apps/backend/Dockerfile`:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]
```

## Appendix B: Frontend Application

Create `apps/frontend/app.py`:

```python
"""Simple frontend that demonstrates OIDC login flow."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os

KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'http://localhost:8080')
BACKEND_URL = os.getenv('BACKEND_URL', 'http://localhost:5000')

HTML_PAGE = f"""<!DOCTYPE html>
<html>
<head>
    <title>Zero Trust Lab - Frontend</title>
    <style>
        body {{ font-family: Calibri, sans-serif; max-width: 800px; margin: 50px auto; background: #f5f8fc; }}
        .card {{ background: white; border-radius: 8px; padding: 20px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ background: #003B64; color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .btn {{ background: #0076CE; color: white; border: none; padding: 12px 24px; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        .btn:hover {{ background: #005a9e; }}
        .btn-danger {{ background: #E03C31; }}
        #token-info {{ background: #f0f0f0; padding: 15px; border-radius: 4px; word-break: break-all; display: none; }}
        .status {{ padding: 10px; border-radius: 4px; margin: 10px 0; }}
        .status.success {{ background: #d4edda; color: #155724; }}
        .status.error {{ background: #f8d7da; color: #721c24; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Zero Trust Lab - Frontend Application</h1>
        <p>OIDC Authentication + Policy-Based Authorization</p>
    </div>
    
    <div class="card">
        <h2>Step 1: Authenticate with Keycloak (OIDC)</h2>
        <p>Click below to authenticate via Keycloak Identity Provider using OAuth 2.1 Authorization Code flow with PKCE.</p>
        <button class="btn" onclick="login()">Login with Keycloak</button>
        <button class="btn btn-danger" onclick="logout()">Logout</button>
        <div id="token-info"></div>
    </div>
    
    <div class="card">
        <h2>Step 2: Access Protected API</h2>
        <p>After authentication, try accessing the backend API. Your token will be validated by Keycloak and your request authorized by OPA.</p>
        <button class="btn" onclick="callAPI('/api/data')">Read Data (analyst+)</button>
        <button class="btn" onclick="callAPI('/api/admin')">Admin Panel (admin only)</button>
        <div id="api-result"></div>
    </div>

    <div class="card">
        <h2>Zero Trust Flow</h2>
        <p>1. User authenticates with Keycloak (Identity Provider)</p>
        <p>2. Keycloak issues JWT token with user roles</p>
        <p>3. Frontend sends token to Backend API</p>
        <p>4. Backend validates token with Keycloak public key</p>
        <p>5. Backend checks OPA policy (role + resource + time + sensitivity)</p>
        <p>6. Access granted only if ALL checks pass</p>
    </div>

    <script>
        // PKCE helper functions
        function generateCodeVerifier() {{
            const array = new Uint8Array(32);
            crypto.getRandomValues(array);
            return btoa(String.fromCharCode(...array)).replace(/[+/=]/g, '');
        }}
        
        async function generateCodeChallenge(verifier) {{
            const encoder = new TextEncoder();
            const data = encoder.encode(verifier);
            const hash = await crypto.subtle.digest('SHA-256', data);
            return btoa(String.fromCharCode(...new Uint8Array(hash)))
                .replace(/[+]/g, '-').replace(/[/]/g, '_').replace(/=/g, '');
        }}
        
        async function login() {{
            const codeVerifier = generateCodeVerifier();
            sessionStorage.setItem('pkce_verifier', codeVerifier);
            const codeChallenge = await generateCodeChallenge(codeVerifier);
            
            const authUrl = '{KEYCLOAK_URL}/realms/zero-trust-lab/protocol/openid-connect/auth' +
                '?client_id=zt-frontend' +
                '&response_type=code' +
                '&scope=openid profile email' +
                '&redirect_uri=' + encodeURIComponent(window.location.origin + '/callback') +
                '&code_challenge=' + codeChallenge +
                '&code_challenge_method=S256';
            
            window.location.href = authUrl;
        }}
        
        function logout() {{
            sessionStorage.removeItem('access_token');
            document.getElementById('token-info').style.display = 'none';
            document.getElementById('api-result').innerHTML = '';
        }}
        
        async function callAPI(endpoint) {{
            const token = sessionStorage.getItem('access_token');
            if (!token) {{
                document.getElementById('api-result').innerHTML = 
                    '<div class="status error">Please login first!</div>';
                return;
            }}
            try {{
                const resp = await fetch('http://localhost:5000' + endpoint, {{
                    headers: {{ 'Authorization': 'Bearer ' + token }}
                }});
                const data = await resp.json();
                const statusClass = resp.ok ? 'success' : 'error';
                document.getElementById('api-result').innerHTML = 
                    '<div class="status ' + statusClass + '">' +
                    '<strong>Status: ' + resp.status + '</strong><br>' +
                    '<pre>' + JSON.stringify(data, null, 2) + '</pre></div>';
            }} catch(e) {{
                document.getElementById('api-result').innerHTML = 
                    '<div class="status error">API call failed: ' + e.message + '</div>';
            }}
        }}
    </script>
</body>
</html>"""

class FrontendHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(HTML_PAGE.encode())
    
    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 3000), FrontendHandler)
    print("Frontend running on http://localhost:3000")
    server.serve_forever()
```

Create `apps/frontend/Dockerfile`:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY app.py .
EXPOSE 3000
CMD ["python", "app.py"]
```

---

## Appendix C: Quick Start Commands

```bash
# Full environment start
cd zero-trust-lab
docker compose up -d

# Check all services
docker compose ps

# View logs
docker compose logs -f

# Stop everything
docker compose down

# Stop and remove volumes (clean slate)
docker compose down -v
```

## Appendix D: Troubleshooting

| Issue | Solution |
|-------|---------|
| Keycloak won't start | Wait 2-3 min for initialization. Check: `docker logs zt-keycloak` |
| OPA policy errors | Validate Rego syntax: `docker exec zt-opa /opa check /policies` |
| Wazuh dashboard not loading | Wait 3-5 min. Accept self-signed cert. Check: `docker logs zt-wazuh-dashboard` |
| Port conflicts | Change ports in docker-compose.yml. Common conflicts: 443, 8080 |
| Insufficient memory | Wazuh needs ~4GB. Close other applications or reduce Wazuh heap: `-Xms256m -Xmx256m` |
| Network connectivity issues | Rebuild networks: `docker compose down && docker compose up -d` |

---

*Created for Industry Connect Faculty Development Workshop*  
*Covering: Zero Trust Architecture, Modern IAM, Micro-segmentation, SOC Operations, Threat Intelligence, Post-Quantum Cryptography, Red Team/Blue Team*
