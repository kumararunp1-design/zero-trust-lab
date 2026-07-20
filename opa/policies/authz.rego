# ============================================================
# Zero Trust Authorization Policy
# Implements ABAC (Attribute-Based Access Control)
#
# Combines role-based permissions with contextual checks:
#   - Resource access control (with wildcard support)
#   - Action-level permissions (read, write, delete, admin)
#   - Data sensitivity clearance levels
#   - Time-based access restrictions
#
# Default: DENY (Zero Trust principle - never trust, always verify)
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
# ALL conditions must be satisfied (AND logic)
# ============================================================
allow if {
    # 1. User has a valid role with defined permissions
    some role in input.user.roles
    permissions := role_permissions[role]

    # 2. Role has access to the requested resource (or wildcard)
    resource_allowed(permissions.resources, input.resource)

    # 3. Action is permitted for this role
    input.action in permissions.actions

    # 4. Sensitivity level is within role's clearance
    input.sensitivity in permissions.sensitivity_levels

    # 5. Time-based access control
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
