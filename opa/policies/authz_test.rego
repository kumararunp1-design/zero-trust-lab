# ============================================================
# Zero Trust Authorization Policy - Unit Tests
# Run with: docker exec zt-opa /opa test /policies -v
# ============================================================

package authz

import future.keywords.if

# Test: Admin should have full access (any resource, action, sensitivity, time)
test_admin_full_access if {
    allow with input as {
        "user": {"username": "alice", "roles": ["admin"]},
        "resource": "anything",
        "action": "admin",
        "sensitivity": "secret",
        "time": {"hour": 3, "day": "sunday"}
    }
}

# Test: Analyst should be able to read alerts during business hours
test_analyst_read_alerts if {
    allow with input as {
        "user": {"username": "bob", "roles": ["analyst"]},
        "resource": "alerts",
        "action": "read",
        "sensitivity": "internal",
        "time": {"hour": 14, "day": "monday"}
    }
}

# Test: Analyst should NOT be able to write (read-only role)
test_analyst_cannot_write if {
    not allow with input as {
        "user": {"username": "bob", "roles": ["analyst"]},
        "resource": "alerts",
        "action": "write",
        "sensitivity": "internal",
        "time": {"hour": 14, "day": "monday"}
    }
}

# Test: Developer cannot access secret-level data
test_developer_no_secret if {
    not allow with input as {
        "user": {"username": "charlie", "roles": ["developer"]},
        "resource": "code",
        "action": "read",
        "sensitivity": "secret",
        "time": {"hour": 14, "day": "monday"}
    }
}

# Test: Non-admin users denied outside business hours (6 AM - 10 PM)
test_non_admin_after_hours if {
    not allow with input as {
        "user": {"username": "bob", "roles": ["analyst"]},
        "resource": "alerts",
        "action": "read",
        "sensitivity": "internal",
        "time": {"hour": 23, "day": "monday"}
    }
}
