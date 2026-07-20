# ============================================================
# Data Classification Policy
# Enforces data handling requirements based on sensitivity labels
#
# Levels: public | internal | confidential | secret
# ============================================================

package data_classification

import future.keywords.if
import future.keywords.in

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

requirements := classification_rules[input.classification]

export_allowed if {
    requirements.export_allowed
}

encryption_required if {
    requirements.encryption_required
}
