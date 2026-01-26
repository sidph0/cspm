"""
remediation base module (defines contracts and shared types for auto remediation) 

core principles:
- explicitly opt-in
- safe by default
- explainable
- reversible (where possible)
- blocked when permissions are missing
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RemediationStatus(str, Enum):
    # remediation attempt status
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class RemediationAction(str, Enum):
    """supported remediation actions (MVP scope only)"""
    # ec2 Security Group actions
    REMOVE_INGRESS_RULE = "REMOVE_INGRESS_RULE"
    # s3 actions
    ENABLE_PUBLIC_ACCESS_BLOCK = "ENABLE_PUBLIC_ACCESS_BLOCK"


@dataclass
class RemediationResult:
    """
    result of a remediation attempt
    
    Attributes:
        status: SUCCESS, FAILED, or SKIPPED
        reason: human readable explanation of the result
        details: additional structured data (what changed)
        resource_id: the resource that was (or would be) remediated
        rule_id: the rule that triggered this remediation
        action: the remediation type
        dry_run: if it was a dry run (no changes made)
    """
    status: RemediationStatus
    reason: str
    details: dict[str, Any] = field(default_factory=dict)
    resource_id: str = ""
    rule_id: str = ""
    action: RemediationAction | None = None
    dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        """convert to dict for serialization"""
        return {
            "status": self.status.value,
            "reason": self.reason,
            "details": self.details,
            "resource_id": self.resource_id,
            "rule_id": self.rule_id,
            "action": self.action.value if self.action else None,
            "dry_run": self.dry_run,
        }


# permission reqs for each remediation action
REMEDIATION_PERMISSIONS: dict[RemediationAction, list[tuple[str, str]]] = {
    RemediationAction.REMOVE_INGRESS_RULE: [("ec2", "RevokeSecurityGroupIngress")],
    RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK: [("s3", "PutPublicAccessBlock")],
}


# maps rule_id to remediation metadata
# only rules in this dict support auto remediation
SUPPORTED_REMEDIATIONS: dict[str, dict[str, Any]] = {
    "AWS_SG_INGRESS_SSH_WORLD": {
        "supported": True,
        "safe": True,
        "action": RemediationAction.REMOVE_INGRESS_RULE,
        "description": "Remove SSH (port 22) ingress rule allowing 0.0.0.0/0",
        "requires_permissions": REMEDIATION_PERMISSIONS[RemediationAction.REMOVE_INGRESS_RULE],
    },
    "AWS_SG_INGRESS_RDP_WORLD": {
        "supported": True,
        "safe": True,
        "action": RemediationAction.REMOVE_INGRESS_RULE,
        "description": "Remove RDP (port 3389) ingress rule allowing 0.0.0.0/0",
        "requires_permissions": REMEDIATION_PERMISSIONS[RemediationAction.REMOVE_INGRESS_RULE],
    },
    "AWS_SG_INGRESS_ALL_WORLD": {
        "supported": True,
        "safe": True,
        "action": RemediationAction.REMOVE_INGRESS_RULE,
        "description": "Remove ALL traffic ingress rule allowing 0.0.0.0/0",
        "requires_permissions": REMEDIATION_PERMISSIONS[RemediationAction.REMOVE_INGRESS_RULE],
    },
    "AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED": {
        "supported": True,
        "safe": True,
        "action": RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK,
        "description": "Enable all four Public Access Block settings",
        "requires_permissions": REMEDIATION_PERMISSIONS[RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK],
    },
    # Explicitly NOT supported (for transparency)
    "AWS_SG_INGRESS_SSH_ANY": {
        "supported": False,
        "safe": False,
        "action": None,
        "description": "SSH to any CIDR - requires manual review",
        "requires_permissions": [],
    },
    "AWS_S3_BUCKET_POLICY_PUBLIC": {
        "supported": False,
        "safe": False,
        "action": None,
        "description": "Bucket policy changes not supported for auto-fix (business logic)",
        "requires_permissions": [],
    },
}


def get_remediation_metadata(rule_id: str) -> dict[str, Any]:
    """
    get remediation metadata for rule
    
    returns metadata dict with supported key always present
    """
    return SUPPORTED_REMEDIATIONS.get(rule_id, {
        "supported": False,
        "safe": False,
        "action": None,
        "description": "No auto remediation available for this rule",
        "requires_permissions": [],
    })


def check_remediation_permissions(
    coverage: dict[str, Any],
    required_permissions: list[tuple[str, str]],
) -> tuple[bool, str | None]:
    """
    check if all required remediation permissions are available
    
    remediation perms are actually different from rule eval perms

    for MVP return True if coverage exists (assuming perms available) and let the actual remediation call handle perms errors
    
    returns has_permission & missing_permission_str
    """
    if not coverage or not isinstance(coverage, dict):
        # if no coverage data we cant determine perms
        # skip remediation to be safe
        if required_permissions:
            perm = required_permissions[0]
            return False, f"{perm[0]}:{perm[1]}"
        return True, None
    
    # cant check remediation perms directly since they write operations
    # try remediation and handle errors
    # can still gate on the base read perms being available
    # for now if coverage is available, assume remediation is possible and let the actual API call fail if perms are missing
    
    return True, None
