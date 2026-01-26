# remediation module for CSPM Lite
# safe opt in auto remediation for limited misconfigurations

from cspm.remediation.base import (
    RemediationResult,
    RemediationAction,
    REMEDIATION_PERMISSIONS,
    SUPPORTED_REMEDIATIONS,
)
from cspm.remediation.aws_ec2 import remediate_ec2_security_group
from cspm.remediation.aws_s3 import remediate_s3_public_access_block

__all__ = [
    "RemediationResult",
    "RemediationAction",
    "REMEDIATION_PERMISSIONS",
    "SUPPORTED_REMEDIATIONS",
    "remediate_ec2_security_group",
    "remediate_s3_public_access_block",
]
