"""
AWS S3 remediation module

safe remediation of S3 bucket misconfigs:
- enable Public Access Block (all four flags = True)

Guardrails:
- no bucket policy edits (business logic concerns)
- no bucket deletion
- support dry run mode
- skip if perm missing
"""
from __future__ import annotations

from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cspm.remediation.base import (
    RemediationResult,
    RemediationStatus,
    RemediationAction,
)


def remediate_s3_public_access_block(
    finding: dict[str, Any],
    *,
    dry_run: bool = True,
    demo_mode: bool = False,
) -> RemediationResult:
    """
    remediate S3 bucket by enabling all PAB settings.
    
    rule_ids:
    - AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED: Enable all four PAB settings
    
    args:
        finding: the finding dict from rule eval
        dry_run: if true, only preview changes (no AWS API mutation)
        demo_mode: if true, return mocked success without AWS calls
    
    returns RemediationResult with status, reason, and details
    """
    rule_id = finding.get("rule_id", "")
    resource_id = finding.get("resource_id", "")  # bucket name
    
    # only support PAB rule
    if rule_id != "AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED":
        return RemediationResult(
            status=RemediationStatus.SKIPPED,
            reason=f"Rule {rule_id} is not supported for S3 auto-remediation",
            resource_id=resource_id,
            rule_id=rule_id,
            action=None,
            dry_run=dry_run,
        )
    
    # validate required fields
    if not resource_id:
        return RemediationResult(
            status=RemediationStatus.SKIPPED,
            reason="Missing resource_id (bucket name) in finding",
            resource_id=resource_id,
            rule_id=rule_id,
            action=RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK,
            dry_run=dry_run,
        )
    
    if demo_mode:
        return _mock_remediation_result(
            rule_id=rule_id,
            resource_id=resource_id,
            dry_run=dry_run,
        )
    
    # the PAB config to set
    pab_config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    
    # dry run mode: verify we can access the bucket but dont change anything
    if dry_run:
        try:
            s3 = boto3.client("s3")
            
            # check if bucket exists / access
            # (head_bucket is a lightweight check)
            s3.head_bucket(Bucket=resource_id)
            
            # get current PAB to show what would change
            try:
                current_pab = s3.get_public_access_block(Bucket=resource_id)
                current_config = current_pab.get("PublicAccessBlockConfiguration", {})
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") in (
                    "NoSuchPublicAccessBlockConfiguration",
                    "NoSuchPublicAccessBlock",
                ):
                    current_config = None
                else:
                    raise
            
            return RemediationResult(
                status=RemediationStatus.SUCCESS,
                reason=f"[DRY-RUN] Would enable Public Access Block on {resource_id}",
                details={
                    "current_config": current_config,
                    "new_config": pab_config,
                },
                resource_id=resource_id,
                rule_id=rule_id,
                action=RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK,
                dry_run=True,
            )
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "UnknownError")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            
            if error_code in ("AccessDenied", "403"):
                return RemediationResult(
                    status=RemediationStatus.SKIPPED,
                    reason=f"Missing permission: s3:PutPublicAccessBlock",
                    details={"error_code": error_code, "error_message": error_msg},
                    resource_id=resource_id,
                    rule_id=rule_id,
                    action=RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK,
                    dry_run=True,
                )
            
            return RemediationResult(
                status=RemediationStatus.FAILED,
                reason=f"AWS API error: {error_code} - {error_msg}",
                details={"error_code": error_code, "error_message": error_msg},
                resource_id=resource_id,
                rule_id=rule_id,
                action=RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK,
                dry_run=True,
            )
        except BotoCoreError as e:
            return RemediationResult(
                status=RemediationStatus.FAILED,
                reason=f"AWS SDK error: {str(e)}",
                resource_id=resource_id,
                rule_id=rule_id,
                action=RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK,
                dry_run=True,
            )
    
    # actual remediation (not dry run)
    try:
        s3 = boto3.client("s3")
        
        # get current config for comparison
        try:
            current_pab = s3.get_public_access_block(Bucket=resource_id)
            current_config = current_pab.get("PublicAccessBlockConfiguration", {})
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in (
                "NoSuchPublicAccessBlockConfiguration",
                "NoSuchPublicAccessBlock",
            ):
                current_config = None
            else:
                raise
        
        # apply the Public Access Block
        s3.put_public_access_block(
            Bucket=resource_id,
            PublicAccessBlockConfiguration=pab_config,
        )
        
        return RemediationResult(
            status=RemediationStatus.SUCCESS,
            reason=f"Enabled Public Access Block on {resource_id}",
            details={
                "previous_config": current_config,
                "new_config": pab_config,
            },
            resource_id=resource_id,
            rule_id=rule_id,
            action=RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK,
            dry_run=False,
        )
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "UnknownError")
        error_msg = e.response.get("Error", {}).get("Message", str(e))
        
        if error_code in ("AccessDenied", "403"):
            return RemediationResult(
                status=RemediationStatus.SKIPPED,
                reason=f"Missing permission: s3:PutPublicAccessBlock",
                details={"error_code": error_code, "error_message": error_msg},
                resource_id=resource_id,
                rule_id=rule_id,
                action=RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK,
                dry_run=False,
            )
        
        return RemediationResult(
            status=RemediationStatus.FAILED,
            reason=f"AWS API error: {error_code} - {error_msg}",
            details={"error_code": error_code, "error_message": error_msg},
            resource_id=resource_id,
            rule_id=rule_id,
            action=RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK,
            dry_run=False,
        )
    except BotoCoreError as e:
        return RemediationResult(
            status=RemediationStatus.FAILED,
            reason=f"AWS SDK error: {str(e)}",
            resource_id=resource_id,
            rule_id=rule_id,
            action=RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK,
            dry_run=False,
        )


def _mock_remediation_result(
    rule_id: str,
    resource_id: str,
    dry_run: bool,
) -> RemediationResult:
    """return mock remediation result for demo mode"""
    pab_config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    
    # "before" config showing disabled settings
    mock_before = {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
    
    if dry_run:
        return RemediationResult(
            status=RemediationStatus.SUCCESS,
            reason=f"[DRY-RUN] Would enable Public Access Block on {resource_id}",
            details={
                "current_config": mock_before,
                "new_config": pab_config,
                "demo_mode": True,
            },
            resource_id=resource_id,
            rule_id=rule_id,
            action=RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK,
            dry_run=True,
        )
    else:
        return RemediationResult(
            status=RemediationStatus.SUCCESS,
            reason=f"[DEMO] Enabled Public Access Block on {resource_id}",
            details={
                "previous_config": mock_before,
                "new_config": pab_config,
                "demo_mode": True,
            },
            resource_id=resource_id,
            rule_id=rule_id,
            action=RemediationAction.ENABLE_PUBLIC_ACCESS_BLOCK,
            dry_run=False,
        )
