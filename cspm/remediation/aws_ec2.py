"""
AWS EC2 remediation module

safe remediation of EC2 SG Ingress rules:
- SSH (port 22) from 0.0.0.0/0 or ::/0
- RDP (port 3389) from 0.0.0.0/0 or ::/0
- ALL traffic (IpProtocol=-1) from 0.0.0.0/0 or ::/0

Guardrails:
- skip if perm missing
- skip if rule cannot be uniquely identified
- support dry run mode
- never delete entire SGs
- only remove the specific offending CIDR + port combo
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


# world CIDRs being remediated
WORLD_IPV4 = "0.0.0.0/0"
WORLD_IPV6 = "::/0"


def remediate_ec2_security_group(
    finding: dict[str, Any],
    *,
    dry_run: bool = True,
    demo_mode: bool = False,
) -> RemediationResult:
    """
    remediate an EC2 SG ingress rule finding
    
    rule_ids:
    - AWS_SG_INGRESS_SSH_WORLD: Remove SSH (22) from 0.0.0.0/0
    - AWS_SG_INGRESS_RDP_WORLD: Remove RDP (3389) from 0.0.0.0/0
    - AWS_SG_INGRESS_ALL_WORLD: Remove ALL traffic (-1) from 0.0.0.0/0
    
    args:
        finding: the finding dict from rule eval
        dry_run: if true, only preview changes (no AWS API mutation)
        demo_mode: if true, return mocked success without AWS calls
    
    returns RemediationResult with status, reason, and details
    """
    rule_id = finding.get("rule_id", "")
    resource_id = finding.get("resource_id", "")  # SG ID
    region = finding.get("region", "")
    
    # determine port/protocol to remove based on rule_id
    target = _get_target_for_rule(rule_id)
    if target is None:
        return RemediationResult(
            status=RemediationStatus.SKIPPED,
            reason=f"Rule {rule_id} is not supported for auto remediation",
            resource_id=resource_id,
            rule_id=rule_id,
            action=None,
            dry_run=dry_run,
        )
    
    port, protocol, description = target
    
    # validate required fields
    if not resource_id or not region:
        return RemediationResult(
            status=RemediationStatus.SKIPPED,
            reason="Missing resource_id or region in finding",
            resource_id=resource_id,
            rule_id=rule_id,
            action=RemediationAction.REMOVE_INGRESS_RULE,
            dry_run=dry_run,
        )
    
    if demo_mode:
        return _mock_remediation_result(
            rule_id=rule_id,
            resource_id=resource_id,
            port=port,
            protocol=protocol,
            dry_run=dry_run,
        )
    
    # build ingress rule to revoke
    # we need to revoke both IPv4 and IPv6 world CIDRs if they exist
    revoke_results = []
    
    try:
        ec2 = boto3.client("ec2", region_name=region)
        
        # build IP permissions to revoke for IPv4
        ip_perms_v4 = _build_ip_permission(port, protocol, WORLD_IPV4, is_ipv6=False)
        # build IP permissions to revoke for IPv6
        ip_perms_v6 = _build_ip_permission(port, protocol, WORLD_IPV6, is_ipv6=True)
        
        # try to revoke IPv4 rule
        v4_result = _revoke_ingress_rule(
            ec2, resource_id, ip_perms_v4, 
            dry_run=dry_run, 
            cidr=WORLD_IPV4,
            port=port,
            protocol=protocol,
        )
        if v4_result:
            revoke_results.append(v4_result)
        
        # try to revoke IPv6 rule
        v6_result = _revoke_ingress_rule(
            ec2, resource_id, ip_perms_v6,
            dry_run=dry_run,
            cidr=WORLD_IPV6,
            port=port,
            protocol=protocol,
        )
        if v6_result:
            revoke_results.append(v6_result)
        
        # determine overall status
        if not revoke_results:
            return RemediationResult(
                status=RemediationStatus.SKIPPED,
                reason="No matching ingress rules found to revoke",
                resource_id=resource_id,
                rule_id=rule_id,
                action=RemediationAction.REMOVE_INGRESS_RULE,
                dry_run=dry_run,
            )
        
        # check if any succeeded or would succeed
        successes = [r for r in revoke_results if r["status"] in ("SUCCESS", "DRY_RUN")]
        if successes:
            if dry_run:
                return RemediationResult(
                    status=RemediationStatus.SUCCESS,
                    reason=f"[DRY-RUN] Would revoke {description} from {resource_id}",
                    details={"revoked_rules": revoke_results},
                    resource_id=resource_id,
                    rule_id=rule_id,
                    action=RemediationAction.REMOVE_INGRESS_RULE,
                    dry_run=True,
                )
            else:
                return RemediationResult(
                    status=RemediationStatus.SUCCESS,
                    reason=f"Revoked {description} from {resource_id}",
                    details={"revoked_rules": revoke_results},
                    resource_id=resource_id,
                    rule_id=rule_id,
                    action=RemediationAction.REMOVE_INGRESS_RULE,
                    dry_run=False,
                )
        else:
            # all attempts failed
            return RemediationResult(
                status=RemediationStatus.FAILED,
                reason=f"Failed to revoke rules: {revoke_results}",
                details={"revoked_rules": revoke_results},
                resource_id=resource_id,
                rule_id=rule_id,
                action=RemediationAction.REMOVE_INGRESS_RULE,
                dry_run=dry_run,
            )
            
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "UnknownError")
        error_msg = e.response.get("Error", {}).get("Message", str(e))
        
        # handle perm errors specifically
        if error_code in ("UnauthorizedOperation", "AccessDenied"):
            return RemediationResult(
                status=RemediationStatus.SKIPPED,
                reason=f"Missing permission: ec2:RevokeSecurityGroupIngress",
                details={"error_code": error_code, "error_message": error_msg},
                resource_id=resource_id,
                rule_id=rule_id,
                action=RemediationAction.REMOVE_INGRESS_RULE,
                dry_run=dry_run,
            )
        
        return RemediationResult(
            status=RemediationStatus.FAILED,
            reason=f"AWS API error: {error_code} - {error_msg}",
            details={"error_code": error_code, "error_message": error_msg},
            resource_id=resource_id,
            rule_id=rule_id,
            action=RemediationAction.REMOVE_INGRESS_RULE,
            dry_run=dry_run,
        )
    except BotoCoreError as e:
        return RemediationResult(
            status=RemediationStatus.FAILED,
            reason=f"AWS SDK error: {str(e)}",
            resource_id=resource_id,
            rule_id=rule_id,
            action=RemediationAction.REMOVE_INGRESS_RULE,
            dry_run=dry_run,
        )


def _get_target_for_rule(rule_id: str) -> tuple[int | None, str, str] | None:
    """
    get the target port/protocol for a rule
    
    returns:
        (port, protocol, description) or None if not supported
        port=None means all ports (protocol=-1)
    """
    if rule_id == "AWS_SG_INGRESS_SSH_WORLD":
        return (22, "tcp", "SSH (port 22) from 0.0.0.0/0")
    elif rule_id == "AWS_SG_INGRESS_RDP_WORLD":
        return (3389, "tcp", "RDP (port 3389) from 0.0.0.0/0")
    elif rule_id == "AWS_SG_INGRESS_ALL_WORLD":
        return (None, "-1", "ALL traffic from 0.0.0.0/0")
    return None


def _build_ip_permission(
    port: int | None,
    protocol: str,
    cidr: str,
    is_ipv6: bool,
) -> list[dict[str, Any]]:
    """build the IP perms structure for revoke_security_group_ingress"""
    perm: dict[str, Any] = {
        "IpProtocol": protocol,
    }
    
    # for all traffic (-1) don't specify ports
    if port is not None:
        perm["FromPort"] = port
        perm["ToPort"] = port
    
    if is_ipv6:
        perm["Ipv6Ranges"] = [{"CidrIpv6": cidr}]
    else:
        perm["IpRanges"] = [{"CidrIp": cidr}]
    
    return [perm]


def _revoke_ingress_rule(
    ec2_client: Any,
    security_group_id: str,
    ip_permissions: list[dict[str, Any]],
    *,
    dry_run: bool,
    cidr: str,
    port: int | None,
    protocol: str,
) -> dict[str, Any] | None:
    """
    attempt to revoke an ingress rule
    
    returns a result dict or None if the rule doesn't exist
    """
    try:
        # AWS dry_run param causes a DryRunOperation error on success
        ec2_client.revoke_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=ip_permissions,
            DryRun=dry_run,
        )
        # if we get here without dry_run, operation succeeded
        return {
            "status": "SUCCESS",
            "cidr": cidr,
            "port": port if port else "all",
            "protocol": protocol,
        }
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        
        # DryRunOperation means the call would succeed
        if error_code == "DryRunOperation":
            return {
                "status": "DRY_RUN",
                "cidr": cidr,
                "port": port if port else "all",
                "protocol": protocol,
                "message": "Would succeed if not dry-run",
            }
        
        # InvalidPermission.NotFound means rule doesn't exist (skip silently)
        if error_code == "InvalidPermission.NotFound":
            return None
        
        # reraise other errors
        raise


def _mock_remediation_result(
    rule_id: str,
    resource_id: str,
    port: int | None,
    protocol: str,
    dry_run: bool,
) -> RemediationResult:
    """mock remediation result for demo mode"""
    port_str = str(port) if port else "all"
    
    if dry_run:
        return RemediationResult(
            status=RemediationStatus.SUCCESS,
            reason=f"[DRY-RUN] Would revoke {protocol} port {port_str} from 0.0.0.0/0 on {resource_id}",
            details={
                "revoked_rules": [
                    {
                        "status": "DRY_RUN",
                        "cidr": WORLD_IPV4,
                        "port": port_str,
                        "protocol": protocol,
                        "message": "[DEMO] Would succeed if not dry-run",
                    }
                ],
                "demo_mode": True,
            },
            resource_id=resource_id,
            rule_id=rule_id,
            action=RemediationAction.REMOVE_INGRESS_RULE,
            dry_run=True,
        )
    else:
        return RemediationResult(
            status=RemediationStatus.SUCCESS,
            reason=f"[DEMO] Revoked {protocol} port {port_str} from 0.0.0.0/0 on {resource_id}",
            details={
                "revoked_rules": [
                    {
                        "status": "SUCCESS",
                        "cidr": WORLD_IPV4,
                        "port": port_str,
                        "protocol": protocol,
                        "message": "[DEMO] Simulated success",
                    }
                ],
                "demo_mode": True,
            },
            resource_id=resource_id,
            rule_id=rule_id,
            action=RemediationAction.REMOVE_INGRESS_RULE,
            dry_run=False,
        )
