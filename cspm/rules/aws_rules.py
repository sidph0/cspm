from __future__ import annotations

import json
from typing import Any, Optional

from cspm.remediation.base import get_remediation_metadata


# known CIDR (IPv4/IPv6) values
WORLD_IPV4 = "0.0.0.0/0"
WORLD_IPV6 = "::/0"

# rule permission requirements: map rule_id -> (service, action)
# note - rules require all listed permissions to be available for evaluation
RULE_PERMISSIONS: dict[str, list[tuple[str, str]]] = {
    "AWS_SG_INGRESS_SSH_ANY": [("ec2", "DescribeSecurityGroups")],
    "AWS_SG_INGRESS_SSH_WORLD": [("ec2", "DescribeSecurityGroups")],
    "AWS_SG_INGRESS_RDP_WORLD": [("ec2", "DescribeSecurityGroups")],
    "AWS_SG_INGRESS_ALL_WORLD": [("ec2", "DescribeSecurityGroups")],
    "AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED": [("s3", "ListBuckets"), ("s3", "GetPublicAccessBlock")],
    # GetBucketPolicyStatus is preferred but GetBucketPolicy can be also be used as fallback heuristic
    # need GetBucketPolicyStatus since it's the authoritative source
    "AWS_S3_BUCKET_POLICY_PUBLIC": [("s3", "ListBuckets"), ("s3", "GetBucketPolicyStatus")],
}


def _check_permissions_available(
    coverage: dict[str, Any], required_permissions: list[tuple[str, str]]
) -> tuple[bool, Optional[str]]:
    """
    check if all required permissions are available in coverage.
    
    returns:
        (is_available, missing_permission)
        - is_available - true if all permissions are fine
        - missing_permission - none if available, otherwise service:action format
    """
    if not coverage or not isinstance(coverage, dict):
        if required_permissions:
            return False, f"{required_permissions[0][0]}:{required_permissions[0][1]}"
        return True, None
    
    for service, action in required_permissions:
        service_data = coverage.get(service)
        if not isinstance(service_data, dict):
            return False, f"{service}:{action}"
        
        action_data = service_data.get(action)
        if not isinstance(action_data, dict) or action_data.get("status") != "OK":
            return False, f"{service}:{action}"
    
    return True, None


def run_aws_rules(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """
    AWS rules:
      - SG: SSH open to ANY (used for risk drift as public vs private changes risk)
      - SG: SSH open to world
      - SG: RDP open to world
      - SG: ALL traffic open to world
      - S3: Block Public Access disabled/missing
      - S3: Bucket policy public (via policy status or heuristic)
    """
    findings: list[dict[str, Any]] = []

    aws = snapshot.get("aws", {})
    regions = aws.get("regions", {})
    coverage = aws.get("coverage", {})

    # -------------------------
    # Security Group rules
    # -------------------------
    for region, region_data in regions.items():
        # if the collector recorded an error for this region, then skip rules
        if isinstance(region_data, dict) and region_data.get("error"):
            continue

        security_groups = region_data.get("security_groups", []) if isinstance(region_data, dict) else []
        for sg in security_groups:
            # security group id + its permissions
            sg_id = sg.get("group_id") or "unknown-sg"
            perms = sg.get("ip_permissions", []) or []

            # -------------------------
            # SSH open to ANY (show risk drift)
            # persists across scans even if CIDR changes so risk can increase / decrease
            # -------------------------
            rule_id = "AWS_SG_INGRESS_SSH_ANY"
            required_perms = RULE_PERMISSIONS.get(rule_id, [])
            has_perms, missing_perm = _check_permissions_available(coverage, required_perms)
            
            if not has_perms:
                findings.append(
                    _make_not_evaluated_finding(
                        rule_id=rule_id,
                        region=region,
                        resource_type="security_group",
                        resource_id=sg_id,
                        missing_permission=missing_perm or "unknown",
                    )
                )
            else:
                ssh_any = _sg_find_port_any_cidr(perms, 22)
                if ssh_any is not None:
                    cidr, evidence = ssh_any
                    findings.append(
                        _make_finding(
                            rule_id=rule_id,
                            region=region,
                            resource_type="security_group",
                            resource_id=sg_id,
                            evidence=f"{evidence} (cidr={cidr})",
                            severity=70,
                            is_public=_is_world_cidr(cidr),
                        )
                    )

            # existing - SSH open to world
            rule_id = "AWS_SG_INGRESS_SSH_WORLD"
            required_perms = RULE_PERMISSIONS.get(rule_id, [])
            has_perms, missing_perm = _check_permissions_available(coverage, required_perms)
            
            if not has_perms:
                findings.append(
                    _make_not_evaluated_finding(
                        rule_id=rule_id,
                        region=region,
                        resource_type="security_group",
                        resource_id=sg_id,
                        missing_permission=missing_perm or "unknown",
                    )
                )
            elif _sg_allows_port_from_world(perms, 22):
                findings.append(
                    _make_finding(
                        rule_id=rule_id,
                        region=region,
                        resource_type="security_group",
                        resource_id=sg_id,
                        evidence=_build_sg_evidence(perms, 22),
                        severity=90,
                        is_public=True,
                    )
                )

            # RDP
            rule_id = "AWS_SG_INGRESS_RDP_WORLD"
            required_perms = RULE_PERMISSIONS.get(rule_id, [])
            has_perms, missing_perm = _check_permissions_available(coverage, required_perms)
            
            if not has_perms:
                findings.append(
                    _make_not_evaluated_finding(
                        rule_id=rule_id,
                        region=region,
                        resource_type="security_group",
                        resource_id=sg_id,
                        missing_permission=missing_perm or "unknown",
                    )
                )
            elif _sg_allows_port_from_world(perms, 3389):
                findings.append(
                    _make_finding(
                        rule_id=rule_id,
                        region=region,
                        resource_type="security_group",
                        resource_id=sg_id,
                        evidence=_build_sg_evidence(perms, 3389),
                        severity=90,
                        is_public=True,
                    )
                )

            # any protocol/port allowed from 0.0.0.0/0 or ::/0
            rule_id = "AWS_SG_INGRESS_ALL_WORLD"
            required_perms = RULE_PERMISSIONS.get(rule_id, [])
            has_perms, missing_perm = _check_permissions_available(coverage, required_perms)
            
            if not has_perms:
                findings.append(
                    _make_not_evaluated_finding(
                        rule_id=rule_id,
                        region=region,
                        resource_type="security_group",
                        resource_id=sg_id,
                        missing_permission=missing_perm or "unknown",
                    )
                )
            elif _sg_allows_all_traffic_from_world(perms):
                findings.append(
                    _make_finding(
                        rule_id=rule_id,
                        region=region,
                        resource_type="security_group",
                        resource_id=sg_id,
                        evidence=_build_sg_all_traffic_evidence(perms),
                        severity=95,
                        is_public=True,
                    )
                )

    # -------------------------
    # S3 rules (bucket-level)
    # Stored under aws.s3.buckets by collector
    # -------------------------
    s3 = aws.get("s3", {})
    buckets = s3.get("buckets", []) if isinstance(s3, dict) else []

    for b in buckets:
        bucket_name = b.get("name") or "unknown-bucket"
        bucket_region = b.get("region") or "unknown-region"

        # S3 Public Access Block rule
        rule_id = "AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED"
        required_perms = RULE_PERMISSIONS.get(rule_id, [])
        has_perms, missing_perm = _check_permissions_available(coverage, required_perms)
        
        if not has_perms:
            findings.append(
                _make_not_evaluated_finding(
                    rule_id=rule_id,
                    region=bucket_region,
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    missing_permission=missing_perm or "unknown",
                )
            )
        else:
            pab = b.get("public_access_block")  # dict or None
            # if PublicAccessBlock is missing or not fully restrictive then flag it
            if _public_access_block_is_missing_or_not_blocking(pab):
                findings.append(
                    _make_finding(
                        rule_id=rule_id,
                        region=bucket_region,
                        resource_type="s3_bucket",
                        resource_id=bucket_name,
                        evidence=_build_s3_pab_evidence(pab),
                        severity=80,
                        is_public=True,  # shows increased exposure risk
                    )
                )

        # S3 Bucket Policy Public rule
        rule_id = "AWS_S3_BUCKET_POLICY_PUBLIC"
        required_perms = RULE_PERMISSIONS.get(rule_id, [])
        has_perms, missing_perm = _check_permissions_available(coverage, required_perms)
        
        if not has_perms:
            findings.append(
                _make_not_evaluated_finding(
                    rule_id=rule_id,
                    region=bucket_region,
                    resource_type="s3_bucket",
                    resource_id=bucket_name,
                    missing_permission=missing_perm or "unknown",
                )
            )
        else:
            # prefer aws provided policy status if present
            policy_status = b.get("policy_status")
            # either explicit policy status from AWS or a heuristic
            if _policy_status_is_public(policy_status) or _policy_looks_public(b.get("policy")):
                findings.append(
                    _make_finding(
                        rule_id=rule_id,
                        region=bucket_region,
                        resource_type="s3_bucket",
                        resource_id=bucket_name,
                        evidence=_build_s3_policy_evidence(policy_status, b.get("policy")),
                        severity=85,
                        is_public=True,
                    )
                )

    return findings


def _make_finding(
    *,
    rule_id: str,
    region: str,
    resource_type: str,
    resource_id: str,
    evidence: str,
    severity: int,
    is_public: bool = False,
) -> dict[str, Any]:
    # compact finding record consumed by reporting code
    # includes remediation metadata for auto fix capability
    remediation_meta = get_remediation_metadata(rule_id)
    
    return {
        "provider": "aws",
        "rule_id": rule_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "region": region,
        "severity": severity,
        "evidence": evidence,
        "is_public": bool(is_public),
        "status": "EVALUATED",  # normal finding
        "remediation": {
            "supported": remediation_meta.get("supported", False),
            "safe": remediation_meta.get("safe", False),
            "action": remediation_meta.get("action").value if remediation_meta.get("action") else None,
            "description": remediation_meta.get("description", ""),
            "requires_permissions": [
                f"{svc}:{act}" for svc, act in remediation_meta.get("requires_permissions", [])
            ],
        },
    }


def _make_not_evaluated_finding(
    *,
    rule_id: str,
    region: str,
    resource_type: str,
    resource_id: str,
    missing_permission: str,
) -> dict[str, Any]:
    """
    create finding record for a rule that cant be evaluated due to missing perms
    """
    # not evaluated findings dont support remediation
    return {
        "provider": "aws",
        "rule_id": rule_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "region": region,
        "severity": 0,  # not useful for not evaluated findings
        "evidence": f"Rule not evaluated: missing permission {missing_permission}",
        "is_public": False,
        "status": "NOT_EVALUATED",
        "missing_permission": missing_permission,
        "remediation": {
            "supported": False,
            "safe": False,
            "action": None,
            "description": "Cannot remediate: rule not evaluated",
            "requires_permissions": [],
        },
    }


# -------------------------
# SG helpers
# -------------------------
def _is_world_cidr(cidr: str) -> bool:
    c = (cidr or "").strip()
    return c == WORLD_IPV4 or c == WORLD_IPV6


def _sg_allows_port_from_world(ip_permissions: list[dict[str, Any]], port: int) -> bool:
    # `ip_permissions` follows aws DescribeSecurityGroups IpPermissions shape
    for perm in ip_permissions:
        if not _perm_matches_port(perm, port):
            continue

        for r in perm.get("IpRanges", []) or []:
            if (r.get("CidrIp") or "").strip() == WORLD_IPV4:
                return True

        for r in perm.get("Ipv6Ranges", []) or []:
            if (r.get("CidrIpv6") or "").strip() == WORLD_IPV6:
                return True

    return False


def _sg_find_port_any_cidr(ip_permissions: list[dict[str, Any]], port: int) -> tuple[str, str] | None:
    """
    return (cidr, evidence) for the first cidr rule found that allows the port
    (check ipv4 then ipv6, used for SSH_ANY rule to show drift)
    """
    for perm in ip_permissions:
        if not _perm_matches_port(perm, port):
            continue

        proto = perm.get("IpProtocol")
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        for r in perm.get("IpRanges", []) or []:
            cidr = (r.get("CidrIp") or "").strip()
            if cidr:
                desc = (r.get("Description") or "").strip()
                ev = _fmt_sg_evidence(proto, from_port, to_port, cidr, desc)
                return cidr, ev

        for r in perm.get("Ipv6Ranges", []) or []:
            cidr = (r.get("CidrIpv6") or "").strip()
            if cidr:
                desc = (r.get("Description") or "").strip()
                ev = _fmt_sg_evidence(proto, from_port, to_port, cidr, desc)
                return cidr, ev

    return None


def _sg_allows_all_traffic_from_world(ip_permissions: list[dict[str, Any]]) -> bool:
    for perm in ip_permissions:
        if perm.get("IpProtocol") != "-1":
            continue

        for r in perm.get("IpRanges", []) or []:
            if (r.get("CidrIp") or "").strip() == WORLD_IPV4:
                return True

        for r in perm.get("Ipv6Ranges", []) or []:
            if (r.get("CidrIpv6") or "").strip() == WORLD_IPV6:
                return True

    return False


def _perm_matches_port(perm: dict[str, Any], port: int) -> bool:
    proto = perm.get("IpProtocol")

    # -1 means all protocols/ports
    if proto == "-1":
        return True

    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")

    # if ports are missing we cant reliably match
    if from_port is None or to_port is None:
        return False

    try:
        return int(from_port) <= port <= int(to_port)
    except (TypeError, ValueError):
        return False


def _build_sg_evidence(ip_permissions: list[dict[str, Any]], port: int) -> str:
    for perm in ip_permissions:
        if not _perm_matches_port(perm, port):
            continue

        proto = perm.get("IpProtocol")
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        for r in perm.get("IpRanges", []) or []:
            if (r.get("CidrIp") or "").strip() == WORLD_IPV4:
                desc = (r.get("Description") or "").strip()
                return _fmt_sg_evidence(proto, from_port, to_port, WORLD_IPV4, desc)

        for r in perm.get("Ipv6Ranges", []) or []:
            if (r.get("CidrIpv6") or "").strip() == WORLD_IPV6:
                desc = (r.get("Description") or "").strip()
                return _fmt_sg_evidence(proto, from_port, to_port, WORLD_IPV6, desc)

    return f"Port {port} exposed to world (rule matched)"


def _build_sg_all_traffic_evidence(ip_permissions: list[dict[str, Any]]) -> str:
    for perm in ip_permissions:
        if perm.get("IpProtocol") != "-1":
            continue

        for r in perm.get("IpRanges", []) or []:
            if (r.get("CidrIp") or "").strip() == WORLD_IPV4:
                desc = (r.get("Description") or "").strip()
                return _fmt_sg_evidence("-1", None, None, WORLD_IPV4, desc)

        for r in perm.get("Ipv6Ranges", []) or []:
            if (r.get("CidrIpv6") or "").strip() == WORLD_IPV6:
                desc = (r.get("Description") or "").strip()
                return _fmt_sg_evidence("-1", None, None, WORLD_IPV6, desc)

    return "All traffic exposed to world (rule matched)"


def _fmt_sg_evidence(proto: Any, from_port: Any, to_port: Any, cidr: str, desc: str) -> str:
    proto_s = str(proto)
    if proto_s == "-1":
        port_s = "all ports"
    else:
        if from_port is None or to_port is None:
            port_s = "unknown port range"
        elif from_port == to_port:
            port_s = f"port {from_port}"
        else:
            port_s = f"ports {from_port}-{to_port}"

    if desc:
        return f"{cidr} allows {port_s} ({proto_s}) | {desc}"
    return f"{cidr} allows {port_s} ({proto_s})"


# -------------------------
# S3 helpers
# -------------------------
def _public_access_block_is_missing_or_not_blocking(pab: Any) -> bool:
    """
    PublicAccessBlock should have all 4 booleans True to be fully blocking
    if missing / any False -> treat as not fully blocking
    """
    if not isinstance(pab, dict):
        return True

    cfg = pab.get("PublicAccessBlockConfiguration")
    if not isinstance(cfg, dict):
        return True

    required = [
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    ]
    for k in required:
        if cfg.get(k) is not True:
            return True
    return False


def _policy_status_is_public(policy_status: Any) -> bool:
    """
    get_bucket_policy_status returns {"PolicyStatus": {"IsPublic": true/false}}
    """
    if not isinstance(policy_status, dict):
        return False
    ps = policy_status.get("PolicyStatus")
    if not isinstance(ps, dict):
        return False
    return ps.get("IsPublic") is True


def _policy_looks_public(policy: Any) -> bool:
    """
    heuristic fallback if there is a policy document string/dict
    """
    if not policy:
        return False

    try:
        if isinstance(policy, str):
            obj = json.loads(policy)
        elif isinstance(policy, dict):
            obj = policy
        else:
            return False
    except Exception:
        return False

    stmts = obj.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return False

    for st in stmts:
        if not isinstance(st, dict):
            continue
        if st.get("Effect") != "Allow":
            continue

        principal = st.get("Principal")
        # If Principal is a wildcard then the policy allows public access
        if principal == "*" or principal == {"AWS": "*"}:
            return True

    return False


def _build_s3_pab_evidence(pab: Any) -> str:
    if not pab:
        return "PublicAccessBlock missing (treated as not fully blocking public access)"
    cfg = pab.get("PublicAccessBlockConfiguration", {})
    return (
        # Summarize which flags are enabled/disabled for easier triage
        "PublicAccessBlock not fully enabled: "
        f"BlockPublicAcls={cfg.get('BlockPublicAcls')}, "
        f"IgnorePublicAcls={cfg.get('IgnorePublicAcls')}, "
        f"BlockPublicPolicy={cfg.get('BlockPublicPolicy')}, "
        f"RestrictPublicBuckets={cfg.get('RestrictPublicBuckets')}"
    )


def _build_s3_policy_evidence(policy_status: Any, policy: Any) -> str:
    if _policy_status_is_public(policy_status):
        return "Bucket policy status indicates IsPublic=True"
    if policy:
        return "Bucket policy appears public (heuristic match on Allow + Principal='*')"
    return "Bucket policy appears public (rule matched)"
