from __future__ import annotations

from typing import Any


WORLD_IPV4 = "0.0.0.0/0"
WORLD_IPV6 = "::/0"

# known CIDR (IPv4/IPv6) values

def run_aws_rules(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """
    run aws misconfiguration rules against the snapshot
    gives a list of findings (dicts) that can be scored / reported
    """
    findings: list[dict[str, Any]] = []

    # top level aws section of the snapshot
    aws_section = snapshot.get("aws", {})
    regions = aws_section.get("regions", {})

    for region, region_data in regions.items():
        # if the collector recorded an error for this region, then skip rules
        if isinstance(region_data, dict) and region_data.get("error"):
            continue

        security_groups = region_data.get("security_groups", []) if isinstance(region_data, dict) else []
        for security_group in security_groups:
            # security group id + its permissions
            security_group_id = security_group.get("group_id") or "unknown-sg"
            permissions = security_group.get("ip_permissions", []) or []

            # rule - SSH open to world
            if _sg_allows_port_from_world(permissions, 22):
                evidence = _build_evidence(permissions, 22)
                findings.append(
                    _make_finding(
                        rule_id="AWS_SG_INGRESS_SSH_WORLD",
                        region=region,
                        resource_id=security_group_id,
                        evidence=evidence,
                        severity=90,
                    )
                )

            # rule - RDP open to world
            if _sg_allows_port_from_world(permissions, 3389):
                evidence = _build_evidence(permissions, 3389)
                findings.append(
                    _make_finding(
                        rule_id="AWS_SG_INGRESS_RDP_WORLD",
                        region=region,
                        resource_id=security_group_id,
                        evidence=evidence,
                        severity=90,
                    )
                )

    return findings


def _make_finding(
    *,
    rule_id: str,
    region: str,
    resource_id: str,
    evidence: str,
    severity: int,
) -> dict[str, Any]:
    # build a normal finding dict for reporting/scoring
    return {
        "provider": "aws",
        "rule_id": rule_id,
        "resource_type": "security_group",
        "resource_id": resource_id,
        "region": region,
        "severity": severity,
        "evidence": evidence,
    }


def _sg_allows_port_from_world(ip_permissions: list[dict[str, Any]], port: int) -> bool:
    """
    returns True if any permission allows the given port from 0.0.0.0/0 or ::/0
    """
    for permission in ip_permissions:
        if not _perm_matches_port(permission, port):
            continue

        # IPv4 ranges
        for ip_range in permission.get("IpRanges", []) or []:
            if (ip_range.get("CidrIp") or "").strip() == WORLD_IPV4:
                return True

        # IPv6 ranges
        for ip_range in permission.get("Ipv6Ranges", []) or []:
            if (ip_range.get("CidrIpv6") or "").strip() == WORLD_IPV6:
                return True

    return False


def _perm_matches_port(perm: dict[str, Any], port: int) -> bool:
    """
    returns True if the permission covers the port (TCP/UDP) OR is "all traffic".
    notes:
      - IpProtocol '-1' means all protocols/ports
      - FromPort/ToPort may be missing for some protocols or when -1
    """
    proto = perm.get("IpProtocol")

    # all traffic
    if proto == "-1": # -1 means all protocols
        return True

    # if protocol is something else (tcp/udp), check range when present
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")

    # if ports are not provided, then we cant confidently match specific port
    if from_port is None or to_port is None:
        return False

    try:
        return int(from_port) <= port <= int(to_port)
    except (TypeError, ValueError):
        return False


def _build_evidence(ip_permissions: list[dict[str, Any]], port: int) -> str:
    """
    build a short evidence string for reporting
    -   tries to include the first matching rule that exposes the port to world
    """
    for permission in ip_permissions:
        if not _perm_matches_port(permission, port):
            continue

        # get protocol and port info
        proto = permission.get("IpProtocol")
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        for ip_range in permission.get("IpRanges", []) or []:
            if (ip_range.get("CidrIp") or "").strip() == WORLD_IPV4:
                desc = (ip_range.get("Description") or "").strip()
                return _fmt_evidence(proto, from_port, to_port, WORLD_IPV4, desc)

        for ip_range in permission.get("Ipv6Ranges", []) or []:
            if (ip_range.get("CidrIpv6") or "").strip() == WORLD_IPV6:
                desc = (ip_range.get("Description") or "").strip()
                return _fmt_evidence(proto, from_port, to_port, WORLD_IPV6, desc)

    return f"Port {port} exposed to world (rule matched)"


def _fmt_evidence(proto: Any, from_port: Any, to_port: Any, cidr: str, desc: str) -> str:
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
