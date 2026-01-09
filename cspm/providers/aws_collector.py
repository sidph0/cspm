from __future__ import annotations

# collect an AWS snapshot (ec2 security groups per region)

from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# current UTC time in ISO 8601 format
def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# retrieve AWS account ID using STS
def _get_account_id() -> str:
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]


def collect_aws_snapshot(regions: list[str]) -> dict[str, Any]:
    """
    # Collect a minimal AWS configuration snapshot for Milestone 1:
      - Security Groups (EC2) per region

    Returns a dict that can be JSON-serialized.
    """
    account_id = _get_account_id()

    # snapshot with metadata and per-region map
    snapshot: dict[str, Any] = {
        "metadata": {
            "provider": "aws",
            "account_id": account_id,
            "collected_at_utc": _utc_now_iso(),
            "regions": regions,
        },
        "aws": {
            "regions": {},
        },
    }

    for region in regions:
        # region block to hold security groups
        region_block: dict[str, Any] = {"security_groups": []}
        snapshot["aws"]["regions"][region] = region_block

        try:
            # ec2 client for the region
            ec2 = boto3.client("ec2", region_name=region)

            # paginate through security groups
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    # append compact representation, keep IpPermissions structure
                    region_block["security_groups"].append(
                        {
                            "group_id": sg.get("GroupId"),
                            "group_name": sg.get("GroupName"),
                            "description": sg.get("Description"),
                            "vpc_id": sg.get("VpcId"),
                            # keep aws native structure for now (rules can read this directly)
                            "ip_permissions": sg.get("IpPermissions", []),
                        }
                    )

        except (ClientError, BotoCoreError) as e:
            # don’t crash the entire scan if one region fails
            region_block["error"] = {
                "type": e.__class__.__name__,
                "message": str(e),
            }

    return snapshot
