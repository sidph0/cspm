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
    Milestone 1+:
    - ec2 security groups per region
    - s3 buckets (global list) + per bucket posture checks (region, public access block, policy status)

    returns dict that can be json serialized.
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
            "s3": {"buckets": []},
        },
    }

    # -------------------------
    # EC2 Security Groups per region
    # -------------------------
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

    # -------------------------
    # S3 buckets (global)
    # -------------------------
    try:
        # s3 client and list available buckets
        s3 = boto3.client("s3")
        resp = s3.list_buckets()
        bucket_names = [b.get("Name") for b in resp.get("Buckets", []) if b.get("Name")]

        # helper - get bucket region (LocationConstraint) with error capture
        def _fetch_region(bucket_name: str) -> tuple[str | None, dict | None]:
            try:
                loc = s3.get_bucket_location(Bucket=bucket_name).get("LocationConstraint")
                # aws returns none for us-west-1, normalize that
                return ("us-west-1" if loc in (None, "") else str(loc), None)
            except (ClientError, BotoCoreError) as e:
                # return error dict for caller to record
                return (None, {"type": e.__class__.__name__, "message": str(e)})

        # helper - get public access block configuration
        def _fetch_public_access_block(bucket_name: str) -> tuple[Any, dict | None]:
            try:
                return (s3.get_public_access_block(Bucket=bucket_name), None)
            except ClientError as e:
                # treat explicit "no config" codes as none
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"):
                    return (None, None)
                return (None, {"type": e.__class__.__name__, "message": str(e)})
            except BotoCoreError as e:
                return (None, {"type": e.__class__.__name__, "message": str(e)})

        # helper - check bucket policy status (fast public check)
        def _fetch_policy_status(bucket_name: str) -> tuple[Any, dict | None]:
            try:
                return (s3.get_bucket_policy_status(Bucket=bucket_name), None)
            except ClientError as e:
                # if no policy, return none
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("NoSuchBucketPolicy",):
                    return (None, None)
                return (None, {"type": e.__class__.__name__, "message": str(e)})
            except BotoCoreError as e:
                return (None, {"type": e.__class__.__name__, "message": str(e)})

        # helper - fetch full bucket policy (optional)
        def _fetch_policy(bucket_name: str) -> tuple[Any, dict | None]:
            try:
                return (s3.get_bucket_policy(Bucket=bucket_name).get("Policy"), None)
            except ClientError as e:
                # no policy is a normal condition, get others as errors
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("NoSuchBucketPolicy", "NoSuchPolicy"):
                    return (None, None)
                return (None, {"type": e.__class__.__name__, "message": str(e)})
            except BotoCoreError as e:
                return (None, {"type": e.__class__.__name__, "message": str(e)})

        # iterate buckets and populate per bucket info using helpers above
        for name in bucket_names:
            bucket_info: dict[str, Any] = {"name": name}

            # region
            region, region_err = _fetch_region(name)
            if region is not None:
                bucket_info["region"] = region
            elif region_err is not None:
                bucket_info["region_error"] = region_err

            # public access block (nothing if missing)
            pab, pab_err = _fetch_public_access_block(name)
            if pab is not None:
                bucket_info["public_access_block"] = pab
            elif pab_err is not None:
                bucket_info["public_access_block_error"] = pab_err
            else:
                # explicit none means config is missing
                bucket_info.setdefault("public_access_block", None)

            # policy status (fast public check)
            ps, ps_err = _fetch_policy_status(name)
            if ps is not None:
                bucket_info["policy_status"] = ps
            elif ps_err is not None:
                bucket_info["policy_status_error"] = ps_err
            else:
                bucket_info.setdefault("policy_status", None)

            # optional full policy document
            policy, policy_err = _fetch_policy(name)
            if policy is not None:
                bucket_info["policy"] = policy
            elif policy_err is not None:
                bucket_info["policy_error"] = policy_err
            else:
                bucket_info.setdefault("policy", None)

            snapshot["aws"]["s3"]["buckets"].append(bucket_info)

    except (ClientError, BotoCoreError) as e:
        # top level s3 error (like list_buckets failure)
        snapshot["aws"]["s3"]["error"] = {"type": e.__class__.__name__, "message": str(e)}

    return snapshot
