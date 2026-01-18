from __future__ import annotations

# collect an AWS snapshot (ec2 security groups per region)

from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError


# -------------------------
# coverage helpers
# -------------------------
def _cov_ok(coverage: dict[str, Any], service: str, action: str) -> None:
    coverage.setdefault(service, {})
    coverage[service][action] = {"status": "OK"}


def _cov_err(coverage: dict[str, Any], service: str, action: str, err: Exception) -> None:
    coverage.setdefault(service, {})

    code = None
    msg = str(err)
    try:
        resp = getattr(err, "response", None)
        if isinstance(resp, dict):
            e = resp.get("Error") or {}
            code = e.get("Code")
            msg = e.get("Message") or msg
    except Exception:
        pass

    coverage[service][action] = {
        "status": "ERROR",
        "error_code": code or "UnknownError",
        "message": msg,
    }


# current UTC time in ISO 8601 format
def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def collect_aws_snapshot(regions: list[str]) -> dict[str, Any]:
    """
    Milestone 1+:
    - sts caller identity (account id)
    - ec2 security groups per region
    - s3 buckets (global list) + per bucket posture checks (region, public access block, policy status)

    returns dict that can be json serialized.
    """
    coverage: dict[str, Any] = {}

    # retrieve AWS account ID using STS (and track coverage)
    try:
        sts = boto3.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        _cov_ok(coverage, "sts", "GetCallerIdentity")
    except (ClientError, BotoCoreError) as e:
        _cov_err(coverage, "sts", "GetCallerIdentity", e)
        # Without account id, we can still return a snapshot, but mark unknown
        account_id = "unknown"

    # snapshot with metadata and per-region map
    snapshot: dict[str, Any] = {
        "metadata": {
            "provider": "aws",
            "account_id": account_id,
            "collected_at_utc": _utc_now_iso(),
            "regions": regions,
        },
        "aws": {
            "coverage": coverage,  # NEW
            "regions": {},
            "s3": {"buckets": []},
        },
    }

    # -------------------------
    # EC2 Security Groups per region
    # -------------------------
    for region in regions:
        region_block: dict[str, Any] = {"security_groups": []}
        snapshot["aws"]["regions"][region] = region_block

        try:
            ec2 = boto3.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")

            any_pages = False
            for page in paginator.paginate():
                any_pages = True
                for sg in page.get("SecurityGroups", []):
                    region_block["security_groups"].append(
                        {
                            "group_id": sg.get("GroupId"),
                            "group_name": sg.get("GroupName"),
                            "description": sg.get("Description"),
                            "vpc_id": sg.get("VpcId"),
                            "ip_permissions": sg.get("IpPermissions", []),
                        }
                    )

            # if we successfully paginated at least once then it's fine (even if 0 SGs)
            if any_pages:
                _cov_ok(coverage, "ec2", "DescribeSecurityGroups")

        except (ClientError, BotoCoreError) as e:
            _cov_err(coverage, "ec2", "DescribeSecurityGroups", e)
            region_block["error"] = {
                "type": e.__class__.__name__,
                "message": str(e),
            }

    # -------------------------
    # S3 buckets (global)
    # -------------------------
    try:
        s3 = boto3.client("s3")

        resp = s3.list_buckets()
        _cov_ok(coverage, "s3", "ListBuckets")

        bucket_names = [b.get("Name") for b in resp.get("Buckets", []) if b.get("Name")]

        def _fetch_region(bucket_name: str) -> tuple[str | None, dict | None]:
            try:
                loc = s3.get_bucket_location(Bucket=bucket_name).get("LocationConstraint")
                _cov_ok(coverage, "s3", "GetBucketLocation")
                return ("us-west-1" if loc in (None, "") else str(loc), None)
            except (ClientError, BotoCoreError) as e:
                _cov_err(coverage, "s3", "GetBucketLocation", e)
                return (None, {"type": e.__class__.__name__, "message": str(e)})

        def _fetch_public_access_block(bucket_name: str) -> tuple[Any, dict | None]:
            try:
                resp = s3.get_public_access_block(Bucket=bucket_name)
                _cov_ok(coverage, "s3", "GetPublicAccessBlock")
                return (resp, None)
            except ClientError as e:
                _cov_err(coverage, "s3", "GetPublicAccessBlock", e)
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"):
                    return (None, None)
                return (None, {"type": e.__class__.__name__, "message": str(e)})
            except BotoCoreError as e:
                _cov_err(coverage, "s3", "GetPublicAccessBlock", e)
                return (None, {"type": e.__class__.__name__, "message": str(e)})

        def _fetch_policy_status(bucket_name: str) -> tuple[Any, dict | None]:
            try:
                resp = s3.get_bucket_policy_status(Bucket=bucket_name)
                _cov_ok(coverage, "s3", "GetBucketPolicyStatus")
                return (resp, None)
            except ClientError as e:
                _cov_err(coverage, "s3", "GetBucketPolicyStatus", e)
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("NoSuchBucketPolicy",):
                    return (None, None)
                return (None, {"type": e.__class__.__name__, "message": str(e)})
            except BotoCoreError as e:
                _cov_err(coverage, "s3", "GetBucketPolicyStatus", e)
                return (None, {"type": e.__class__.__name__, "message": str(e)})

        def _fetch_policy(bucket_name: str) -> tuple[Any, dict | None]:
            try:
                resp = s3.get_bucket_policy(Bucket=bucket_name).get("Policy")
                _cov_ok(coverage, "s3", "GetBucketPolicy")
                return (resp, None)
            except ClientError as e:
                _cov_err(coverage, "s3", "GetBucketPolicy", e)
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("NoSuchBucketPolicy", "NoSuchPolicy"):
                    return (None, None)
                return (None, {"type": e.__class__.__name__, "message": str(e)})
            except BotoCoreError as e:
                _cov_err(coverage, "s3", "GetBucketPolicy", e)
                return (None, {"type": e.__class__.__name__, "message": str(e)})

        for name in bucket_names:
            bucket_info: dict[str, Any] = {"name": name}

            region, region_err = _fetch_region(name)
            if region is not None:
                bucket_info["region"] = region
            elif region_err is not None:
                bucket_info["region_error"] = region_err

            pab, pab_err = _fetch_public_access_block(name)
            if pab is not None:
                bucket_info["public_access_block"] = pab
            elif pab_err is not None:
                bucket_info["public_access_block_error"] = pab_err
            else:
                bucket_info.setdefault("public_access_block", None)

            ps, ps_err = _fetch_policy_status(name)
            if ps is not None:
                bucket_info["policy_status"] = ps
            elif ps_err is not None:
                bucket_info["policy_status_error"] = ps_err
            else:
                bucket_info.setdefault("policy_status", None)

            policy, policy_err = _fetch_policy(name)
            if policy is not None:
                bucket_info["policy"] = policy
            elif policy_err is not None:
                bucket_info["policy_error"] = policy_err
            else:
                bucket_info.setdefault("policy", None)

            snapshot["aws"]["s3"]["buckets"].append(bucket_info)

    except (ClientError, BotoCoreError) as e:
        _cov_err(coverage, "s3", "ListBuckets", e)
        snapshot["aws"]["s3"]["error"] = {"type": e.__class__.__name__, "message": str(e)}

    return snapshot
