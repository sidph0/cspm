from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FindingDiff:
    new: list[dict[str, Any]]
    resolved: list[dict[str, Any]]
    persisting: list[dict[str, Any]]
    increased_risk: list[dict[str, Any]]  # items contain before/after
    decreased_risk: list[dict[str, Any]]  # items contain before/after


def compute_finding_key(f: dict[str, Any]) -> str:
    """
    A stable identifier for 'the same finding' across scans.
    """
    provider = str(f.get("provider", "")).lower()
    rule_id = str(f.get("rule_id", "")).upper()
    resource_type = str(f.get("resource_type", "")).lower()
    resource_id = str(f.get("resource_id", ""))
    region = str(f.get("region", "")).lower()
    return f"{provider}|{rule_id}|{resource_type}|{resource_id}|{region}"


def diff_findings(
    previous_findings: list[dict[str, Any]],
    latest_findings: list[dict[str, Any]],
) -> FindingDiff:
    """
    compare two lists of findings and return drift categories.
    """
    prev_map = {compute_finding_key(f): f for f in previous_findings}
    latest_map = {compute_finding_key(f): f for f in latest_findings}

    prev_keys = set(prev_map.keys())
    latest_keys = set(latest_map.keys())

    new_keys = latest_keys - prev_keys
    resolved_keys = prev_keys - latest_keys
    common_keys = prev_keys & latest_keys

    new = [latest_map[k] for k in sorted(new_keys)]
    resolved = [prev_map[k] for k in sorted(resolved_keys)]
    persisting = [latest_map[k] for k in sorted(common_keys)]

    increased_risk: list[dict[str, Any]] = []
    decreased_risk: list[dict[str, Any]] = []

    for k in sorted(common_keys):
        before = prev_map[k]
        after = latest_map[k]
        before_score = _as_int(before.get("risk_score"), default=0)
        after_score = _as_int(after.get("risk_score"), default=0)

        if after_score > before_score:
            increased_risk.append(
                {
                    "key": k,
                    "before": before,
                    "after": after,
                    "before_risk": before_score,
                    "after_risk": after_score,
                }
            )
        elif after_score < before_score:
            decreased_risk.append(
                {
                    "key": k,
                    "before": before,
                    "after": after,
                    "before_risk": before_score,
                    "after_risk": after_score,
                }
            )

    # sort most important first
    new.sort(key=lambda f: _as_int(f.get("risk_score"), 0), reverse=True)
    resolved.sort(key=lambda f: _as_int(f.get("risk_score"), 0), reverse=True)
    persisting.sort(key=lambda f: _as_int(f.get("risk_score"), 0), reverse=True)

    increased_risk.sort(key=lambda x: x["after_risk"], reverse=True)
    decreased_risk.sort(key=lambda x: x["before_risk"], reverse=True)

    return FindingDiff(
        new=new,
        resolved=resolved,
        persisting=persisting,
        increased_risk=increased_risk,
        decreased_risk=decreased_risk,
    )


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
