from __future__ import annotations

from typing import Any


# ip ranges that show the finding might be exposed to the whole internet
WORLD_EXPOSURE_MARKERS = ("0.0.0.0/0", "::/0")


def score_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    add `risk_score` to each finding
    model:
      risk_score = severity + exposure_bonus
      exposure_bonus = 20 if evidence suggests world exposure
      clamp to [0, 100]
    """
    scored: list[dict[str, Any]] = []

    for finding in findings:
        # use provided severity when possible otherwise default to 50
        severity_value = _to_int(finding.get("severity"), default=50)
        # evidence -> string for marker checks
        evidence_text = str(finding.get("evidence") or "")
        is_public = bool(finding.get("is_public") is True)

        # add a fixed bonus if evidence shows world exposure
        exposure_bonus = 20 if _is_world_exposed(evidence_text) else 0
        # ensure final score stays within sensible bounds
        risk_score = _clamp_range(severity_value + exposure_bonus, 0, 100)

        out = dict(finding)  # copy so we dont mutate the caller's data
        out["risk_score"] = risk_score
        scored.append(out)

    return scored


def _is_world_exposed(evidence: str) -> bool:
    # true if any known world exposure marker shows up in evidence
    return any(marker in evidence for marker in WORLD_EXPOSURE_MARKERS)


def _clamp_range(value: int, lo: int, hi: int) -> int:
    # clamp `value` to the inclusive range [low, high]
    return max(lo, min(hi, value))


def _to_int(value: Any, default: int) -> int:
    # try to go to int, fall back to `default` on error
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
