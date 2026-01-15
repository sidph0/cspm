from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape


def _safe_slug(text: str) -> str:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    return "".join(ch if ch in allowed else "-" for ch in text)


def _timestamp_for_filename(snapshot: dict[str, Any]) -> str:
    collected = snapshot.get("metadata", {}).get("collected_at_utc")
    if isinstance(collected, str) and collected:
        try:
            dt = datetime.fromisoformat(collected.replace("Z", "+00:00"))
            return dt.strftime("%Y%m%dT%H%M%SZ")
        except Exception:
            return _safe_slug(collected)
    return datetime.now().strftime("%Y%m%dT%H%M%S")


def _env() -> Environment:
    base_dir = Path(__file__).resolve().parent
    templates_dir = base_dir / "reporting" / "templates"
    return Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )


class Obj(dict):
    __getattr__ = dict.get


def _wrap_drift_for_template(drift: Optional[dict[str, Any]]) -> Optional[Obj]:
    """
    convert drift dict (and nested objects) into Obj structures so Jinja can use dot notation
    """
    if not isinstance(drift, dict):
        return None

    d = Obj(drift)

    # make sure diff exists and is wrapped
    if isinstance(d.get("diff"), dict):
        d["diff"] = Obj(d["diff"])

        # wrap finding lists
        for key in ("new", "resolved", "persisting"):
            items = d["diff"].get(key) or []
            d["diff"][key] = [Obj(x) for x in items]

        # wrap before/after maps for increased/decreased risk
        for key in ("increased_risk", "decreased_risk"):
            items = d["diff"].get(key) or []
            wrapped = []
            for x in items:
                xo = Obj(x)
                if isinstance(xo.get("before"), dict):
                    xo["before"] = Obj(xo["before"])
                if isinstance(xo.get("after"), dict):
                    xo["after"] = Obj(xo["after"])
                wrapped.append(xo)
            d["diff"][key] = wrapped

    return d


def render_html_report(
    snapshot: dict[str, Any],
    findings: list[dict[str, Any]],
    drift: Optional[dict[str, Any]] = None,
) -> str:
    """
    make unique report file to /reports:
      report_<provider>_<regions>_<timestamp>.html

    also writes/overwrites:
      latest_report.html  (convenience)
    gives full path to the unique report file
    """
    env = _env()
    template = env.get_template("report.html")

    provider = str(snapshot.get("metadata", {}).get("provider") or "unknown").lower()
    provider_slug = _safe_slug(provider)

    regions = snapshot.get("metadata", {}).get("regions") or []
    if not isinstance(regions, list):
        regions = []
    regions_slug = "_".join(_safe_slug(str(r)) for r in regions) if regions else "no-regions"

    ts = _timestamp_for_filename(snapshot)

    drift_obj = _wrap_drift_for_template(drift)

    out_html = template.render(
        generated_at=datetime.now().isoformat(timespec="seconds"),
        snapshot=Obj(snapshot),
        findings=[Obj(f) for f in findings],
        drift=drift_obj,  # new drift context
    )

    project_root = Path(__file__).resolve().parent.parent
    reports_dir = project_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    unique_name = f"report_{provider_slug}_{regions_slug}_{ts}.html"
    unique_path = reports_dir / unique_name
    unique_path.write_text(out_html, encoding="utf-8")

    # latest report (for convenience)
    (reports_dir / "latest_report.html").write_text(out_html, encoding="utf-8")

    return str(unique_path)