from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

def _safe_slug(text: str) -> str:
    """
    make compatible filenames
    keeps letters, numbers, dash, underscore, dot; everything else becomes - .
    """
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    return "".join(ch if ch in allowed else "-" for ch in text)

def _timestamp_for_filename(snapshot: dict[str, Any]) -> str:
    """
    Output format: YYYYMMDDTHHMMSSZ 
    """
    collected = snapshot.get("metadata", {}).get("collected_at_utc")
    if isinstance(collected, str) and collected:
        # try to parse string
        try:
            dt = datetime.fromisoformat(collected.replace("Z", "+00:00"))
            return dt.strftime("%Y%m%dT%H%M%SZ")
        except Exception:
            return _safe_slug(collected)
    return datetime.now().strftime("%Y%m%dT%H%M%S")

def render_html_report(snapshot: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    """
    make unique report file to /reports:
      report_<provider>_<regions>_<timestamp>.html

    also writes/overwrites:
      latest_report.html  (convenience)
    gives full path to the unique report file
    """
    base_dir = Path(__file__).resolve().parent
    templates_dir = base_dir / "reporting" / "templates"

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")

    # jinja template expects attribute access (f.rule_id), so makes dicts to simple objects
    class Obj(dict):
        __getattr__ = dict.get

    findings_obj = [Obj(f) for f in findings]
    snapshot_obj = Obj(snapshot)

    provider = str(snapshot.get("metadata", {}).get("provider") or "unknown")
    provider_slug = _safe_slug(provider.lower())

    regions = snapshot.get("metadata", {}).get("regions") or []
    if not isinstance(regions, list):
        regions = []
    regions_slug = "_".join(_safe_slug(str(r)) for r in regions) if regions else "no-regions"

    ts = _timestamp_for_filename(snapshot)

    out_html = template.render(
        generated_at=datetime.now().isoformat(timespec="seconds"),
        snapshot=snapshot_obj,
        findings=findings_obj,
    )

    project_root = base_dir.parent
    reports_dir = project_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    unique_name = f"report_{provider_slug}_{regions_slug}_{ts}.html"
    unique_path = reports_dir / unique_name
    unique_path.write_text(out_html, encoding="utf-8")

    # convenience "latest" copy (optional but useful)
    latest_path = reports_dir / "latest_report.html"
    latest_path.write_text(out_html, encoding="utf-8")

    return str(unique_path)
