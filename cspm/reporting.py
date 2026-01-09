from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


def render_html_report(snapshot: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    """
    renders reports/latest_report.html using cspm/reporting/templates/report.html
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

    out_html = template.render(
        generated_at=datetime.now().isoformat(timespec="seconds"),
        snapshot=Obj(snapshot),
        findings=findings_obj,
    )

    reports_dir = base_dir.parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    out_path = reports_dir / "latest_report.html"
    out_path.write_text(out_html, encoding="utf-8")

    return str(out_path)
