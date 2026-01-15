import argparse
import json
from pathlib import Path

from cspm.providers.aws_collector import collect_aws_snapshot
from cspm.storage import save_snapshot, record_report_for_latest_run
from cspm.rules.aws_rules import run_aws_rules
from cspm.scoring import score_findings
from cspm.reporting import render_html_report


# cli entrypoint for running scans and making reports


def _project_root() -> Path:
    # cspm/cli.py -> project root is one level up from /cspm
    return Path(__file__).resolve().parent.parent


def _print_top_findings(scored_findings: list[dict], limit: int = 10) -> None:
    print("\n=== Top Findings ===")
    if not scored_findings:
        print("No misconfigurations found.")
        return

    for finding in scored_findings[:limit]:
        print(
            f'- [{finding["risk_score"]:>3}] '
            f'{finding["rule_id"]} | '
            f'{finding["resource_id"]} | '
            f'{finding["region"]}'
        )


def _compute_drift_context(provider: str) -> dict:
    """
    make drift context object for embedding into report

    if drift not available (like only one snapshot exists), returns false
    """
    try:
        from cspm.snapshot_selection import get_latest_and_previous
        from cspm.drift_findings import diff_findings

        pair = get_latest_and_previous(provider=provider)

        prev_findings = score_findings(run_aws_rules(pair.previous))
        latest_findings = score_findings(run_aws_rules(pair.latest))
        diff = diff_findings(prev_findings, latest_findings)

        return {
            "available": True,
            "previous_snapshot_path": str(pair.previous_path),
            "latest_snapshot_path": str(pair.latest_path),
            "diff": {
                "new": diff.new,
                "resolved": diff.resolved,
                "persisting": diff.persisting,
                "increased_risk": diff.increased_risk,
                "decreased_risk": diff.decreased_risk,
            },
        }
    except Exception:
        return {"available": False}


def _run_pipeline(
    snapshot: dict,
    *,
    filename_override: str | None = None,
    update_latest: bool = True,
) -> tuple[str, str]:
    """
    pipeline:
      - save snapshot
      - run rules
      - score + sort findings
      - compute drift context (vs previous) and embed into same report
      - render report
      - record report path in snapshots/latest.json
    returns snapshot_path, report_path
    """
    snapshot_path = save_snapshot(
        snapshot,
        filename_override=filename_override,
        update_latest=update_latest,
    )

    findings = run_aws_rules(snapshot)
    scored = score_findings(findings)
    scored.sort(key=lambda f: f["risk_score"], reverse=True)

    _print_top_findings(scored)

    # embed drift (vs previous scan) inside same report
    drift_ctx = _compute_drift_context(provider="aws")

    report_path = render_html_report(snapshot=snapshot, findings=scored, drift=drift_ctx)
    record_report_for_latest_run(report_path)

    return snapshot_path, report_path



def scan_aws(regions: list[str]) -> None:
    print("[*] Starting AWS scan")

    snapshot = collect_aws_snapshot(regions=regions)
    snapshot_path, report_path = _run_pipeline(snapshot)

    print(f"[+] Snapshot saved to {snapshot_path}")
    print(f"[+] Report written to {report_path}")
    print("[*] Scan complete")


def scan_aws_demo() -> None:
    print("[*] Starting demo scan (no AWS required)")

    root = _project_root()
    samples_dir = root / "cspm" / "samples"

    prev_path = samples_dir / "sample_snapshot_aws_prev.json"
    latest_path = samples_dir / "sample_snapshot_aws.json"

    if not prev_path.exists():
        raise FileNotFoundError(f"Missing demo snapshot: {prev_path}")
    if not latest_path.exists():
        raise FileNotFoundError(f"Missing demo snapshot: {latest_path}")

    demo_account_id = "000000000000"

    # clear old demo snapshots so drift is deterministic every run
    demo_snap_dir = root / "snapshots" / "aws" / demo_account_id
    if demo_snap_dir.exists():
        for p in demo_snap_dir.glob("*.json"):
            try:
                p.unlink()
            except Exception:
                pass

    # seed previous snapshot
    prev_snapshot = json.loads(prev_path.read_text(encoding="utf-8"))
    save_snapshot(
        prev_snapshot,
        filename_override="20260101T000000Z.json",
        update_latest=False,
    )

    # run pipeline on latest snapshot
    latest_snapshot = json.loads(latest_path.read_text(encoding="utf-8"))
    snapshot_path, report_path = _run_pipeline(
        latest_snapshot,
        filename_override="20260102T000000Z.json",
        update_latest=True,
    )

    print(f"[+] Demo snapshot saved to {snapshot_path}")
    print(f"[+] Demo report written to {report_path}")
    print("[*] Demo scan complete")





def render_latest_with_drift() -> str:
    """
    rerender latest snapshot into a new report (and updates latest_report.html), embedding drift if there is a previous snapshot.
    """
    from cspm.snapshot_selection import get_latest_and_previous

    # if there are at least two snapshots ->mbed drift.
    # if only one exists, this will raise; we fall back to just rendering that latest snapshot.
    try:
        pair = get_latest_and_previous(provider="aws")
        latest_snapshot = pair.latest
    except Exception:
        # fall back: try to load the most recent snapshot via snapshots/latest.json pointer
        latest_pointer = (_project_root() / "snapshots" / "latest.json")
        if not latest_pointer.exists():
            raise FileNotFoundError("No snapshots found. Run a scan first.")
        pointer = json.loads(latest_pointer.read_text(encoding="utf-8"))
        snap_path = Path(pointer["snapshot_path"])
        latest_snapshot = json.loads(snap_path.read_text(encoding="utf-8"))

    latest_findings = score_findings(run_aws_rules(latest_snapshot))
    latest_findings.sort(key=lambda f: f["risk_score"], reverse=True)

    drift_ctx = _compute_drift_context(provider="aws")

    report_path = render_html_report(
        snapshot=latest_snapshot,
        findings=latest_findings,
        drift=drift_ctx,
    )
    record_report_for_latest_run(report_path)
    return report_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Local CSPM Lite - Cloud Misconfiguration Scanner"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---- scan ----
    scan_parser = subparsers.add_parser("scan", help="Run a cloud scan")
    scan_parser.add_argument(
        "--provider",
        choices=["aws"],
        required=True,
        help="Cloud provider to scan (MVP: aws only)",
    )
    scan_parser.add_argument(
        "--regions",
        nargs="+",
        default=["us-west-1"],
        help="AWS regions to scan (default: us-west-1)",
    )
    scan_parser.add_argument(
        "--demo",
        action="store_true",
        help="Run using a local sample snapshot (no AWS required)",
    )

    # ---- drift ----
    # no separate drift report file
    drift_parser = subparsers.add_parser(
        "drift",
        help="Embed drift into the main report (re-renders latest_report.html using latest snapshot)",
    )
    drift_parser.add_argument(
        "--provider",
        choices=["aws"],
        required=True,
        help="Cloud provider (MVP: aws only)",
    )

    args = parser.parse_args()

    if args.command == "scan":
        if args.provider != "aws":
            parser.error("Provider not supported yet.")

        if args.demo:
            scan_aws_demo()
        else:
            scan_aws(regions=args.regions)
        return

    if args.command == "drift":
        if args.provider != "aws":
            parser.error("Provider not supported yet.")

        report_path = render_latest_with_drift()
        print(f"[+] Updated main report (with drift embedded): {report_path}")
        return


if __name__ == "__main__":
    main()
