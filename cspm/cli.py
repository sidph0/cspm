import argparse
import json
from pathlib import Path
from typing import Any

from cspm.providers.aws_collector import collect_aws_snapshot
from cspm.storage import save_snapshot, record_report_for_latest_run
from cspm.rules.aws_rules import run_aws_rules
from cspm.scoring import score_findings
from cspm.reporting import render_html_report
from cspm.remediation.base import RemediationResult, RemediationStatus, SUPPORTED_REMEDIATIONS
from cspm.remediation.aws_ec2 import remediate_ec2_security_group
from cspm.remediation.aws_s3 import remediate_s3_public_access_block


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


def _run_remediations(
    findings: list[dict[str, Any]],
    *,
    dry_run: bool = True,
    demo_mode: bool = False,
) -> dict[str, Any]:
    """
    run remediations for findings
    
    returns a remediation summary dict with:
    - eligible: findings that support remediation
    - applied: list of RemediationResult for successful remediations
    - skipped: list of RemediationResult for skipped remediations
    - failed: list of RemediationResult for failed remediations
    """
    eligible: list[dict[str, Any]] = []
    applied: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    
    for finding in findings:
        # skip not evaluated findings
        if finding.get("status") == "NOT_EVALUATED":
            continue
        
        # check if remediation is supported for the rule
        remediation_meta = finding.get("remediation", {})
        if not remediation_meta.get("supported", False):
            # not supported - add to skipped with reason
            skipped.append({
                "status": "SKIPPED",
                "reason": remediation_meta.get("description", "Not supported for auto-fix"),
                "resource_id": finding.get("resource_id", ""),
                "rule_id": finding.get("rule_id", ""),
                "action": None,
                "dry_run": dry_run,
            })
            continue
        
        eligible.append(finding)
        
        # send to appropriate remediation handler
        rule_id = finding.get("rule_id", "")
        result: RemediationResult | None = None
        
        if rule_id in ("AWS_SG_INGRESS_SSH_WORLD", "AWS_SG_INGRESS_RDP_WORLD", "AWS_SG_INGRESS_ALL_WORLD"):
            result = remediate_ec2_security_group(finding, dry_run=dry_run, demo_mode=demo_mode)
        elif rule_id == "AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED":
            result = remediate_s3_public_access_block(finding, dry_run=dry_run, demo_mode=demo_mode)
        
        if result is None:
            skipped.append({
                "status": "SKIPPED",
                "reason": "No remediation handler available",
                "resource_id": finding.get("resource_id", ""),
                "rule_id": rule_id,
                "action": None,
                "dry_run": dry_run,
            })
            continue
        
        # Categorize result
        result_dict = result.to_dict()
        if result.status == RemediationStatus.SUCCESS:
            applied.append(result_dict)
        elif result.status == RemediationStatus.SKIPPED:
            skipped.append(result_dict)
        else:  # FAILED
            failed.append(result_dict)
    
    return {
        "eligible_count": len(eligible),
        "applied_count": len(applied),
        "skipped_count": len(skipped),
        "failed_count": len(failed),
        "applied": applied,
        "skipped": skipped,
        "failed": failed,
        "dry_run": dry_run,
    }


def _print_remediation_summary(summary: dict[str, Any]) -> None:
    """Print remediation summary to console."""
    print("\n=== Remediation Summary ===")
    
    dry_run_label = " [DRY-RUN]" if summary.get("dry_run") else ""
    print(f"Mode:{dry_run_label}")
    print(f"  Eligible: {summary.get('eligible_count', 0)}")
    print(f"  Applied:  {summary.get('applied_count', 0)}")
    print(f"  Skipped:  {summary.get('skipped_count', 0)}")
    print(f"  Failed:   {summary.get('failed_count', 0)}")
    
    # show applied remediations
    if summary.get("applied"):
        print("\nApplied:")
        for r in summary["applied"]:
            print(f"  - {r.get('rule_id')} | {r.get('resource_id')}: {r.get('reason')}")
    
    # show skipped (limit to avoid clutter)
    if summary.get("skipped"):
        print("\nSkipped:")
        for r in summary["skipped"][:10]:
            print(f"  - {r.get('rule_id')} | {r.get('resource_id')}: {r.get('reason')}")
        if len(summary["skipped"]) > 10:
            print(f"  ... and {len(summary['skipped']) - 10} more")
    
    # show failed
    if summary.get("failed"):
        print("\nFailed:")
        for r in summary["failed"]:
            print(f"  - {r.get('rule_id')} | {r.get('resource_id')}: {r.get('reason')}")


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
    remediate: bool = False,
    dry_run: bool = True,
    demo_mode: bool = False,
) -> tuple[str, str]:
    """
    pipeline:
      - save snapshot
      - run rules
      - score + sort findings
      - (optional) run remediations
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

    # run remediations if requested
    remediation_summary: dict[str, Any] | None = None
    if remediate:
        remediation_summary = _run_remediations(
            scored,
            dry_run=dry_run,
            demo_mode=demo_mode,
        )
        _print_remediation_summary(remediation_summary)

    # embed drift (vs previous scan) inside same report
    drift_ctx = _compute_drift_context(provider="aws")

    report_path = render_html_report(
        snapshot=snapshot,
        findings=scored,
        drift=drift_ctx,
        remediation=remediation_summary,
    )
    record_report_for_latest_run(report_path)

    return snapshot_path, report_path



def scan_aws(
    regions: list[str],
    *,
    remediate: bool = False,
    dry_run: bool = True,
) -> None:
    print("[*] Starting AWS scan")
    if remediate:
        mode_label = "DRY-RUN" if dry_run else "LIVE"
        print(f"[*] Remediation enabled ({mode_label})")

    snapshot = collect_aws_snapshot(regions=regions)
    snapshot_path, report_path = _run_pipeline(
        snapshot,
        remediate=remediate,
        dry_run=dry_run,
        demo_mode=False,
    )

    print(f"[+] Snapshot saved to {snapshot_path}")
    print(f"[+] Report written to {report_path}")
    print("[*] Scan complete")


def scan_aws_demo(
    *,
    remediate: bool = False,
    dry_run: bool = True,
) -> None:
    print("[*] Starting demo scan (no AWS required)")
    if remediate:
        mode_label = "DRY-RUN" if dry_run else "SIMULATED"
        print(f"[*] Remediation enabled ({mode_label} - demo mode)")

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
        remediate=remediate,
        dry_run=dry_run,
        demo_mode=True,  # (important) turns on mock remediation results
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
    scan_parser.add_argument(
        "--remediate",
        action="store_true",
        help="Enable auto remediation for supported findings (default: read only)",
    )
    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Preview remediation actions without making changes (requires --remediate)",
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

        # validate remediation flags
        if args.dry_run and not args.remediate:
            parser.error("--dry-run requires --remediate flag")

        # if --remediate is specified without --dry-run, default to dry run for safety
        # user needs to explicitly use --remediate without --dry-run for live changes
        dry_run = args.dry_run if args.remediate else True

        if args.demo:
            scan_aws_demo(remediate=args.remediate, dry_run=dry_run)
        else:
            scan_aws(regions=args.regions, remediate=args.remediate, dry_run=dry_run)
        return

    if args.command == "drift":
        if args.provider != "aws":
            parser.error("Provider not supported yet.")

        report_path = render_latest_with_drift()
        print(f"[+] Updated main report (with drift embedded): {report_path}")
        return


if __name__ == "__main__":
    main()
