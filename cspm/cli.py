import argparse

from cspm.providers.aws_collector import collect_aws_snapshot
from cspm.storage import save_snapshot
from cspm.rules.aws_rules import run_aws_rules
from cspm.scoring import score_findings
from cspm.reporting import render_html_report

# cli entrypoint for running scans and making reports

def scan_aws(regions: list[str]):
    print("[*] Starting AWS scan")

    # collect snapshot
    snapshot = collect_aws_snapshot(regions=regions)

    # save it to disk
    snapshot_path = save_snapshot(snapshot)
    print(f"[+] Snapshot saved to {snapshot_path}")

    # run rules
    findings = run_aws_rules(snapshot)

    # score findings
    scored_findings = score_findings(findings)

    # sort by risk (descending)
    scored_findings.sort(key=lambda f: f["risk_score"], reverse=True)

    # print top findings
    print("\n=== Top Findings ===")
    if not scored_findings:
        print("No misconfigurations found.")
    else:
        for finding in scored_findings[:10]:
            print(
                f'- [{finding["risk_score"]:>3}] '
                f'{finding["rule_id"]} | '
                f'{finding["resource_id"]} | '
                f'{finding["region"]}'
            )

    # create html report
    report_path = render_html_report(
        snapshot=snapshot,
        findings=scored_findings,
    )

    print(f"\n[+] Report written to {report_path}")
    print("[*] Scan complete")


def main():
    # parse command/options
    parser = argparse.ArgumentParser(description="Local CSPM Lite - Cloud Misconfiguration Scanner")

    subparsers = parser.add_subparsers(dest="command", required=True)

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

    args = parser.parse_args()

    if args.command == "scan":
        if args.provider == "aws":
            scan_aws(regions=args.regions)
        else:
            parser.error("Provider not supported yet.")


if __name__ == "__main__":
    main()
#run cli when used as a script