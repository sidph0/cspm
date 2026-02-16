# Local CSPM Lite

Local CSPM Lite is a Windows based local Cloud Security Posture Management (CSPM) tool.
It scans AWS cloud configurations, detects common misconfigurations, attempts to fix said misconfigurations (on request), assigns risk scores, and generates standalone HTML security reports.

---

## What This Project Does
1. get cloud config data from AWS using official APIs
2. evaluates configs against security rules
3. assigns risk scores to findings
4. saves immutable scan snapshots locally 
5. detects config drift between scans (new, resolved, and risk changed findings)  
6. makes timestamped HTML security reports with embedded drift analysis
7. optionally performs safe & controlled auto remediation  
8. allows a demo mode that runs without AWS credentials  

---

## Demo Output 
(remediation on)
[CSPM Demo](https://sidph0.github.io/cspm/)

## AWS Security Group Checks

- SSH (port 22) open to any CIDR
- SSH (port 22) open to the world
- RDP (port 3389) open to the world
- All traffic open to the world (IpProtocol = -1)

## AWS S3 Checks
- Public Access Block disabled or missing
- Bucket policy publicly accessible
---

## Drift Detection (Milestone 2)

- Drift Detection 
  Compares the latest scan with the previous snapshot to show:
  - new findings
  - resolved findings
  - persisting findings
  - risk increased / risk decreased findings

- Contextual Risk Changes 
  risk scores can change over time when exposure changes (like SSH widening from private CIDR to internet)

- Embedded Drift Reporting 
  drift results are embedded directly into the main HTML scan report instead of being generated as a separate file

- Demo Mode (updated)
  seeds a 'previous' and 'latest' snapshot so drift and risk changes are always visible without AWS access

---
## Auto Remediation (Milestone 3)

- now supports opt in auto remediation for a limited set of high risk misconfigurations

### Key Principles
- *Disabled by default* – scanning is read only unless explicitly enabled  
- *Safe scope only* – no IAM, no destructive changes  
- *Explainable* – every action is logged / reported  
- *Permission aware* – remediation is skipped if required permissions are missing  

### Supported Auto Remediations
**EC2 Security Groups**
- Remove inbound rules allowing:
  - SSH (22) from `0.0.0.0/0`
  - RDP (3389) from `0.0.0.0/0`
  - All traffic (`IpProtocol = -1`) from `0.0.0.0/0`

**S3 Buckets**
- Enable Public Access Block (all four flags)

### Dry-Run Mode

```powershell
--remediate --dry-run
```

dry run mode:
- Shows what would be changed
- Makes no AWS API write calls
- Write remediation previews into the report

### Applying Remediation
To apply remediations (real changes):

```powershell
--remediate
```

Remediations will:
- apply only supported / safe fixes
- Skip unsupported / unsafe findings
- Skip fixes when required permissions are missing
- Record applied and skipped actions in the report (with explanations)

### Skipped Remediations
A remediation may be skipped when:
- Required AWS permissions are missing
- The rule is not safe for autofix
- The target change can't be uniquely identified

---

## Permissions & Coverage Awareness

The tool uses a permissions selfcheck during scans and reports:
- Which AWS API calls succeeded
- Which failed (and why)
- Whether scan coverage is FULL, PARTIAL, or LIMITED
---

## Requirements

### Operating System
- Windows 10 or later

### Software
- Python 3.11+ (tested with Python 3.13)
- AWS CLI v2 (for real AWS scans)

### Python Dependencies
- boto3
- botocore
- jinja2
- python-dateutil

---

## Setup (Windows / PowerShell)

### 1. Clone the repository
```powershell
git clone https://github.com/sidph0/cspm.git
cd cspm
```

### 2. Create and activate a virtual environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If script execution is blocked:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 3. Install dependencies
```powershell
pip install -r requirements.txt
```

---
## AWS Configuration (for real scans)

(VERY IMPORTANT) you dont need to deploy anything to AWS.
instead,
1. create an IAM user with read only permissions
2. put this policy:
   - ReadOnlyAccess
3. create an access key for CLI usage
4. configure credentials locally:

```powershell
aws configure
```

Verify access:
```powershell
aws sts get-caller-identity
```

---

## Running the Tool

### Real AWS Scan
```powershell
python -m cspm.cli scan --provider aws --regions us-west-1
```

Multiple regions:
```powershell
python -m cspm.cli scan --provider aws --regions us-west-1 us-east-1
```

### Real AWS Scan with auto remediation
```powershell
python -m cspm.cli scan --provider aws --regions us-west-1 --remediate
```

Dry run preview:
```powershell
python -m cspm.cli scan --provider aws --regions us-west-1 --remediate --dry-run
```

### Demo Mode (No AWS Required)
```powershell
python -m cspm.cli scan --provider aws --demo
```
note: remediation & dry run flags work on the demo

Demo mode:
- seeds previous and latest snapshot automatically
- always shows findings and drift
- no AWS credentials needed

---

## Output

### Snapshots
```
snapshots/aws/<account-id>/<timestamp>.json
```

### Reports
```
reports/report_aws_<regions>_<timestamp>.html
reports/latest_report.html
```

each scan generates a unique & immutable report  
`latest_report.html` for the most recent scan.

---

## Project Structure (Simplified)

```
cspm/
  providers/
    aws_collector.py
  remediation/
    __init__.py
    aws_ec2.py
    aws_s3.py
    base.py
  reporting/templates/
    report.html
  rules/
    aws_rules.py
  samples/
    sample_snapshot_aws.json
    sample_snapshot_aws_prev.json
  cli.py
  storage.py
  scoring.py
  snapshot_selection.py
  drift_findings.py
  reporting.py
reports/
snapshots/
```


---

## Design Notes

- intentionally local first / CLI driven
- all cloud access is read only
- drift aware instead of than snapshot only analysis
- permissions transparency
- remediation to attempt to fix misconfigurations
- pretty simplified scale of real CSPM product architecture
- demo mode kept in sync with production features

---

## Disclaimer

This project is for educational and portfolio purposes

Always review findings before making changes in production environments.
