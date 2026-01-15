# Local CSPM Lite

local CSPM lite is a windows based local Cloud Security Posture Management (CSPM) tool.
It scans AWS cloud configurations, detects common misconfigurations, assigns risk scores, and generates standalone HTML security reports.

---

## What This Project Does
1. get cloud config data from AWS using official APIs
2. evaluates configs against security rules
3. assigns risk scores to findings
4. saves immutable scan snapshots locally 
5. detects config drift between scans (new, resolved, and risk changed findings)  
6. makes timestamped HTML security reports with embedded drift analysis  
7. allows a demo mode that runs without AWS credentials  

---

## AWS Security Group Checks

- SSH (port 22) open to any CIDR
- SSH (port 22) open to the world
- RDP (port 3389) open to the world
- All traffic open to the world (IpProtocol = -1)

## AWS S3 Checks
- Public Access Block disabled or missing
- Bucket policy publicly accessible
---

## New Updates

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

### Demo Mode (No AWS Required)
```powershell
python -m cspm.cli scan --provider aws --demo
```

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
- pretty simplified scale of real CSPM product architecture
- demo mode kept in sync with production features

---

## Disclaimer

This project is for educational and portfolio purposes

Always review findings before making changes in production environments.
