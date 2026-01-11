# Local CSPM Lite

local CSPM lite is a windows based local Cloud Security Posture Management (CSPM) tool.
It scans AWS cloud configurations, detects common misconfigurations, assigns risk scores, and generates standalone HTML security reports.

---

## What This Project Does
1. get cloud config data from AWS using official APIs
2. evaluates configs against security rules
3. assigns risk scores to findings
4. saves immutable scan snapshots locally
5. makes timestamped HTML security reports
6. allows a demo mode that runs without AWS credentials

---

### AWS Security Group Checks
- SSH (port 22) open to the world
- RDP (port 3389) open to the world
- All traffic open to the world (IpProtocol = -1)

### AWS S3 Checks
- Public Access Block disabled or missing
- Bucket policy publicly accessible
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
cd local-cspm-lite
```

### 2. Create and activate a virtual environment
```powershell
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

---

## Project Structure (Simplified)

```
cspm/
  cli.py
  storage.py
  scoring.py
  reporting.py
  providers/
    aws_collector.py
  rules/
    aws_rules.py
reporting/templates/
  report.html
samples/
  sample_snapshot_aws.json
snapshots/
reports/
```

---

## Design Notes

- intentionally local first / CLI driven
- all cloud access is read only unless you add remediation
- pretty simplified scale of real CSPM product architecture

---

## Disclaimer

This project is for educational and portfolio purposes

Always review findings before making changes in production environments.
