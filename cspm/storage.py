from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_timestamp_for_filename() -> str:
    # safe for windows file names
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def save_snapshot(snapshot: dict[str, Any]) -> str:
    """
    save a json serializable snapshot to
      snapshots/<provider>/<account_or_subscription>/<timestamp>.json

    also writes/overwrites:
      snapshots/latest.json  (contains the path to the latest snapshot)
    """
    provider = (snapshot.get("metadata", {}).get("provider") or "unknown").lower()

    # for AWS we expect account_id in metadata
    # for future azure support maybe use subscription_id here instead.
    owner_id = snapshot.get("metadata", {}).get("account_id") or "unknown"

    project_root = Path(__file__).resolve().parent.parent
    snapshots_dir = project_root / "snapshots" / provider / str(owner_id)
    snapshots_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{_utc_timestamp_for_filename()}.json"
    out_path = snapshots_dir / filename

    out_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")

    # write latest pointer
    latest_path = project_root / "snapshots" / "latest.json"
    latest_payload = {
        "provider": provider,
        "owner_id": str(owner_id),
        "snapshot_path": str(out_path),
        "saved_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    latest_path.parent.mkdir(parents=True, exist_ok=True)
    latest_path.write_text(json.dumps(latest_payload, indent=2), encoding="utf-8")

    return str(out_path)
