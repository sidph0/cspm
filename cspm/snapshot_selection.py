from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class SnapshotPair:
    latest_path: Path
    previous_path: Path
    latest: dict[str, Any]
    previous: dict[str, Any]


def load_snapshot(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def get_latest_and_previous(
    *,
    provider: str,
    owner_id: Optional[str] = None,
    project_root: Optional[Path] = None,
) -> SnapshotPair:
    """
    find / load the latest and previous snapshots for a provider (and optionally owner_id).

    Expected snapshot layout:
      snapshots/<provider>/<owner_id>/<timestamp>.json
    Also uses:
      snapshots/latest.json (as a hint for latest snapshot path)

    FileNotFoundError if not enough snapshots are found
    ValueError if snapshots cannot be loaded/parsed
    """
    root = project_root or Path(__file__).resolve().parent.parent
    snapshots_root = root / "snapshots"

    provider_slug = provider.lower().strip()
    provider_dir = snapshots_root / provider_slug
    if not provider_dir.exists():
        raise FileNotFoundError(f"No snapshots found for provider '{provider_slug}' at: {provider_dir}")

    # if owner_id not given try to get it from snapshots/latest.json
    if owner_id is None:
        latest_hint = _read_latest_hint(snapshots_root)
        if latest_hint and latest_hint.get("provider") == provider_slug:
            owner_id = str(latest_hint.get("owner_id") or "").strip() or None

    # make search directory: provider/<owner> or provider/*
    if owner_id:
        search_dir = provider_dir / str(owner_id)
        if not search_dir.exists():
            raise FileNotFoundError(f"No snapshots found for provider '{provider_slug}' and owner '{owner_id}' at: {search_dir}")
        candidate_files = sorted(search_dir.glob("*.json"))
    else:
        # search all owners under this provider
        candidate_files = sorted(provider_dir.glob("*/*.json"))

    # ignore snapshots/latest.json if it somehow gets included bc it shouldn't in this structure
    candidate_files = [p for p in candidate_files if p.name.lower() != "latest.json"]

    if len(candidate_files) < 2:
        raise FileNotFoundError(
            f"Need at least 2 snapshots to compute drift, found {len(candidate_files)}."
        )

    # sort by filename (YYYYMMDDTHHMMSSZ so lexicographic sort works)
    candidate_files.sort(key=lambda p: p.name)

    latest_path = candidate_files[-1]
    previous_path = candidate_files[-2]

    latest = load_snapshot(latest_path)
    previous = load_snapshot(previous_path)

    return SnapshotPair(
        latest_path=latest_path,
        previous_path=previous_path,
        latest=latest,
        previous=previous,
    )


def _read_latest_hint(snapshots_root: Path) -> Optional[dict[str, Any]]:
    """
    reads snapshots/latest.json if it exists
    """
    hint_path = snapshots_root / "latest.json"
    if not hint_path.exists():
        return None
    try:
        return json.loads(hint_path.read_text(encoding="utf-8"))
    except Exception:
        return None
