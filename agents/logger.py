"""
Audit Logger — Immutable, hash-chained JSONL audit log.

Every AI decision is recorded as a hash-chained entry. Each entry includes
a SHA-256 hash of the previous entry, creating a tamper-evident chain.
Modifying any entry breaks the chain — providing cryptographic proof of integrity.
"""

import hashlib
import json
import time
import threading
from pathlib import Path
from typing import Optional


AUDIT_LOG_PATH = Path(__file__).parent.parent / "data" / "audit_log.jsonl"

_write_lock = threading.Lock()


def _compute_hash(data: str) -> str:
    """Compute SHA-256 hash of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _get_last_hash(log_path: Optional[str] = None) -> str:
    """Read the hash of the last entry in the audit log."""
    path = Path(log_path) if log_path else AUDIT_LOG_PATH

    if not path.exists() or path.stat().st_size == 0:
        return "GENESIS"

    last_line = ""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last_line = line

    if not last_line:
        return "GENESIS"

    try:
        entry = json.loads(last_line)
        return entry.get("entry_hash", "GENESIS")
    except json.JSONDecodeError:
        return "GENESIS"


def log_decision(
    prompt_text: str,
    classification: dict,
    policy_result: dict,
    log_path: Optional[str] = None,
) -> dict:
    """
    Write an immutable audit log entry for an AI decision.

    Args:
        prompt_text: The original prompt text (hashed, not stored raw)
        classification: Output from classifier.classify()
        policy_result: Output from policy_checker.check()
        log_path: Optional override path to audit_log.jsonl

    Returns:
        The complete audit log entry that was written
    """
    path = Path(log_path) if log_path else AUDIT_LOG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    with _write_lock:
        prev_hash = _get_last_hash(str(path))

        entry = {
            "timestamp": time.time(),
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
            "prompt_hash": _compute_hash(prompt_text),
            "prompt_length": len(prompt_text),
            "classification": {
                "data_types": classification.get("data_types", []),
                "sensitivity": classification.get("sensitivity", "low"),
                "sector": classification.get("sector", "general"),
                "contains_pii": classification.get("contains_pii", False),
                "confidence": classification.get("confidence", 0),
                "method": classification.get("method", "unknown"),
            },
            "policy_result": {
                "blocked": policy_result.get("blocked", False),
                "action": policy_result.get("action", "ALLOW"),
                "matched_rules": [
                    {
                        "rule_id": r.get("rule_id"),
                        "law": r.get("law"),
                        "action": r.get("action"),
                    }
                    for r in policy_result.get("matched_rules", [])
                ],
                "reason": policy_result.get("reason", ""),
            },
            "status": policy_result.get("action", "ALLOW"),
            "prev_hash": prev_hash,
        }

        # Compute entry hash over the full entry content (excluding entry_hash itself)
        entry_content = json.dumps(
            entry, sort_keys=True, separators=(",", ":"))
        entry["entry_hash"] = _compute_hash(entry_content)

        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")

    return entry


def verify_chain(log_path: Optional[str] = None) -> dict:
    """
    Verify the integrity of the entire audit log hash chain.

    Returns:
        Dict with: valid (bool), total_entries (int), broken_at (int or None),
        details (str)
    """
    path = Path(log_path) if log_path else AUDIT_LOG_PATH

    if not path.exists() or path.stat().st_size == 0:
        return {
            "valid": True,
            "total_entries": 0,
            "broken_at": None,
            "details": "Audit log is empty.",
        }

    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    entries.append((line_num, json.loads(line)))
                except json.JSONDecodeError:
                    return {
                        "valid": False,
                        "total_entries": line_num,
                        "broken_at": line_num,
                        "details": f"Malformed JSON at line {line_num}",
                    }

    expected_prev_hash = "GENESIS"

    for idx, (line_num, entry) in enumerate(entries):
        # Verify prev_hash chain
        if entry.get("prev_hash") != expected_prev_hash:
            return {
                "valid": False,
                "total_entries": len(entries),
                "broken_at": line_num,
                "details": (
                    f"Chain broken at entry {line_num}: "
                    f"expected prev_hash={expected_prev_hash[:16]}..., "
                    f"found prev_hash={entry.get('prev_hash', 'MISSING')[:16]}..."
                ),
            }

        # Verify entry_hash: recompute hash without entry_hash field
        stored_hash = entry.pop("entry_hash", None)
        recomputed_content = json.dumps(
            entry, sort_keys=True, separators=(",", ":"))
        recomputed_hash = _compute_hash(recomputed_content)
        entry["entry_hash"] = stored_hash  # restore

        if stored_hash != recomputed_hash:
            return {
                "valid": False,
                "total_entries": len(entries),
                "broken_at": line_num,
                "details": (
                    f"Entry hash mismatch at entry {line_num}: "
                    f"stored={stored_hash[:16]}..., recomputed={recomputed_hash[:16]}..."
                ),
            }

        expected_prev_hash = stored_hash

    return {
        "valid": True,
        "total_entries": len(entries),
        "broken_at": None,
        "details": f"All {len(entries)} entries verified. Hash chain is intact.",
    }


def get_entries(
    log_path: Optional[str] = None,
    last_n: Optional[int] = None,
    status_filter: Optional[str] = None,
) -> list[dict]:
    """
    Read audit log entries with optional filtering.

    Args:
        log_path: Optional override path
        last_n: Return only the last N entries
        status_filter: Filter by status (BLOCK, FLAG, ALLOW)
    """
    path = Path(log_path) if log_path else AUDIT_LOG_PATH

    if not path.exists():
        return []

    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entry = json.loads(line)
                    if status_filter and entry.get("status") != status_filter:
                        continue
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue

    if last_n:
        entries = entries[-last_n:]

    return entries


def get_stats(log_path: Optional[str] = None) -> dict:
    """Compute summary statistics from the audit log."""
    entries = get_entries(log_path)

    if not entries:
        return {
            "total": 0,
            "blocked": 0,
            "flagged": 0,
            "allowed": 0,
            "by_sector": {},
            "by_data_type": {},
        }

    stats = {
        "total": len(entries),
        "blocked": sum(1 for e in entries if e.get("status") == "BLOCK"),
        "flagged": sum(1 for e in entries if e.get("status") == "FLAG"),
        "allowed": sum(1 for e in entries if e.get("status") == "ALLOW"),
        "by_sector": {},
        "by_data_type": {},
    }

    for entry in entries:
        sector = entry.get("classification", {}).get("sector", "unknown")
        stats["by_sector"][sector] = stats["by_sector"].get(sector, 0) + 1

        for dt in entry.get("classification", {}).get("data_types", []):
            stats["by_data_type"][dt] = stats["by_data_type"].get(dt, 0) + 1

    return stats
