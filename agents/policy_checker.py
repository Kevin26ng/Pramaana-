"""
Policy Engine — Checks classified data against Indian regulatory rulebook.

Loads rules from data/policies.json and evaluates each AI call's classification
to determine: BLOCK, FLAG, or ALLOW — with specific law citations.
"""

import json
import os
from pathlib import Path
from typing import Optional


POLICIES_PATH = Path(__file__).parent.parent / "data" / "policies.json"


def _load_policies(path: Optional[str] = None) -> list[dict]:
    """Load the compliance rulebook from JSON."""
    policy_file = Path(path) if path else POLICIES_PATH
    with open(policy_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["policies"]


def check(classification: dict, policies_path: Optional[str] = None) -> dict:
    """
    Evaluate a classification result against the policy rulebook.

    Args:
        classification: Output from classifier.classify() with keys:
            data_types, sensitivity, sector, contains_pii
        policies_path: Optional override path to policies.json

    Returns:
        Dict with:
            blocked (bool), action (BLOCK/FLAG/ALLOW),
            matched_rules (list of triggered rules with citations),
            reason (human-readable summary)
    """
    policies = _load_policies(policies_path)

    data_types = set(classification.get("data_types", []))
    sector = classification.get("sector", "general").lower()
    contains_pii = classification.get("contains_pii", False)

    if not contains_pii or data_types == {"none"}:
        return {
            "blocked": False,
            "action": "ALLOW",
            "matched_rules": [],
            "reason": "No sensitive Indian data detected. Request allowed.",
        }

    matched_rules = []

    for policy in policies:
        trigger = policy["trigger"]
        trigger_types = set(trigger.get("data_types", []))
        trigger_sectors = trigger.get("sectors", [])

        # Check if any classified data type matches this rule's triggers
        type_match = bool(data_types & trigger_types)

        # Check sector: "*" means all sectors match
        sector_match = "*" in trigger_sectors or sector in trigger_sectors

        if type_match and sector_match:
            matched_rules.append({
                "rule_id": policy["rule_id"],
                "law": policy["law"],
                "action": policy["action"],
                "reason": policy["description"],
                "citation": policy["citation"],
                "penalty": policy["penalty"],
            })

    if not matched_rules:
        return {
            "blocked": False,
            "action": "ALLOW",
            "matched_rules": [],
            "reason": "PII detected but no matching policy rules triggered. Request allowed with advisory.",
        }

    # Determine overall action: BLOCK takes precedence over FLAG
    has_block = any(r["action"] == "BLOCK" for r in matched_rules)
    overall_action = "BLOCK" if has_block else "FLAG"

    # Build human-readable reason from the highest-severity matched rule
    primary_rule = next(
        (r for r in matched_rules if r["action"] == "BLOCK"),
        matched_rules[0],
    )

    reason = (
        f"{primary_rule['reason']} "
        f"[{primary_rule['rule_id']}] — {primary_rule['law']}. "
        f"Penalty: {primary_rule['penalty']}"
    )

    return {
        "blocked": has_block,
        "action": overall_action,
        "matched_rules": matched_rules,
        "reason": reason,
    }


def get_policy_summary() -> list[dict]:
    """Return a summary of all loaded policies (for dashboard display)."""
    policies = _load_policies()
    return [
        {
            "rule_id": p["rule_id"],
            "law": p["law"],
            "action": p["action"],
            "trigger_types": p["trigger"]["data_types"],
            "trigger_sectors": p["trigger"]["sectors"],
        }
        for p in policies
    ]
