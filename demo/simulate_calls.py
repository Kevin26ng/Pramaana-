"""
Demo Simulator — Sends 6 mixed AI calls through the audit proxy.

Demonstrates the full pipeline: classification, policy enforcement,
and audit logging with different data types and sectors.
"""

from agents import classifier, policy_checker, logger
import sys
import time
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


DEMO_CALLS = [
    {
        "name": "Credit Score Check (Banking)",
        "prompt": (
            "Evaluate the credit score for customer with Aadhaar number 9876 5432 1098 "
            "and bank account number 12345678901234. Their recent NEFT transaction history "
            "shows 15 transfers totaling ₹4,50,000. Recommend credit limit."
        ),
        "sector_override": "banking",
    },
    {
        "name": "Patient Triage (Healthcare)",
        "prompt": (
            "Patient ABHA ID 91-4523-6789-0012 presents with symptoms consistent with "
            "Type 2 diabetes. Lab report shows HbA1c at 8.2%. Previous prescription includes "
            "Metformin 500mg. Recommend treatment plan adjustment based on medical history."
        ),
        "sector_override": "healthcare",
    },
    {
        "name": "Fraud Detection (Banking)",
        "prompt": (
            "Flag suspicious activity on account IFSC SBIN0001234. Customer PAN ABCDE1234F "
            "linked to 3 UPI IDs. Transaction pattern shows 47 micro-transactions under ₹200 "
            "in 24 hours via IMPS. Run fraud detection model."
        ),
        "sector_override": "banking",
    },
    {
        "name": "Insurance Underwriting (Insurance)",
        "prompt": (
            "Process underwriting for policyholder. Biometric verification includes fingerprint "
            "scan and iris scan data. Policyholder age 42, non-smoker. Run risk assessment "
            "model with biometric identity verification for life insurance policy."
        ),
        "sector_override": "insurance",
    },
    {
        "name": "General Query (No PII)",
        "prompt": (
            "What is the current RBI repo rate? Summarize the latest monetary policy "
            "committee minutes and explain the impact on home loan EMIs."
        ),
        "sector_override": None,
    },
    {
        "name": "Cross-sector Health + Finance",
        "prompt": (
            "Customer with Aadhaar 1234 5678 9012 is applying for a health insurance policy. "
            "Their ABDM health records show a pre-existing cardiac condition. Bank statement "
            "from account 9876543210 shows premium payment capacity. Process the application."
        ),
        "sector_override": "insurance",
    },
]


def _status_color(status: str) -> str:
    """ANSI color codes for terminal output."""
    colors = {"BLOCK": "\033[91m", "FLAG": "\033[93m", "ALLOW": "\033[92m"}
    reset = "\033[0m"
    return f"{colors.get(status, '')}{status}{reset}"


def run_demo():
    """Execute all demo calls through the agent pipeline."""
    print("=" * 70)
    print("  AI COMPLIANCE AUDIT — DEMO SIMULATOR")
    print("  Processing 6 mixed AI calls through the compliance pipeline")
    print("=" * 70)
    print()

    results = []

    for idx, call in enumerate(DEMO_CALLS, 1):
        print(f"{'─' * 70}")
        print(f"  [{idx}/6] {call['name']}")
        print(f"{'─' * 70}")
        print(f"  Prompt: {call['prompt'][:100]}...")
        print()

        start = time.time()

        # Step 1: Classify (regex-only for demo speed)
        print("  ⟶ Classifying...", end=" ", flush=True)
        classification = classifier.classify(call["prompt"], use_llm=False)

        if call["sector_override"]:
            classification["sector"] = call["sector_override"]

        print(f"Done ({classification['method']})")
        print(f"    Data types: {classification['data_types']}")
        print(f"    Sensitivity: {classification['sensitivity']}")
        print(f"    Sector: {classification['sector']}")
        print(f"    Contains PII: {classification['contains_pii']}")
        print()

        # Step 2: Policy check
        print("  ⟶ Checking policies...", end=" ", flush=True)
        policy_result = policy_checker.check(classification)
        print("Done")
        print(f"    Action: {_status_color(policy_result['action'])}")
        if policy_result["matched_rules"]:
            for rule in policy_result["matched_rules"]:
                print(f"    Rule: {rule['rule_id']} — {rule['law']}")
        print(f"    Reason: {policy_result['reason'][:120]}")
        print()

        # Step 3: Audit log
        print("  ⟶ Logging decision...", end=" ", flush=True)
        audit_entry = logger.log_decision(
            prompt_text=call["prompt"],
            classification=classification,
            policy_result=policy_result,
        )
        elapsed = round((time.time() - start) * 1000, 1)
        print(f"Done ({elapsed}ms)")
        print(f"    Entry hash: {audit_entry['entry_hash'][:32]}...")
        print(f"    Prev hash:  {audit_entry['prev_hash'][:32]}...")
        print()

        results.append({
            "name": call["name"],
            "status": policy_result["action"],
            "elapsed_ms": elapsed,
        })

    # Summary
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    for r in results:
        print(
            f"  {_status_color(r['status']):>20s}  {r['name']}  ({r['elapsed_ms']}ms)")

    print()
    blocked = sum(1 for r in results if r["status"] == "BLOCK")
    flagged = sum(1 for r in results if r["status"] == "FLAG")
    allowed = sum(1 for r in results if r["status"] == "ALLOW")
    print(f"  Blocked: {blocked} | Flagged: {flagged} | Allowed: {allowed}")
    print()

    # Verify chain
    print("  Verifying audit chain integrity...", end=" ", flush=True)
    chain_result = logger.verify_chain()
    if chain_result["valid"]:
        print(f"\033[92m✓ {chain_result['details']}\033[0m")
    else:
        print(f"\033[91m✗ {chain_result['details']}\033[0m")
    print()


if __name__ == "__main__":
    run_demo()
