# [Project Name]

> AI compliance audit layer for Indian regulated enterprises — built for the DPDP Act, RBI FREE-AI framework, and IRDAI guidelines.

---

## The Problem

Indian banks, hospitals, and insurers are making thousands of AI-powered decisions every day — credit scoring, fraud detection, patient triage, underwriting. But if a regulator walked in tomorrow and asked _"show me every AI decision you made, what data it touched, and where that data was processed"_ — most enterprises have no answer.

That is not a technology gap. It is a compliance liability.

The DPDP Act 2023, RBI's FREE-AI framework (August 2025), and IRDAI data guidelines have created mandatory audit and explainability requirements for AI systems in regulated sectors. Penalties under DPDP reach ₹250 crore per violation. Enforcement is coming. The infrastructure to comply does not exist yet.

Global tools like Fiddler AI and Monitaur solve this for Wall Street — GDPR, HIPAA, EU AI Act. Nobody has solved it for Dalal Street.

---

## What This Does

**[Project Name]** sits as a lightweight proxy between an enterprise's AI calls and any LLM provider. Every request passes through three agents:

1. **Classifier Agent** — detects sensitive Indian data types in the prompt: Aadhaar numbers, PAN, health records, financial transaction data, biometric identifiers
2. **Policy Engine** — checks the classified data against a rulebook of Indian regulations: DPDP Act sections, RBI circulars, IRDAI guidelines. Blocks or flags violations in real time
3. **Audit Logger** — writes an immutable, hash-chained record of every AI decision: what data went in, what rule applied, what was blocked, what was allowed, on what infrastructure

The output is a regulator-ready audit trail — structured specifically to answer what the DPBI, RBI, and IRDAI actually ask during an audit.

##### DIFFEENCE WITH EXISTING TOOLS - WHAT INDIA NEEDS RIGHT NOW

Every existing tool logs what AI does. You log what AI does and whether it was legal under Indian law — with the specific citation a regulator can act on.
That's it. That's the gap.
Fiddler, Monitaur, Langfuse, Arize — they all produce engineering evidence. Latency, token counts, drift, hallucination rates. Useful for your ML team. Useless when the RBI auditor walks in.
Your tool produces legal evidence. Not "this call took 340ms." But "this call processed Aadhaar data outside a MEITY-empaneled node, violating DPDP Act 2023 Section 16, at 14:32 IST on April 5, and here is the cryptographic proof that this log has not been tampered with."
The buyer shift is the tell. Every competitor sells to the CTO or the ML engineer. You sell to the Chief Compliance Officer and the Board Risk Committee — people who have personal liability if an audit goes wrong. That's a completely different conversation, a different budget line, and a different urgency level.
The second differentiator nobody will say out loud but judges will feel: you are six months early. RBI's FREE-AI framework dropped in August 2025. MeitY's AI governance guidelines dropped in November 2025. The regulation is so new that even the enterprises who want to comply don't know exactly what compliance looks like yet. You're not catching up to a market — you're arriving before the market knows it needs you. That's the best place to be at a hackathon, because you can credibly say the incumbents haven't reacted yet.

---

## Demo Flow

```
1. Enterprise submits AI call (credit scoring, patient query, fraud detection)
2. Classifier identifies: Aadhaar + financial data + banking sector
3. Policy engine checks: RBI-CIR-2023 — data cannot leave Indian jurisdiction
4. Decision: BLOCKED — reason and law citation logged
5. Audit trail updated with tamper-evident hash chain
6. Regulator PDF report generated on demand
```

Run the demo simulator to see 6 mixed calls processed live:

```bash
python demo/simulate_calls.py
```

---

## Architecture

```
Enterprise AI Stack
        │
        ▼
┌─────────────────┐
│   API Proxy     │  ← FastAPI — intercepts every AI call
│  (proxy.py)     │
└────────┬────────┘
         │
    ┌────▼─────────────────────────┐
    │         Agent Pipeline        │
    │                               │
    │  1. Classifier Agent          │  ← Claude claude-sonnet-4-20250514
    │     Detects: Aadhaar, PAN,    │
    │     health, financial, bio    │
    │                               │
    │  2. Policy Engine             │  ← JSON rulebook (DPDP, RBI, IRDAI)
    │     BLOCK / FLAG / ALLOW      │
    │                               │
    │  3. Audit Logger              │  ← Append-only, hash-chained JSONL
    │     Immutable decision record │
    └────────────────────────────────┘
         │
    ┌────▼────────────┐
    │  Streamlit UI   │  ← Live feed, metrics, PDF report
    └─────────────────┘
```

---

## Folder Structure

```
[project-name]/
├── main.py
├── agents/
│   ├── classifier.py        # Indian PII + data type detection
│   ├── policy_checker.py    # DPDP / RBI / IRDAI rule enforcement
│   ├── logger.py            # Immutable hash-chained audit log
│   └── report_generator.py # Regulator-ready PDF generation
├── data/
│   ├── policies.json        # Compliance rulebook
│   └── audit_log.jsonl      # Append-only decision log
├── api/
│   └── proxy.py             # FastAPI interception layer
├── demo/
│   └── simulate_calls.py    # Demo request simulator
└── ui/
    └── dashboard.py         # Streamlit live dashboard
```

---

## Quickstart

```bash
# Clone
git clone https://github.com/[your-username]/[project-name]
cd [project-name]

# Install
pip install fastapi uvicorn anthropic streamlit reportlab python-dotenv

# Set API key
echo "ANTHROPIC_API_KEY=your_key_here" > .env

# Run API (terminal 1)
uvicorn api.proxy:app --reload

# Run dashboard (terminal 2)
streamlit run ui/dashboard.py

# Run demo (terminal 3)
python demo/simulate_calls.py
```

---

## Compliance Rules Implemented

| Rule ID      | Law                        | Trigger                    | Action |
| ------------ | -------------------------- | -------------------------- | ------ |
| DPDP-001     | DPDP Act 2023 §16          | Aadhaar data, any sector   | BLOCK  |
| RBI-CIR-2023 | RBI IT Framework 2023      | Financial data, banking    | BLOCK  |
| DPDP-002     | DPDP Act 2023 + ABDM       | Health records, healthcare | FLAG   |
| IRDAI-2024   | IRDAI Data Guidelines 2024 | Biometric data, insurance  | BLOCK  |

Rules are defined in `data/policies.json` and can be extended without touching application code.

---

## Audit Log Format

Every AI decision is logged as a hash-chained entry. Tamper with any entry and the chain breaks — providing cryptographic proof of log integrity.

```json
{
  "timestamp": 1743000000.0,
  "prompt_hash": "sha256 of original prompt",
  "classification": {
    "data_types": ["aadhaar", "financial"],
    "sensitivity": "critical",
    "sector": "banking",
    "contains_pii": true
  },
  "policy_result": {
    "blocked": true,
    "rule": "RBI-CIR-2023",
    "law": "RBI IT Framework 2023",
    "reason": "Financial transaction data must remain within Indian jurisdiction"
  },
  "status": "BLOCKED",
  "prev_hash": "abc123...",
  "entry_hash": "def456..."
}
```

---

## Why This Is Different

|              | Global tools (Fiddler, Monitaur) | [Project Name]                |
| ------------ | -------------------------------- | ----------------------------- |
| Regulation   | GDPR, HIPAA, EU AI Act           | DPDP Act, RBI FREE-AI, IRDAI  |
| Geography    | US / EU enterprises              | Indian regulated enterprises  |
| Data types   | Generic PII                      | Aadhaar, PAN, ABDM health IDs |
| Audit output | Engineering dashboards           | Regulator-ready PDF reports   |
| Target buyer | CTO / ML team                    | Chief Compliance Officer      |

---

## Regulatory Context

- **DPDP Act 2023** — India's first comprehensive data protection law. Penalties up to ₹250 crore per violation. Rules notified in 2025.
- **RBI FREE-AI Framework (Aug 2025)** — 26 recommendations for AI governance in financial services. Mandates board-approved AI policies, model inventories, and incident reporting.
- **MeitY AI Governance Guidelines (Nov 2025)** — Activity-based risk classification. High-risk AI deployments (credit scoring, healthcare diagnostics) expected to require mandatory audits.
- **IRDAI Data Guidelines** — Data residency and processing restrictions for insurance AI applications.

---

## Stack

- **Backend**: FastAPI + Python
- **AI Agent**: Claude claude-sonnet-4-20250514 (Anthropic)
- **Audit storage**: Append-only JSONL with SHA-256 hash chaining
- **Dashboard**: Streamlit
- **Report generation**: ReportLab
- **Deployment**: Railway (API) + Streamlit Cloud (UI)

---

## Live Demo

- **Dashboard**: [your-streamlit-url]
- **API**: [your-railway-url]
- **Assessment note**: Project is a hackathon MVP — demo infrastructure may be under active development.

---

## What's Next (Post-Hackathon)

- Real Indian cloud provider integration (NIC Cloud, Yotta, CtrlS — MEITY-empaneled)
- Aadhaar pattern detection hardened with regex + ML classifier
- Consent management module (DPDP §6 — informed consent logging)
- Multi-tenant isolation for enterprise pilots
- Direct DPBI breach notification API integration

---
