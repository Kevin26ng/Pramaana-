"""
Classifier Agent — Detects sensitive Indian data types in AI prompts.

Uses Anthropic Claude as the primary classifier with regex-based fallback
for deterministic detection of structured identifiers (Aadhaar, PAN, etc.).
"""

import re
import os
import json
from typing import Optional
from anthropic import Anthropic


# Regex patterns for deterministic Indian PII detection
INDIAN_PII_PATTERNS = {
    "aadhaar": [
        # 12-digit with optional spaces
        re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
        re.compile(r"\b(?:aadhaar|aadhar|uidai)\b", re.IGNORECASE),
    ],
    "pan": [
        re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),  # ABCDE1234F format
        re.compile(r"\b(?:pan\s*(?:card|number|no))\b", re.IGNORECASE),
    ],
    "health": [
        re.compile(r"\b(?:abha|abdm|health\s*id|patient\s*(?:id|record|data)|medical\s*record|diagnosis|prescription|treatment\s*plan|lab\s*report|blood\s*(?:test|report)|health\s*record)\b", re.IGNORECASE),
        re.compile(r"\b(?:ICD-?\d{1,2}|SNOMED|LOINC)\b", re.IGNORECASE),
        re.compile(r"\b\d{2}-\d{4}-\d{4}-\d{4}\b"),  # ABHA number pattern
    ],
    "financial": [
        re.compile(r"\b(?:account\s*(?:number|no)|ifsc|upi\s*id|credit\s*score|loan\s*(?:amount|account|id)|transaction\s*(?:id|data|record)|bank\s*(?:statement|balance)|neft|rtgs|imps)\b", re.IGNORECASE),
        re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),  # IFSC code
        re.compile(r"\b\d{9,18}\b"),  # Bank account number range
        re.compile(r"\b[\w.]+@[a-z]{3,}\b"),  # UPI ID pattern (simplified)
    ],
    "biometric": [
        re.compile(r"\b(?:biometric|fingerprint|iris\s*scan|retina|face\s*(?:id|recognition|data)|voice\s*(?:print|recognition)|palm\s*print)\b", re.IGNORECASE),
    ],
}

# Sector detection keywords
SECTOR_KEYWORDS = {
    "banking": ["bank", "banking", "credit", "loan", "deposit", "neft", "rtgs", "imps", "upi", "rbi", "nbfc"],
    "finance": ["finance", "fintech", "investment", "mutual fund", "stock", "demat", "sebi"],
    "fintech": ["fintech", "digital lending", "payment gateway", "wallet"],
    "healthcare": ["hospital", "healthcare", "patient", "doctor", "medical", "clinical", "diagnosis", "pharma"],
    "hospital": ["hospital", "ward", "icu", "opd", "ipd", "discharge"],
    "pharma": ["pharma", "pharmaceutical", "drug", "medicine"],
    "insurance": ["insurance", "policy", "premium", "claim", "underwriting", "actuary", "irdai"],
    "insurtech": ["insurtech", "digital insurance"],
}

CLASSIFICATION_PROMPT = """You are an Indian data compliance classifier. Analyze the following text and identify:

1. **Data types present** — Choose from: aadhaar, pan, health, financial, biometric, general_pii, none
2. **Sensitivity level** — one of: critical, high, medium, low
3. **Sector** — Choose from: banking, finance, fintech, healthcare, hospital, pharma, insurance, insurtech, general
4. **Contains PII** — true or false
5. **Confidence** — your confidence score from 0.0 to 1.0

Respond ONLY with valid JSON in this exact format:
{
  "data_types": ["aadhaar", "financial"],
  "sensitivity": "critical",
  "sector": "banking",
  "contains_pii": true,
  "confidence": 0.95
}

Text to classify:
---
{prompt_text}
---

JSON response:"""


def _regex_classify(text: str) -> dict:
    """Fast deterministic classification using regex patterns."""
    detected_types = []

    for data_type, patterns in INDIAN_PII_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(text):
                detected_types.append(data_type)
                break

    detected_sectors = []
    text_lower = text.lower()
    for sector, keywords in SECTOR_KEYWORDS.items():
        for keyword in keywords:
            if keyword in text_lower:
                detected_sectors.append(sector)
                break

    contains_pii = len(detected_types) > 0

    if any(t in detected_types for t in ["aadhaar", "biometric"]):
        sensitivity = "critical"
    elif any(t in detected_types for t in ["financial", "health"]):
        sensitivity = "high"
    elif "pan" in detected_types:
        sensitivity = "medium"
    else:
        sensitivity = "low"

    return {
        "data_types": detected_types if detected_types else ["none"],
        "sensitivity": sensitivity,
        "sector": detected_sectors[0] if detected_sectors else "general",
        "contains_pii": contains_pii,
        "confidence": 0.7 if contains_pii else 0.5,
        "method": "regex",
    }


def _llm_classify(text: str, api_key: Optional[str] = None) -> dict:
    """Classification using Anthropic Claude for nuanced detection."""
    key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not key:
        raise ValueError(
            "ANTHROPIC_API_KEY is required for LLM classification")

    client = Anthropic(api_key=key)

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=512,
        messages=[
            {
                "role": "user",
                "content": CLASSIFICATION_PROMPT.format(prompt_text=text[:4000]),
            }
        ],
    )

    response_text = message.content[0].text.strip()

    # Extract JSON from the response
    try:
        # Try direct parse first
        result = json.loads(response_text)
    except json.JSONDecodeError:
        # Try to find JSON in the response
        json_match = re.search(r"\{.*\}", response_text, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
        else:
            raise ValueError(f"Could not parse LLM response: {response_text}")

    result["method"] = "llm"
    return result


def classify(text: str, use_llm: bool = True, api_key: Optional[str] = None) -> dict:
    """
    Classify a prompt for sensitive Indian data types.

    Uses regex for fast deterministic detection first, then optionally
    enhances with LLM classification for nuanced understanding.

    Args:
        text: The prompt text to classify
        use_llm: Whether to use Claude for classification (default True)
        api_key: Optional Anthropic API key override

    Returns:
        Classification dict with data_types, sensitivity, sector, contains_pii, confidence
    """
    # Always run regex first for deterministic matches
    regex_result = _regex_classify(text)

    if not use_llm:
        return regex_result

    try:
        llm_result = _llm_classify(text, api_key)

        # Merge: union of data types from both methods, take highest sensitivity
        merged_types = list(
            set(regex_result["data_types"] + llm_result.get("data_types", [])))
        if "none" in merged_types and len(merged_types) > 1:
            merged_types.remove("none")

        sensitivity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        regex_sev = sensitivity_order.get(regex_result["sensitivity"], 0)
        llm_sev = sensitivity_order.get(
            llm_result.get("sensitivity", "low"), 0)

        return {
            "data_types": merged_types,
            "sensitivity": regex_result["sensitivity"] if regex_sev >= llm_sev else llm_result["sensitivity"],
            "sector": llm_result.get("sector", regex_result["sector"]),
            "contains_pii": regex_result["contains_pii"] or llm_result.get("contains_pii", False),
            "confidence": max(regex_result["confidence"], llm_result.get("confidence", 0)),
            "method": "hybrid",
        }
    except Exception:
        # Fall back to regex if LLM fails
        regex_result["method"] = "regex_fallback"
        return regex_result
