"""
API Proxy — FastAPI interception layer for AI calls.

Sits between the enterprise AI stack and any LLM provider.
Every request passes through the three-agent pipeline:
Classifier -> Policy Engine -> Audit Logger
"""

import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from agents import classifier, policy_checker, logger, report_generator


load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Verify audit chain integrity on startup."""
    chain_status = logger.verify_chain()
    if not chain_status["valid"]:
        print(f"⚠ AUDIT CHAIN INTEGRITY WARNING: {chain_status['details']}")
    else:
        print(
            f"✓ Audit chain intact: {chain_status['total_entries']} entries verified")
    yield


app = FastAPI(
    title="AI Compliance Audit Proxy",
    description="Compliance interception layer for Indian regulated AI systems — DPDP Act, RBI FREE-AI, IRDAI",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files (images, videos, etc.) from the ui/ folder
_ui_dir = Path(__file__).resolve().parent.parent / "ui"
app.mount("/static", StaticFiles(directory=str(_ui_dir)), name="static")


# --- Request / Response Models ---

class AIRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=50000,
                        description="The AI prompt to audit")
    sector: Optional[str] = Field(
        None, description="Override sector (banking, healthcare, insurance, etc.)")
    use_llm_classifier: bool = Field(
        True, description="Use Claude for classification (set False for regex-only)")
    metadata: Optional[dict] = Field(
        None, description="Additional metadata to attach to the audit entry")


class ClassificationResult(BaseModel):
    data_types: list[str]
    sensitivity: str
    sector: str
    contains_pii: bool
    confidence: float
    method: str


class PolicyResult(BaseModel):
    blocked: bool
    action: str
    matched_rules: list[dict]
    reason: str


class AuditResponse(BaseModel):
    status: str
    classification: ClassificationResult
    policy_result: PolicyResult
    audit_entry: dict
    processing_time_ms: float


class ChainVerification(BaseModel):
    valid: bool
    total_entries: int
    broken_at: Optional[int]
    details: str


# --- Endpoints ---

@app.get("/")
async def root():
    """Serve the frontend HTML."""
    html_path = Path(__file__).resolve().parent.parent / "ui" / "index.html"
    if html_path.exists():
        return FileResponse(html_path, media_type="text/html")
    return {
        "service": "AI Compliance Audit Proxy",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/health",
    }


@app.post("/audit", response_model=AuditResponse)
async def audit_ai_call(request: AIRequest):
    """
    Main endpoint: intercept and audit an AI call.

    Pipeline: Classify -> Check Policy -> Log Decision
    """
    start = time.time()

    # Step 1: Classify
    classification = classifier.classify(
        request.prompt,
        use_llm=request.use_llm_classifier,
    )

    # Override sector if provided
    if request.sector:
        classification["sector"] = request.sector.lower()

    # Step 2: Check against policy engine
    policy_result = policy_checker.check(classification)

    # Step 3: Log the decision
    audit_entry = logger.log_decision(
        prompt_text=request.prompt,
        classification=classification,
        policy_result=policy_result,
    )

    elapsed_ms = round((time.time() - start) * 1000, 2)

    return AuditResponse(
        status=policy_result["action"],
        classification=ClassificationResult(**classification),
        policy_result=PolicyResult(**policy_result),
        audit_entry=audit_entry,
        processing_time_ms=elapsed_ms,
    )


@app.get("/audit/log")
async def get_audit_log(last_n: Optional[int] = None, status: Optional[str] = None):
    """Retrieve audit log entries with optional filters."""
    entries = logger.get_entries(last_n=last_n, status_filter=status)
    return {"entries": entries, "count": len(entries)}


@app.get("/audit/stats")
async def get_audit_stats():
    """Get summary statistics from the audit log."""
    return logger.get_stats()


@app.get("/audit/verify", response_model=ChainVerification)
async def verify_chain():
    """Verify the integrity of the audit log hash chain."""
    return logger.verify_chain()


@app.get("/policies")
async def get_policies():
    """List all compliance policies in the rulebook."""
    return {"policies": policy_checker.get_policy_summary()}


@app.post("/report")
async def generate_report(last_n: Optional[int] = None):
    """Generate a regulator-ready PDF audit report."""
    try:
        pdf_path = report_generator.generate_pdf(last_n=last_n)
        return {"status": "generated", "path": pdf_path}
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Report generation failed: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    chain = logger.verify_chain()
    return {
        "status": "healthy",
        "audit_chain_valid": chain["valid"],
        "total_audit_entries": chain["total_entries"],
    }
