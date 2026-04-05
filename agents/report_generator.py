"""
Report Generator — Produces regulator-ready PDF audit reports.

Generates structured PDF reports from the audit log, formatted to answer
the specific questions DPBI, RBI, and IRDAI auditors ask during inspections.
"""

import time
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from agents import logger


REPORTS_DIR = Path(__file__).parent.parent / "reports"


def _build_styles():
    """Create custom paragraph styles for the report."""
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=18,
        spaceAfter=12,
        textColor=colors.HexColor("#1a1a2e"),
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=16,
        spaceAfter=8,
        textColor=colors.HexColor("#16213e"),
    ))
    styles.add(ParagraphStyle(
        name="BodySmall",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12,
    ))
    styles.add(ParagraphStyle(
        name="Disclaimer",
        parent=styles["BodyText"],
        fontSize=7,
        textColor=colors.grey,
        spaceBefore=20,
    ))
    return styles


def generate_pdf(
    output_path: Optional[str] = None,
    last_n: Optional[int] = None,
    log_path: Optional[str] = None,
) -> str:
    """
    Generate a regulator-ready PDF audit report.

    Args:
        output_path: Where to save the PDF. Defaults to reports/audit_report_<timestamp>.pdf
        last_n: Include only the last N entries
        log_path: Optional override for audit log path

    Returns:
        The file path of the generated PDF
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if output_path is None:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_path = str(REPORTS_DIR / f"audit_report_{timestamp}.pdf")

    entries = logger.get_entries(log_path=log_path, last_n=last_n)
    stats = logger.get_stats(log_path=log_path)
    chain_status = logger.verify_chain(log_path=log_path)

    styles = _build_styles()
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    elements = []

    # --- Title Page ---
    elements.append(Spacer(1, 40 * mm))
    elements.append(
        Paragraph("AI Compliance Audit Report", styles["ReportTitle"]))
    elements.append(Paragraph(
        "Regulatory Compliance Assessment — DPDP Act 2023, RBI FREE-AI Framework, IRDAI Guidelines",
        styles["BodyText"],
    ))
    elements.append(Spacer(1, 10 * mm))
    elements.append(Paragraph(
        f"<b>Generated:</b> {time.strftime('%d %B %Y, %H:%M IST')}",
        styles["BodyText"],
    ))
    elements.append(Paragraph(
        f"<b>Total Decisions Audited:</b> {stats['total']}",
        styles["BodyText"],
    ))
    elements.append(Paragraph(
        f"<b>Hash Chain Integrity:</b> {'VERIFIED ✓' if chain_status['valid'] else 'BROKEN ✗ — TAMPERING DETECTED'}",
        styles["BodyText"],
    ))
    elements.append(PageBreak())

    # --- Executive Summary ---
    elements.append(Paragraph("1. Executive Summary", styles["SectionHeader"]))
    summary_data = [
        ["Metric", "Value"],
        ["Total AI Decisions", str(stats["total"])],
        ["Blocked (Violation)", str(stats["blocked"])],
        ["Flagged (Review Required)", str(stats["flagged"])],
        ["Allowed", str(stats["allowed"])],
        ["Audit Log Integrity", "Intact" if chain_status["valid"] else "COMPROMISED"],
    ]
    summary_table = Table(summary_data, colWidths=[200, 200])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f0f0f5")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 8 * mm))

    # --- Sector Breakdown ---
    if stats.get("by_sector"):
        elements.append(
            Paragraph("2. Decisions by Sector", styles["SectionHeader"]))
        sector_data = [["Sector", "Count"]]
        for sector, count in sorted(stats["by_sector"].items(), key=lambda x: -x[1]):
            sector_data.append([sector.title(), str(count)])
        sector_table = Table(sector_data, colWidths=[200, 200])
        sector_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f0f0f5")]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(sector_table)
        elements.append(Spacer(1, 8 * mm))

    # --- Detailed Audit Entries ---
    elements.append(
        Paragraph("3. Detailed Audit Trail", styles["SectionHeader"]))

    if not entries:
        elements.append(
            Paragraph("No audit entries recorded.", styles["BodyText"]))
    else:
        entry_data = [["#", "Timestamp", "Status",
                       "Sector", "Data Types", "Rule", "Reason"]]
        for idx, entry in enumerate(entries, 1):
            classification = entry.get("classification", {})
            policy = entry.get("policy_result", {})
            matched = policy.get("matched_rules", [])
            rule_ids = ", ".join(r.get("rule_id", "—")
                                 for r in matched) if matched else "—"

            # Truncate reason for table fitting
            reason = policy.get("reason", "—")
            if len(reason) > 80:
                reason = reason[:77] + "..."

            status = entry.get("status", "ALLOW")
            timestamp_iso = entry.get("timestamp_iso", "—")

            entry_data.append([
                str(idx),
                Paragraph(timestamp_iso, styles["BodySmall"]),
                status,
                classification.get("sector", "—").title(),
                Paragraph(", ".join(classification.get(
                    "data_types", [])), styles["BodySmall"]),
                Paragraph(rule_ids, styles["BodySmall"]),
                Paragraph(reason, styles["BodySmall"]),
            ])

        col_widths = [25, 75, 45, 55, 65, 60, 145]
        entry_table = Table(entry_data, colWidths=col_widths, repeatRows=1)

        # Color-code rows by status
        table_style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]

        for idx, entry in enumerate(entries, 1):
            status = entry.get("status", "ALLOW")
            if status == "BLOCK":
                table_style_commands.append(
                    ("BACKGROUND", (2, idx), (2, idx), colors.HexColor("#ffcccc"))
                )
            elif status == "FLAG":
                table_style_commands.append(
                    ("BACKGROUND", (2, idx), (2, idx), colors.HexColor("#fff3cd"))
                )

        entry_table.setStyle(TableStyle(table_style_commands))
        elements.append(entry_table)

    # --- Hash Chain Verification ---
    elements.append(Spacer(1, 10 * mm))
    elements.append(
        Paragraph("4. Hash Chain Verification", styles["SectionHeader"]))
    elements.append(Paragraph(
        f"<b>Status:</b> {chain_status['details']}",
        styles["BodyText"],
    ))
    elements.append(Paragraph(
        f"<b>Total entries in chain:</b> {chain_status['total_entries']}",
        styles["BodyText"],
    ))
    if not chain_status["valid"]:
        elements.append(Paragraph(
            f"<b>⚠ INTEGRITY BREACH at entry:</b> {chain_status['broken_at']}",
            styles["BodyText"],
        ))

    # --- Disclaimer ---
    elements.append(Spacer(1, 20 * mm))
    elements.append(Paragraph(
        "This report was generated automatically by the AI Compliance Audit System. "
        "All entries are cryptographically hash-chained. Any modification to the underlying "
        "audit log will invalidate the chain and be detectable. This report is intended for "
        "regulatory review under the DPDP Act 2023, RBI FREE-AI Framework, and IRDAI Guidelines.",
        styles["Disclaimer"],
    ))

    doc.build(elements)
    return output_path
