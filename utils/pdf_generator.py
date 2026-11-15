"""Professional PDF investigation report (ReportLab)."""
import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

NAVY, CYAN = colors.HexColor("#0b1220"), colors.HexColor("#0284c7")
LEVEL_COLORS = {"Low Risk": "#16a34a", "Medium Risk": "#d97706", "High Risk": "#ea580c", "Critical Risk": "#dc2626"}


def _t(text, limit=None) -> str:
    """Make text safe for the built-in Helvetica font (latin-1) and for ReportLab markup."""
    text = str(text if text is not None else "").replace("\u20b9", "Rs. ").replace("\u201c", '"').replace("\u201d", '"')
    text = text.replace("\u2019", "'").replace("\u2013", "-").replace("\u2014", "-")
    text = text.encode("latin-1", "replace").decode("latin-1")
    if limit and len(text) > limit:
        text = text[:limit] + " ...[truncated]"
    return escape(text)


def generate_report(result: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=26 * mm, bottomMargin=18 * mm,
                            title=f"PhishTrace Report {result.get('investigation_id', '')}", author="PhishTrace")
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("s", parent=body, fontSize=8, textColor=colors.HexColor("#475569"))
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=CYAN, fontSize=13, spaceBefore=12, spaceAfter=4)
    mono = ParagraphStyle("m", parent=body, fontName="Courier", fontSize=8, leading=10, backColor=colors.HexColor("#f1f5f9"),
                          borderPadding=4)
    level, score = result["risk_level"], result["risk_score"]
    lc = colors.HexColor(LEVEL_COLORS.get(level, "#475569"))

    def chrome(canvas, d):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(NAVY)
        canvas.rect(0, h - 18 * mm, w, 18 * mm, stroke=0, fill=1)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 15)
        canvas.drawString(18 * mm, h - 11.5 * mm, "PhishTrace")
        canvas.setFont("Helvetica", 8.5)
        canvas.setFillColor(colors.HexColor("#7dd3fc"))
        canvas.drawString(52 * mm, h - 11.5 * mm, "Digital Investigation Report")
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(18 * mm, 10 * mm, "Automated assessment - not a guarantee. Verify through official channels.")
        canvas.drawRightString(w - 18 * mm, 10 * mm, f"Page {d.page}")
        canvas.restoreState()

    s = []
    s.append(Paragraph(f"Investigation {_t(result.get('investigation_id', 'UNSAVED'))}", ParagraphStyle(
        "t", parent=ss["Title"], fontSize=18, alignment=0, spaceAfter=6)))
    summary = Table([
        ["Analysis timestamp (UTC)", _t(result["analysis_time"])],
        ["Input type", _t(result["input_type"].upper())],
        ["Classification", _t(result["classification"])],
        ["Risk classification", Paragraph(f'<font color="{LEVEL_COLORS.get(level, "#475569")}"><b>{_t(level)}</b></font>', body)],
        ["Risk score", f"{score} / 100"],
    ], colWidths=[48 * mm, 120 * mm])
    summary.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 9), ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#475569")),
                                 ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                                 ("LINEBEFORE", (0, 3), (0, 3), 3, lc), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    s += [summary, Spacer(1, 4)]
    s.append(Paragraph(_t(result.get("disclaimer", "")), small))

    s.append(Paragraph("Submitted evidence", h2))
    if result.get("is_demo"):
        s.append(Paragraph("DEMONSTRATION DATA - fictional content.", small))
    s.append(Paragraph(_t(result.get("evidence", "(not stored)"), 2500).replace("\n", "<br/>"), mono))

    s.append(Paragraph("Identified indicators", h2))
    ent = result.get("entities", {})
    rows = [["Type", "Values (defanged)"]]
    for k in ("urls", "domains", "ips", "emails", "phones"):
        if ent.get(k):
            vals = [v.replace("http", "hxxp").replace(".", "[.]") if k in ("urls", "domains") else v for v in ent[k][:8]]
            rows.append([k.upper(), Paragraph(_t(", ".join(vals)), small)])
    if len(rows) == 1:
        rows.append(["-", "No URLs, domains, IPs, e-mail addresses or phone numbers extracted."])
    t = Table(rows, colWidths=[28 * mm, 140 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("FONTSIZE", (0, 0), (-1, -1), 8.5), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    s.append(t)

    s.append(Paragraph("Explanation of findings", h2))
    sev_col = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#2563eb", "info": "#64748b"}
    rows = [["Severity", "Indicator / explanation", "Evidence source"]]
    for f in result["findings"]:
        ctx = f"<br/><i>Context: {_t(f['context'], 120)}</i>" if f.get("context") else ""
        rows.append([Paragraph(f'<font color="{sev_col[f["severity"]]}"><b>{f["severity"].upper()}</b></font>', small),
                     Paragraph(f"<b>{_t(f['indicator'])}</b><br/>{_t(f['explanation'], 400)}{ctx}", small),
                     Paragraph(_t(f["source"]), small)])
    if len(rows) == 1:
        rows.append(["-", "No findings recorded.", "-"])
    t = Table(rows, colWidths=[20 * mm, 112 * mm, 36 * mm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("FONTSIZE", (0, 0), (-1, -1), 8.5), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    s.append(t)

    s.append(Paragraph("Recommended actions", h2))
    for r in result["recommendations"]:
        s.append(Paragraph("&bull; " + _t(r), body))
    s.append(Paragraph("Limitations of this analysis", h2))
    for u in result.get("unknowns", []):
        s.append(Paragraph("&bull; " + _t(u), small))
    s += [Spacer(1, 8), HRFlowable(width="100%", color=colors.HexColor("#cbd5e1")),
          Paragraph("Scoring: findings carry weighted points (low 5, medium 12, high 22, critical 35); score = 100 x (1 - e^(-total/55)). "
                    "Bands: 0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical.", small)]
    doc.build(s, onFirstPage=chrome, onLaterPages=chrome)
    return buf.getvalue()
