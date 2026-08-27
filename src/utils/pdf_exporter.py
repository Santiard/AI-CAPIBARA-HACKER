"""
Generador de reportes de auditoría en formato PDF descargable.
Utiliza ReportLab para compilar un documento ejecutivo y técnico con tablas,
paletas de colores de severidad y bloques de código de mitigación.
Incluye sanitización para compatibilidad con fuentes estándar.
"""
import os
import re
from typing import Dict, Any, Union
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from src.utils.report_formatter import AuditReportData


def clean_pdf_text(text: str) -> str:
    """
    Sanitiza el texto eliminando emojis no soportados por las fuentes Type1 estándar de PDF.
    """
    if not text:
        return ""
    # Reemplazar emojis comunes por etiquetas legibles
    cleaned = text.replace("🦫", "[AI-CAPIBARA]").replace("📊", "").replace("🔍", "")
    cleaned = cleaned.replace("🛡️", "").replace("🛠️", "").replace("⚖️", "").replace("✅", "[OK]")
    cleaned = cleaned.replace("🔴", "[CRITICAL]").replace("🟠", "[HIGH]").replace("🟡", "[MEDIUM]")
    cleaned = cleaned.replace("🔵", "[LOW]").replace("ℹ️", "[INFO]")
    # Filtrar caracteres no imprimibles o fuera de latin-1
    return cleaned.encode('latin-1', 'replace').decode('latin-1')


def export_report_to_pdf(data: Union[AuditReportData, Dict[str, Any]], output_path: str = "exports/audit_report.pdf") -> str:
    """
    Compila los datos estructurados de auditoría en un archivo PDF formal.
    Retorna la ruta absoluta del archivo generado.
    """
    if isinstance(data, dict):
        report = AuditReportData(**data)
    else:
        report = data

    # Crear directorio si no existe
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=10
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155")
    )

    code_style = ParagraphStyle(
        'CodeBox',
        parent=styles['Code'],
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0f766e"),
        backColor=colors.HexColor("#f0fdfa")
    )

    story = []

    # 1. Título y Metadatos
    story.append(Paragraph(clean_pdf_text("AI-CAPIBARA-HACKER: INFORME DE AUDITORIA DE SEGURIDAD DEFENSIVA"), title_style))
    story.append(Paragraph(clean_pdf_text(f"<b>Generado por:</b> Sistema Multi-Agente &nbsp;|&nbsp; <b>Fecha:</b> {report.scan_date}"), subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

    # Info del Objetivo
    target_info = [
        [Paragraph(clean_pdf_text(f"<b>Objetivo IP:</b> {report.target_ip}"), body_style), Paragraph(clean_pdf_text(f"<b>Hostname:</b> {report.hostname or 'N/A'}"), body_style)],
        [Paragraph(clean_pdf_text(f"<b>Sistema Operativo:</b> {report.os_info}"), body_style), Paragraph(clean_pdf_text(f"<b>Servicios Detectados:</b> {len(report.services_inventory)}"), body_style)]
    ]
    t_info = Table(target_info, colWidths=[260, 270])
    t_info.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_info)
    story.append(Spacer(1, 8))

    # 2. Resumen Ejecutivo
    story.append(Paragraph(clean_pdf_text("1. Resumen Ejecutivo"), h2_style))
    story.append(Paragraph(clean_pdf_text(report.executive_summary), body_style))
    story.append(Spacer(1, 8))

    # 3. Tabla de Inventario
    story.append(Paragraph(clean_pdf_text("2. Inventario de Puertos y Servicios Detectados"), h2_style))
    inv_data = [["Puerto", "Proto", "Servicio", "Producto", "Version", "CPE"]]
    for s in report.services_inventory:
        inv_data.append([
            str(s.get("port", "-")),
            str(s.get("protocol", "tcp")).upper(),
            clean_pdf_text(str(s.get("service", "-"))),
            clean_pdf_text(str(s.get("product", "-"))[:20]),
            clean_pdf_text(str(s.get("version", "-"))[:15]),
            clean_pdf_text(str(s.get("cpe", "-"))[:30])
        ])

    t_inv = Table(inv_data, colWidths=[45, 45, 80, 110, 80, 170])
    t_inv.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (1, -1), 'CENTER'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_inv)
    story.append(Spacer(1, 8))

    # 4. Tabla de Vulnerabilidades
    story.append(Paragraph(clean_pdf_text("3. Vulnerabilidades Correlacionadas (CVEs)"), h2_style))
    if report.vulnerabilities:
        vuln_data = [["CVE ID", "Severidad", "CVSS", "Servicio", "Descripcion / Impacto"]]
        for v in report.vulnerabilities:
            cve_id = clean_pdf_text(str(v.get("cve_id", "-")))
            sev = clean_pdf_text(str(v.get("severity", "UNKNOWN")))
            score = str(v.get("cvss_score", "-"))
            svc = clean_pdf_text(str(v.get("affected_service", "-")))
            desc = clean_pdf_text(str(v.get("description", "-")))
            vuln_data.append([cve_id, sev, score, svc, Paragraph(desc, body_style)])

        t_vuln = Table(vuln_data, colWidths=[90, 65, 45, 110, 220])
        t_vuln.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#dc2626")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (2, -1), 'CENTER'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#fef2f2")]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#fca5a5")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_vuln)
    else:
        story.append(Paragraph(clean_pdf_text("No se encontraron CVEs asociados."), body_style))
    
    story.append(Spacer(1, 8))

    # 5. Remediaciones y Hardening
    story.append(Paragraph(clean_pdf_text("4. Plan de Remediacion & Hardening (CIS)"), h2_style))
    for idx, rem in enumerate(report.remediations, 1):
        rem_block = []
        svc = clean_pdf_text(rem.get("service", "General"))
        title = clean_pdf_text(rem.get("title", f"Mitigacion #{idx}"))
        ref = clean_pdf_text(rem.get("cis_reference", "CIS Standard"))
        steps = clean_pdf_text(rem.get("steps", ""))

        rem_block.append(Paragraph(f"<b>4.{idx} [{svc}] {title}</b> — <font color='#64748b'>{ref}</font>", body_style))
        rem_block.append(Spacer(1, 2))
        rem_block.append(Paragraph(f"<pre>{steps}</pre>", code_style))
        rem_block.append(Spacer(1, 4))
        story.append(KeepTogether(rem_block))

    # 6. Dictamen del Agente Crítico
    story.append(Paragraph(clean_pdf_text("5. Dictamen del Agente Critico / QA"), h2_style))
    critic_box = [[Paragraph(clean_pdf_text(f"<b>Revision de Calidad:</b> {report.critic_verdict}"), body_style)]]
    t_critic = Table(critic_box, colWidths=[530])
    t_critic.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#eff6ff")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#3b82f6")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(t_critic)

    # Construir PDF
    doc.build(story)
    return os.path.abspath(output_path)
