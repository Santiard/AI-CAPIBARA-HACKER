"""
Formateador de reportes de auditoría en formato Markdown.
Estructura hallazgos, inventario, análisis de severidad CVSS,
recomendaciones de hardening CIS y notas del Agente Crítico.
"""
from datetime import datetime
from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field


class AuditReportData(BaseModel):
    target_ip: str = Field(default="127.0.0.1", description="IP del objetivo auditado")
    hostname: Optional[str] = Field(default="srv-target.local", description="Nombre del host")
    os_info: Optional[str] = Field(default="Linux Ubuntu / Debian", description="Sistema Operativo detectado")
    scan_date: Optional[str] = Field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    executive_summary: str = Field(description="Resumen ejecutivo para la dirección técnica")
    services_inventory: List[Dict[str, Any]] = Field(default_factory=list, description="Lista de puertos y servicios")
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list, description="Vulnerabilidades CVE identificadas")
    remediations: List[Dict[str, Any]] = Field(default_factory=list, description="Guías de mitigación y hardening")
    critic_verdict: Optional[str] = Field(default="Auditoría validada sin inconsistencias evidentes.", description="Dictamen del Agente Crítico")


def format_markdown_report(data: Union[AuditReportData, Dict[str, Any]]) -> str:
    """
    Genera un informe completo y profesional en formato Markdown a partir de los datos de auditoría.
    """
    if isinstance(data, dict):
        report = AuditReportData(**data)
    else:
        report = data

    md_lines = []
    
    # Encabezado
    md_lines.append("# 🦫 INFORME TÉCNICO DE AUDITORÍA DE SEGURIDAD")
    md_lines.append("### Generado por Sistema Multi-Agente AI-CAPIBARA-HACKER")
    md_lines.append(f"**Fecha y Hora de Auditoría:** `{report.scan_date}`  ")
    md_lines.append(f"**Objetivo:** `{report.target_ip}` (`{report.hostname or 'N/A'}`)  ")
    md_lines.append(f"**Sistema Operativo:** `{report.os_info}`  ")
    md_lines.append("\n---\n")

    # Resumen Ejecutivo
    md_lines.append("## 1. 📊 Resumen Ejecutivo")
    md_lines.append(report.executive_summary.strip())
    md_lines.append("\n---\n")

    # Inventario de Servicios
    md_lines.append("## 2. 🔍 Inventario de Activos y Superficie de Ataque")
    md_lines.append("| Puerto | Protocolo | Servicio | Producto | Versión | CPE Identificado |")
    md_lines.append("| :---: | :---: | :--- | :--- | :--- | :--- |")
    
    if report.services_inventory:
        for s in report.services_inventory:
            port = s.get("port", "N/A")
            proto = s.get("protocol", "tcp")
            service = s.get("service", "unknown")
            product = s.get("product", "-")
            version = s.get("version", "-")
            cpe = s.get("cpe", "-")
            md_lines.append(f"| `{port}` | {proto.upper()} | **{service}** | {product} | {version} | `{cpe}` |")
    else:
        md_lines.append("| - | - | Sin servicios abiertos detectados | - | - | - |")
    
    md_lines.append("\n---\n")

    # Matriz de Vulnerabilidades
    md_lines.append("## 3. 🛡️ Vulnerabilidades Correlacionadas (CVEs & CVSS)")
    if report.vulnerabilities:
        md_lines.append("| CVE ID | Severidad | CVSS v3 | Servicio Afectado | Resumen del Fallo |")
        md_lines.append("| :--- | :---: | :---: | :--- | :--- |")
        for v in report.vulnerabilities:
            cve = v.get("cve_id", "N/A")
            sev = v.get("severity", "UNKNOWN")
            score = v.get("cvss_score", 0.0)
            svc = v.get("affected_service", "General")
            desc = v.get("description", "Sin descripción disponible.")
            
            badge = "🔴" if sev == "CRITICAL" else ("🟠" if sev == "HIGH" else ("🟡" if sev == "MEDIUM" else "🔵"))
            md_lines.append(f"| **{cve}** | {badge} {sev} | `{score}` | `{svc}` | {desc} |")

        # Desglose interpretado por el Agente de Inteligencia
        md_lines.append("\n### 🔍 Análisis Detallado e Interpretación de Riesgos por el Agente Intel\n")
        for idx, v in enumerate(report.vulnerabilities, 1):
            cve = v.get("cve_id", "N/A")
            sev = v.get("severity", "UNKNOWN")
            score = v.get("cvss_score", 0.0)
            svc = v.get("affected_service", "General")
            desc = v.get("description", "Sin descripción disponible.")
            os_beh = v.get("os_behavior", "El servicio escucha localmente en el puerto indicado.")
            risk_imp = v.get("risk_impact", "Representa un vector potencial de acceso no autorizado.")
            badge = "🔴" if sev == "CRITICAL" else ("🟠" if sev == "HIGH" else ("🟡" if sev == "MEDIUM" else "🔵"))
            
            md_lines.append(f"#### 3.{idx} [{cve}] {svc} ({badge} {sev} - CVSS {score})")
            md_lines.append(f"- **¿Qué es esta vulnerabilidad?** {desc}")
            md_lines.append(f"- **Comportamiento en tu Sistema Operativo:** {os_beh}")
            md_lines.append(f"- **¿Por qué es un riesgo?:** {risk_imp}\n")
    else:
        md_lines.append("✅ *No se identificaron CVEs conocidos asociados a las versiones detectadas.*")

    md_lines.append("\n---\n")

    # Matriz de Remediación y Hardening
    md_lines.append("## 4. 🛠️ Plan de Remediación y Endurecimiento (CIS Benchmarks)")
    if report.remediations:
        for idx, rem in enumerate(report.remediations, 1):
            service = rem.get("service", "General")
            title = rem.get("title", f"Medida de Hardening #{idx}")
            steps = rem.get("steps", "Consultar documentación oficial del fabricante.")
            ref = rem.get("cis_reference", "CIS Baseline Recommendation")

            md_lines.append(f"### 4.{idx} [{service}] {title}")
            md_lines.append(f"> **Referencia de Estándar:** `{ref}`\n")
            md_lines.append("**Acciones recomendadas de configuración / comandos:**")
            md_lines.append(f"```bash\n{steps.strip()}\n```\n")
    else:
        md_lines.append("ℹ️ *No se requieren medidas de remediación urgentes.*")

    md_lines.append("\n---\n")

    # Dictamen del Agente Crítico
    md_lines.append("## 5. ⚖️ Dictamen de Validación (Agente Crítico / QA)")
    md_lines.append(f"> [!IMPORTANT]\n> **Revisión de Calidad & Falsos Positivos:**\n> {report.critic_verdict}\n")
    
    md_lines.append("\n---\n")
    md_lines.append("*Informe generado con fines de evaluación técnica y cumplimiento defensivo.*")

    return "\n".join(md_lines)


def generate_sample_report_data() -> Dict[str, Any]:
    """
    Genera datos de reporte simulados para pruebas y renderizado inicial.
    """
    return {
        "target_ip": "192.168.1.50",
        "hostname": "srv-corp-production.local",
        "os_info": "Linux Ubuntu 20.04 LTS (Kernel 5.4)",
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "executive_summary": (
            "Se ejecutó una auditoría perimetral sobre el activo de producción. "
            "Se detectaron 5 servicios expuestos. Se identificó una vulnerabilidad CRÍTICA "
            "en el servicio FTP (vsftpd 2.3.4 con backdoor conocido) y configuraciones desactualizadas "
            "en OpenSSH y Apache. Se recomienda el aislamiento inmediato del puerto 21 y la actualización de paquetes."
        ),
        "services_inventory": [
            {"port": 21, "protocol": "tcp", "service": "ftp", "product": "vsftpd", "version": "2.3.4", "cpe": "cpe:/a:vsftpd:vsftpd:2.3.4"},
            {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "7.4p1", "cpe": "cpe:/a:openbsd:openssh:7.4p1"},
            {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd", "version": "2.4.29", "cpe": "cpe:/a:apache:http_server:2.4.29"},
            {"port": 3306, "protocol": "tcp", "service": "mysql", "product": "MySQL", "version": "5.7.33", "cpe": "cpe:/a:mysql:mysql:5.7.33"},
            {"port": 8080, "protocol": "tcp", "service": "http", "product": "Apache Tomcat", "version": "9.0.30", "cpe": "cpe:/a:apache:tomcat:9.0.30"}
        ],
        "vulnerabilities": [
            {
                "cve_id": "CVE-2011-2523",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "affected_service": "vsftpd 2.3.4 (Puerto 21)",
                "description": "Vulnerabilidad de Backdoor que permite ejecución remota de comandos no autenticada con privilegios de root."
            },
            {
                "cve_id": "CVE-2018-15473",
                "severity": "MEDIUM",
                "cvss_score": 5.3,
                "affected_service": "OpenSSH 7.4p1 (Puerto 22)",
                "description": "Enumeración de usuarios del sistema mediante peticiones de autenticación malformadas."
            },
            {
                "cve_id": "CVE-2021-41773",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "affected_service": "Apache httpd 2.4.29 (Puerto 80)",
                "description": "Path traversal y potencial ejecución remota de código en versiones desactualizadas de Apache httpd."
            }
        ],
        "remediations": [
            {
                "service": "vsftpd (FTP)",
                "title": "Deshabilitar o Reemplazar Servicio FTP Obsoleto",
                "cis_reference": "CIS Linux Benchmark 2.1.1 (Ensure FTP Server is not enabled)",
                "steps": "sudo systemctl stop vsftpd\nsudo systemctl disable vsftpd\nsudo ufw deny 21/tcp"
            },
            {
                "service": "OpenSSH",
                "title": "Hardening de Configuración SSH",
                "cis_reference": "CIS Linux Benchmark 5.2.4 (SSH Protocol and Ciphers)",
                "steps": "# Editar /etc/ssh/sshd_config\nPermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\n# Reiniciar servicio\nsudo systemctl restart sshd"
            },
            {
                "service": "Apache httpd",
                "title": "Actualización de Paquetes y Ocultación de Banners",
                "cis_reference": "CIS Apache HTTP Server 2.4 Benchmark 1.1",
                "steps": "sudo apt update && sudo apt install --only-upgrade apache2\n# En security.conf:\nServerTokens Prod\nServerSignature Off"
            }
        ],
        "critic_verdict": (
            "El Agente Crítico revisó los hallazgos: Las 3 vulnerabilidades coinciden con las versiones exactas reportadas. "
            "Las medidas de mitigación recomendadas son no destructivas y no comprometen la base de datos principal MySQL (puerto 3306). "
            "Se aprueba la emisión del reporte para el auditor humano."
        )
    }
