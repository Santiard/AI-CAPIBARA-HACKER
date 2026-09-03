import logging
import json
from datetime import datetime
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from langchain_core.messages import SystemMessage, HumanMessage, RemoveMessage

from src.agents.state import AgentState
from src.agents.prompts import (
    ORCHESTRATOR_PROMPT,
    PARSER_PROMPT,
    INTEL_PROMPT,
    COMPLIANCE_PROMPT
)
from src.agents.critic import evaluate_proposals
from src.agents.interpreter import interpret_vulnerability
from src.tools.nmap_parser import parse_nmap_xml, generate_mock_scan
from src.tools.host_inspector import run_active_host_diagnostics
from src.rag.retriever import SecurityRetriever
from src.utils.report_formatter import AuditReportData, format_markdown_report
from src.utils.pdf_exporter import export_report_to_pdf
from src.config import MAX_CONTEXT_TOKENS

logger = logging.getLogger("ai_capibara.agents.graph")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# Instancia compartida del retriever RAG
_retriever = SecurityRetriever()


# --- Funciones de Nodos ---

def node_orchestrator(state: AgentState):
    """
    Nodo 1: Orquestador / Planificador
    Determina el modo de auditoría (pasivo o activo), valida permisos y prepara el flujo.
    """
    mode = state.get("audit_mode", "passive")
    logger.info(f"🧭 Orquestador iniciando en Modo: {mode.upper()}")
    
    if mode == "active":
        if not state.get("human_approval_granted", False):
            msg = "Aviso: Modo Activo requiere autorización explícita del usuario para inspección local."
        else:
            msg = "Autorización concedida. Iniciando descubrimiento de variables del entorno y puertos locales."
    else:
        raw_scan = state.get("raw_scan", "")
        if not raw_scan:
            msg = "Modo Pasivo: No se detectó archivo de escaneo previo, se usará escaneo de prueba (sample_scan.xml)."
        else:
            msg = "Modo Pasivo: Procesando escaneo de red provisto por el usuario."
            
    return {
        "messages": [
            SystemMessage(content=ORCHESTRATOR_PROMPT),
            SystemMessage(content=f"[Orquestador Status]: {msg}")
        ]
    }


def node_parser(state: AgentState):
    """
    Nodo 2: Invocación del Parser / Host Profiler
    - En modo activo: Ejecuta descubrimiento del host anfitrión y puertos locales en escucha.
    - En modo pasivo: Parsea el archivo XML/JSON de Nmap o carga el escaneo de prueba.
    """
    mode = state.get("audit_mode", "passive")
    logger.info(f"🔍 Ejecutando nodo Parser/Profiler en Modo: {mode.upper()}")
    
    if mode == "active":
        # Ejecución activa segura sobre el PC anfitrión
        diag_bundle = run_active_host_diagnostics()
        return {
            "host_profile": diag_bundle.get("host_profile", {}),
            "parsed_services": diag_bundle,
            "raw_scan": diag_bundle.get("raw_summary", "Diagnóstico activo del host.")
        }
    else:
        # Modo pasivo: parsear XML de Nmap
        raw_scan = state.get("raw_scan", "")
        try:
            if raw_scan and "<nmaprun" in raw_scan:
                report = parse_nmap_xml(raw_scan)
                parsed_data = report.model_dump()
            else:
                # Cargar scan simulado / prueba
                report = generate_mock_scan()
                parsed_data = report.model_dump()
        except Exception as e:
            logger.warning(f"Fallo al parsear XML ({e}), usando datos de prueba de respaldo.")
            report = generate_mock_scan()
            parsed_data = report.model_dump()
            
        return {
            "parsed_services": parsed_data,
            "host_profile": {
                "hostname": parsed_data.get("hostname", "srv-target.local"),
                "os_name": parsed_data.get("os_match", "Linux"),
                "ip_addresses": [parsed_data.get("target_ip", "127.0.0.1")]
            }
        }


def node_intel(state: AgentState):
    """
    Nodo 3: Consulta al RAG de Inteligencia (CVEs)
    Toma los servicios detectados y consulta la base de vectores ChromaDB.
    """
    logger.info("🛡️ Ejecutando nodo Intel (Consulta RAG de CVEs)")
    parsed = state.get("parsed_services", {})
    services = parsed.get("services", [])
    host_prof = state.get("host_profile", {})
    host_os = f"{host_prof.get('os_name', 'Windows')} {host_prof.get('os_release', '')}".strip() or "Windows 11"
    
    cve_findings = []
    seen_cves = set()
    seen_service_signatures = set()
    
    for s in services:
        svc_name = s.get("service", "")
        version = s.get("version", "")
        product = s.get("product", svc_name)
        port = s.get("port", 0)
        
        # Evitar consultas RAG duplicadas para el mismo binario/servicio
        sig = (svc_name.lower(), (version or "").lower())
        if sig in seen_service_signatures:
            continue
        seen_service_signatures.add(sig)
        
        # Búsqueda híbrida en la colección de CVEs
        try:
            ver_arg = version if (version and version != "local_active") else None
            rag_results = _retriever.query_vulnerabilities(
                service_name=svc_name,
                version=ver_arg,
                top_k=2
            )
            for res in rag_results:
                # Solo aceptar resultados con suficiente similitud o coincidencia de servicio
                similarity = res.get("similarity_score", 1.0)
                if similarity < 0.40 and not (svc_name in res.get("content", "").lower()):
                    continue

                cve_id = res.get("cve_id") or res.get("metadata", {}).get("cve_id", "CVE-GENERAL")
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                
                score = float(res.get("cvss_score") or res.get("metadata", {}).get("cvss_score", 6.5))
                severity = res.get("severity") or res.get("metadata", {}).get("severity", "MEDIUM")
                raw_content = res.get("content") or res.get("summary") or res.get("text", "")
                
                # Invocamos al Agente Intérprete para contextualizar en el OS del usuario
                interp = interpret_vulnerability(
                    cve_id=cve_id,
                    service_name=svc_name,
                    port=port,
                    raw_content=raw_content,
                    host_os=host_os,
                    product=product
                )
                
                cve_findings.append({
                    "cve": cve_id,
                    "cve_id": cve_id,
                    "severity": severity,
                    "cvss_score": score,
                    "affected_service": f"{product or svc_name} (Puerto {port})",
                    "description": interp.get("summary", ""),
                    "os_behavior": interp.get("os_behavior", ""),
                    "risk_impact": interp.get("risk_impact", "")
                })
        except Exception as e:
            logger.error(f"Error consultando RAG CVE para servicio {svc_name}: {e}")
            
    # Fallback si no hubo matches directos
    if not cve_findings:
        cve_findings.append({
            "cve": "CVE-INFO-BASELINE",
            "cve_id": "CVE-INFO-BASELINE",
            "severity": "LOW",
            "cvss_score": 3.0,
            "affected_service": "Servicios Locales del Sistema",
            "description": "Los puertos locales inspeccionados corresponden a servicios estándar del sistema sin vulnerabilidades críticas conocidas expuestas a la red.",
            "os_behavior": f"Servicios internos de {host_os} operando en sockets locales protegidos por el firewall perimetral del sistema operativo.",
            "risk_impact": "Riesgo bajo bajo la configuración actual. Se recomienda mantener el filtrado de red activo para evitar accesos remotos no autorizados."
        })
        
    return {"cve_findings": cve_findings}



def node_compliance(state: AgentState):
    """
    Nodo 4: Consulta al RAG de Cumplimiento (Hardening & CIS Benchmarks)
    Busca guías de endurecimiento en ChromaDB para mitigar los hallazgos.
    """
    logger.info("📋 Ejecutando nodo Compliance (Consulta RAG de Hardening CIS)")
    parsed = state.get("parsed_services", {})
    services = parsed.get("services", [])
    host_prof = state.get("host_profile", {})
    os_name = host_prof.get("os_name", "linux").lower()
    
    proposals = []
    seen_rules = set()
    seen_compliance_signatures = set()
    
    for s in services:
        svc_name = s.get("service", "")
        sig = svc_name.lower()
        if sig in seen_compliance_signatures:
            continue
        seen_compliance_signatures.add(sig)
        
        try:
            benchmarks = _retriever.query_hardening_benchmarks(
                service_name=svc_name,
                os_type=os_name,
                top_k=2
            )
            for bm in benchmarks:
                rule_id = bm.get("rule_id") or bm.get("metadata", {}).get("rule_id", "CIS-RULE")
                if rule_id in seen_rules:
                    continue
                seen_rules.add(rule_id)
                
                title = bm.get("title") or f"Ajuste de seguridad para {svc_name}"
                steps = bm.get("remediation") or bm.get("text", "")[:250]
                
                proposals.append({
                    "service": svc_name.upper(),
                    "title": title,
                    "cis_reference": rule_id,
                    "steps": steps or f"Aplicar restricciones de red en el puerto {s.get('port')}.",
                    "recommendation": f"[{rule_id}] {title}"
                })
        except Exception as e:
            logger.error(f"Error consultando RAG CIS para servicio {svc_name}: {e}")
            
    if not proposals:
        proposals.append({
            "service": "GENERAL",
            "title": "Configuración de Firewall Perimetral",
            "cis_reference": "CIS Network Baseline 1.1",
            "steps": "sudo ufw default deny incoming\nsudo ufw default allow outgoing",
            "recommendation": "Habilitar filtrado de paquetes para cerrar puertos en desuso."
        })
        
    return {"hardening_proposals": proposals}


def node_critic(state: AgentState):
    """
    Nodo 5: Evaluación del Crítico / QA
    Invoca a qwen2.5:14b para evaluar coherencia, mitigar alucinaciones y validar recomendaciones.
    """
    logger.info("⚖️ Ejecutando nodo Critic (Validación QA del LLM)")
    result = evaluate_proposals(state)
    retries = state.get("critic_retry_count", 0) + 1
    result["critic_retry_count"] = retries
    return result



def node_final_report(state: AgentState):
    """
    Nodo 6: Generación y exportación del informe final (Markdown + PDF descargable)
    """
    logger.info("📄 Ejecutando nodo Final Report")
    parsed = state.get("parsed_services", {})
    host_prof = state.get("host_profile", {})
    
    target_ip = parsed.get("target_ip") or (host_prof.get("ip_addresses", ["127.0.0.1"])[0])
    hostname = parsed.get("hostname") or host_prof.get("hostname", "local-pc")
    os_info = parsed.get("os_match") or f"{host_prof.get('os_name', '')} {host_prof.get('os_release', '')}"
    
    mode_str = "Diagnóstico Activo del PC Anfitrión" if state.get("audit_mode") == "active" else "Análisis Pasivo de Escaneo Nmap"
    
    exec_summary = (
        f"Auditoría defensiva completada mediante {mode_str}. "
        f"Se identificaron {len(parsed.get('services', []))} servicios en escucha. "
        f"Se correlacionaron {len(state.get('cve_findings', []))} vectores de riesgo CVE "
        f"y se estructuraron {len(state.get('hardening_proposals', []))} directivas de endurecimiento CIS. "
        f"Dictamen del Agente Crítico: {state.get('critic_verdict', 'Aprobado')}."
    )
    
    report_data = AuditReportData(
        target_ip=target_ip,
        hostname=hostname,
        os_info=os_info,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        executive_summary=exec_summary,
        services_inventory=parsed.get("services", []),
        vulnerabilities=state.get("cve_findings", []),
        remediations=state.get("hardening_proposals", []),
        critic_verdict=f"{state.get('critic_verdict', 'approve').upper()}: {state.get('critic_feedback', 'Revisión técnica conforme.')}"
    )
    
    # Generar Markdown
    md_content = format_markdown_report(report_data)
    
    # Generar PDF exportable
    try:
        export_report_to_pdf(report_data, output_path="exports/audit_report.pdf")
        logger.info("PDF de auditoría exportado exitosamente en exports/audit_report.pdf")
    except Exception as e:
        logger.error(f"Error generando PDF final: {e}")
        
    return {"final_report": md_content}


# --- Sliding Window / Context Pruning ---

def prune_context(state: AgentState):
    """
    Función de Sliding Window: Poda o compacta mensajes históricos para no
    saturar la ventana de contexto del LLM local, preservando directivas clave.
    """
    messages = state.get("messages", [])
    if not messages:
        return {}
    
    max_messages = 8
    if len(messages) > max_messages:
        messages_to_remove = []
        start_idx = 1 if isinstance(messages[0], SystemMessage) else 0
        end_idx = len(messages) - max_messages + 1
        
        for msg in messages[start_idx:end_idx]:
            if hasattr(msg, "id") and msg.id:
                messages_to_remove.append(RemoveMessage(id=msg.id))
        
        if messages_to_remove:
            logger.info(f"Sliding Window: Podando {len(messages_to_remove)} mensajes del historial de contexto.")
            return {"messages": messages_to_remove}
    
    return {}


# --- Construcción del Grafo Multiagente ---

def build_graph():
    """
    Construye el grafo Multiagente de LangGraph con soporte dual pasivo/activo,
    evaluación del Crítico y Human-in-the-Loop.
    """
    builder = StateGraph(AgentState)
    
    # 1. Agregar Nodos
    builder.add_node("Orquestador", node_orchestrator)
    builder.add_node("Parser", node_parser)
    builder.add_node("Intel", node_intel)
    builder.add_node("Compliance", node_compliance)
    builder.add_node("Critic", node_critic)
    builder.add_node("FinalReport", node_final_report)
    builder.add_node("PruneContext", prune_context)
    
    # 2. Punto de Entrada
    builder.set_entry_point("Orquestador")
    
    # 3. Edges y Flujo
    builder.add_edge("Orquestador", "Parser")
    builder.add_edge("Parser", "Intel")
    builder.add_edge("Intel", "Compliance")
    builder.add_edge("Compliance", "Critic")
    
    def router_critic(state: AgentState):
        verdict = state.get("critic_verdict", "reject").lower()
        retries = state.get("critic_retry_count", 0)
        
        # Si fue aprobado o ya se realizó un reintento de ajuste, avanzar al reporte
        if verdict == "approve" or retries >= 1:
            logger.info(f"✅ Router Critic: Avanzando a FinalReport (veredicto='{verdict}', ciclos={retries})")
            return "FinalReport"
        else:
            logger.warning(f"⚠️ Router Critic: Rechazado ('{verdict}'). Reintentando Compliance (ciclo {retries}/1)...")
            return "Compliance"
            
    builder.add_conditional_edges(
        "Critic",
        router_critic,
        {
            "FinalReport": "FinalReport",
            "Compliance": "Compliance"
        }
    )
    
    builder.add_edge("FinalReport", "PruneContext")
    builder.add_edge("PruneContext", END)
    
    # 4. Checkpointer y Human-in-the-Loop
    memory = MemorySaver()
    graph = builder.compile(
        checkpointer=memory,
        interrupt_before=["FinalReport"]
    )
    
    return graph


# Exportar grafo compilado
agent_graph = build_graph()

