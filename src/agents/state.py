from typing import TypedDict, Annotated, Sequence
import operator
from langchain_core.messages import BaseMessage

class AgentState(TypedDict):
    """
    Estado global del grafo multiagente.
    Soporta modo pasivo (archivos Nmap) y modo activo (diagnóstico local del host).
    """
    audit_mode: str  # 'passive' o 'active'
    host_profile: dict  # Variables del entorno descubiertas (OS, IPs, arch)
    raw_scan: str  # Contenido del escaneo o resumen del diagnóstico
    parsed_services: dict  # Inventario normalizado de servicios y puertos
    cve_findings: list[dict]  # Hallazgos de vulnerabilidades recuperados vía RAG
    hardening_proposals: list[dict]  # Medidas de mitigación CIS recuperadas vía RAG
    critic_verdict: str  # Dictamen del agente crítico ('approve' o 'reject')
    critic_feedback: str  # Justificación del crítico
    critic_retry_count: int  # Contador de reintentos para evitar bucles infinitos
    final_report: str  # Reporte Markdown consolidado
    human_approval_granted: bool  # Flag de autorización previa en Human-in-the-loop
    # Usamos Annotated y operator.add para que los mensajes se vayan sumando a la lista
    messages: Annotated[Sequence[BaseMessage], operator.add]
