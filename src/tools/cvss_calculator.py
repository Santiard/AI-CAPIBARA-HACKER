"""
Herramienta de cálculo y clasificación de severidad CVSS v3.1.
Permite evaluar riesgos, clasificar vulnerabilidades y priorizar acciones de mitigación.
Incluye decorador @tool de LangChain.
"""
import json
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from langchain_core.tools import tool


class VulnerabilityScore(BaseModel):
    cve_id: str = Field(description="Identificador CVE (ej. CVE-2021-44228)")
    cvss_score: float = Field(description="Puntuación base CVSS (0.0 a 10.0)")
    severity: str = Field(description="Categoría de severidad: CRITICAL, HIGH, MEDIUM, LOW, NONE")
    vector_string: Optional[str] = Field(default=None, description="Vector CVSS v3.1")
    impact_level: str = Field(description="Nivel de urgencia recomendado para el parche/mitigación")
    description: Optional[str] = Field(default=None, description="Resumen del impacto")


def get_severity_label(score: float) -> str:
    """
    Determina la severidad oficial según el estándar CVSS v3.1.
    """
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    else:
        return "NONE"


def get_impact_recommendation(severity: str) -> str:
    """
    Devuelve la prioridad de remediación según la severidad.
    """
    recommendations = {
        "CRITICAL": "Remediación Inmediata (0-24 horas). Explotación remota activa posible.",
        "HIGH": "Remediación Urgente (1-3 días). Parchear o aplicar mitigación perimetral.",
        "MEDIUM": "Remediación Programada (1-2 semanas). Revisar en el siguiente ciclo de mantenimiento.",
        "LOW": "Monitoreo / Endurecimiento general de línea base.",
        "NONE": "Informativo / Sin impacto directo comprobado."
    }
    return recommendations.get(severity, "Evaluar según contexto del activo.")


def evaluate_vulnerability(cve_id: str, cvss_score: float, description: str = "", vector: str = None) -> VulnerabilityScore:
    """
    Evalúa una vulnerabilidad individual y retorna un VulnerabilityScore.
    """
    severity = get_severity_label(cvss_score)
    impact_level = get_impact_recommendation(severity)
    return VulnerabilityScore(
        cve_id=cve_id.upper().strip(),
        cvss_score=cvss_score,
        severity=severity,
        vector_string=vector,
        impact_level=impact_level,
        description=description
    )


@tool
def cvss_evaluator_tool(cves_json_input: str) -> str:
    """
    Herramienta para el agente: Evalúa y clasifica una lista de vulnerabilidades según su puntuación CVSS v3.
    Input esperado: Un JSON con una lista de objetos [{"cve_id": "CVE-2011-2523", "cvss_score": 9.8, "description": "..."}]
    Retorna la lista ordenada de mayor a menor severidad con niveles de urgencia.
    """
    try:
        data = json.loads(cves_json_input)
        if isinstance(data, dict):
            cves = data.get("vulnerabilities", [data])
        elif isinstance(data, list):
            cves = data
        else:
            return json.dumps({"error": "Formato inválido. Debe ser una lista o dict con vulnerabilidades."})

        scored_list: List[VulnerabilityScore] = []
        for item in cves:
            cve_id = item.get("cve_id", "CVE-UNKNOWN")
            score = float(item.get("cvss_score", item.get("cvss", 5.0)))
            desc = item.get("description", "")
            vector = item.get("vector_string", None)
            scored_list.append(evaluate_vulnerability(cve_id, score, desc, vector))

        # Ordenar de mayor severidad a menor
        scored_list.sort(key=lambda x: x.cvss_score, reverse=True)

        return json.dumps([item.model_dump() for item in scored_list], indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error evaluando métricas CVSS: {str(e)}"})
