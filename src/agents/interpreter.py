"""
Agente Intérprete y Explicador de Vulnerabilidades (Intel Explainer).
Toma los hallazgos técnicos recuperados de ChromaDB y genera explicaciones claras
en tres dimensiones clave:
1. ¿Qué es esta vulnerabilidad?
2. Comportamiento en el sistema operativo y versiones del usuario.
3. Por qué es un riesgo y qué consecuencias reales tiene.
"""
import json
import logging
import re
from typing import Dict, Any, Optional
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage
from src.config import OLLAMA_BASE_URL, OLLAMA_MODEL

logger = logging.getLogger("ai_capibara.agents.interpreter")

INTERPRETER_SYSTEM_PROMPT = """Eres el Agente Experto en Interpretación y Análisis de Vulnerabilidades de AI-CAPIBARA-HACKER.
Tu función es analizar hallazgos técnicos de ciberseguridad y traducirlos a un lenguaje claro, profesional y comprensible para cualquier usuario, explicando cómo interactúa la vulnerabilidad con su entorno específico (Sistema Operativo, versión y puerto).

Para cada vulnerabilidad debes responder estrictamente en formato JSON con estas 3 claves:
{
  "summary": "Explicación clara y sin tecnicismos oscuros de qué es esta vulnerabilidad y qué fallo ocurre.",
  "os_behavior": "Cómo se comporta o interactúa con el Sistema Operativo del usuario, si este puerto/servicio está expuesto en red o localmente y qué condiciones requiere.",
  "risk_impact": "Por qué es un riesgo real (ej. ejecución remota de comandos, robo de credenciales, compromiso de datos o caída del servicio)."
}
"""

def interpret_vulnerability(
    cve_id: str,
    service_name: str,
    port: int,
    raw_content: str,
    host_os: str = "Windows 11",
    product: Optional[str] = None
) -> Dict[str, str]:
    """
    Invoca al LLM local (qwen2.5:14b) para interpretar y contextualizar la vulnerabilidad en el OS del usuario.
    """
    prompt_user = f"""
Por favor interpreta la siguiente vulnerabilidad detectada:
- Identificador: {cve_id}
- Servicio / Proceso: {product or service_name} (Puerto TCP {port})
- Sistema Operativo del Host: {host_os}
- Información Técnica de la Base de Conocimiento (RAG):
{raw_content[:800]}

Genera la explicación contextualizada en formato JSON con 'summary', 'os_behavior' y 'risk_impact'.
"""
    try:
        llm = ChatOllama(model=OLLAMA_MODEL, temperature=0.1, base_url=OLLAMA_BASE_URL)
        response = llm.invoke([
            SystemMessage(content=INTERPRETER_SYSTEM_PROMPT),
            HumanMessage(content=prompt_user)
        ])
        content = response.content.strip()
        
        match = re.search(r"\{[\s\S]*\}", content)
        if match:
            parsed = json.loads(match.group(0))
            sum_val = str(parsed.get("summary", "")).strip()
            os_val = str(parsed.get("os_behavior", "")).strip()
            risk_val = str(parsed.get("risk_impact", "")).strip()
            if sum_val:
                return {
                    "summary": sum_val,
                    "os_behavior": os_val or f"Interacción en {host_os} sobre el puerto {port}.",
                    "risk_impact": risk_val or "Impacto potencial en la seguridad del sistema."
                }
    except Exception as e:
        logger.warning(f"Fallo al invocar LLM para interpretar {cve_id}: {e}")

    # Fallback heurístico inteligente si el LLM tarda o falla
    clean_desc = raw_content.replace("\n", " ").strip()
    if len(clean_desc) > 220:
        clean_desc = clean_desc[:220] + "..."
    return {
        "summary": clean_desc or f"Fallo de seguridad identificado en {service_name} registrado bajo el código {cve_id}.",
        "os_behavior": f"El servicio se encuentra activo en el puerto local {port} bajo {host_os}. Si el socket escucha en 0.0.0.0, es accesible por otros equipos de la red local.",
        "risk_impact": f"Permite a un atacante en la red aprovechar la debilidad en {service_name} para degradar la integridad o confidencialidad del sistema."
    }
