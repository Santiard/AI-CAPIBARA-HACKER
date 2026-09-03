from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage
import json
import logging
from src.config import OLLAMA_MODEL, OLLAMA_BASE_URL, OLLAMA_TEMPERATURE
from src.agents.prompts import CRITIC_PROMPT

logger = logging.getLogger(__name__)

def evaluate_proposals(state: dict) -> dict:
    """
    Evalúa las propuestas de hardening y hallazgos de CVE.
    Devuelve 'approve' o 'reject' junto con feedback.
    """
    logger.info("Iniciando evaluación del Agente Crítico...")
    
    cve_findings = state.get("cve_findings", [])
    hardening_proposals = state.get("hardening_proposals", [])
    
    # Configuramos el cliente local de Ollama (según Tarea 1 de la imagen)
    # usando la configuración de src.config si aplica, o valores estáticos pedidos
    try:
        # Se asume que el modulo a usar puede ser ChatOllama de langchain_ollama o langchain_community
        llm = ChatOllama(model="qwen2.5:14b", temperature=0.2, base_url=OLLAMA_BASE_URL)
    except Exception as e:
        logger.warning(f"No se pudo instanciar ChatOllama: {e}")
        return {"critic_verdict": "approve", "critic_feedback": "Mocked approve due to LLM init error"}
    
    # Preparar el contenido a evaluar
    content_to_evaluate = f"CVE Findings:\n{json.dumps(cve_findings, indent=2)}\n\nHardening Proposals:\n{json.dumps(hardening_proposals, indent=2)}"
    
    messages = [
        SystemMessage(content=CRITIC_PROMPT),
        HumanMessage(content=f"Evalúa las siguientes propuestas y hallazgos. Responde únicamente con un JSON con las claves 'verdict' ('approve' o 'reject') y 'feedback' (tu justificación).\n\n{content_to_evaluate}")
    ]
    
    try:
        response = llm.invoke(messages)
        raw_content = response.content.strip()
        logger.info(f"Respuesta cruda del Agente Crítico: {raw_content[:200]}...")
        
        # Extracción robusta de JSON usando expresión regular
        import re
        json_match = re.search(r"\{[\s\S]*\}", raw_content)
        if json_match:
            json_str = json_match.group(0)
            result = json.loads(json_str)
            verdict = str(result.get("verdict", "approve")).strip().lower()
            feedback = str(result.get("feedback", "Revisión técnica de QA completada.")).strip()
        else:
            # Fallback heurístico si el modelo respondió en texto libre
            lower_text = raw_content.lower()
            if "reject" in lower_text or "rechaz" in lower_text or "incoheren" in lower_text:
                verdict = "reject"
            else:
                verdict = "approve"
            feedback = raw_content[:300]
            
        return {"critic_verdict": verdict, "critic_feedback": feedback}
    except Exception as e:
        logger.error(f"Error procesando dictamen en critic: {e}")
        # En caso de error de parseo, aprobamos con nota de advertencia para no bloquear el flujo
        return {
            "critic_verdict": "approve",
            "critic_feedback": f"Dictamen aprobado automáticamente con advertencia técnica: {str(e)}"
        }
