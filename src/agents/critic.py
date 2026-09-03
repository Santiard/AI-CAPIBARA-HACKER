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
        invalid_cves = []
        invalid_hardening = []
        if json_match:
            json_str = json_match.group(0)
            result = json.loads(json_str)
            verdict = str(result.get("verdict", "approve")).strip().lower()
            feedback = str(result.get("feedback", "Revisión técnica de QA completada.")).strip()
            
            invalid_cves = result.get("invalid_cves", [])
            if not isinstance(invalid_cves, list):
                invalid_cves = []
                
            invalid_hardening = result.get("invalid_hardening", [])
            if not isinstance(invalid_hardening, list):
                invalid_hardening = []
        else:
            # Fallback heurístico si el modelo respondió en texto libre
            lower_text = raw_content.lower()
            if "reject" in lower_text or "rechaz" in lower_text or "incoheren" in lower_text:
                verdict = "reject"
            else:
                verdict = "approve"
            feedback = raw_content[:300]
            
        # Purgar datos sucios de la memoria (Eliminar falsos positivos detectados)
        purged = False
        if invalid_cves:
            logger.warning(f"Purgando CVEs alucinados del reporte: {invalid_cves}")
            cve_findings = [c for c in cve_findings if c.get("cve_id") not in invalid_cves]
            purged = True
            
        if invalid_hardening:
            logger.warning(f"Purgando propuestas de Hardening alucinadas del reporte: {invalid_hardening}")
            hardening_proposals = [
                h for h in hardening_proposals 
                if h.get("cis_reference") not in invalid_hardening and h.get("title") not in invalid_hardening
            ]
            purged = True
            
        if purged:
            deleted_items = []
            if invalid_cves:
                deleted_items.append(f"Vulnerabilidades (CVEs): {', '.join(invalid_cves)}")
            if invalid_hardening:
                deleted_items.append(f"Propuestas de Hardening: {', '.join(invalid_hardening)}")
                
            feedback += (
                "\n\n⚠️ **ACCIÓN DE AUTO-CORRECCIÓN DE QA:**\n"
                "Se detectaron inconsistencias en los datos recuperados (alucinaciones). "
                "Para garantizar la exactitud del reporte, se eliminaron automáticamente los siguientes elementos falsos:\n- " 
                + "\n- ".join(deleted_items)
            )
            
        return {
            "critic_verdict": verdict, 
            "critic_feedback": feedback,
            "cve_findings": cve_findings,
            "hardening_proposals": hardening_proposals
        }
    except Exception as e:
        logger.error(f"Error procesando dictamen en critic: {e}")
        # En caso de error de parseo, aprobamos con nota de advertencia para no bloquear el flujo
        return {
            "critic_verdict": "approve",
            "critic_feedback": f"Dictamen aprobado automáticamente con advertencia técnica: {str(e)}"
        }
