import logging
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from langchain_core.messages import SystemMessage, HumanMessage, RemoveMessage

from src.agents.state import AgentState
from src.agents.prompts import ORCHESTRATOR_PROMPT, PARSER_PROMPT, INTEL_PROMPT, COMPLIANCE_PROMPT
from src.agents.critic import evaluate_proposals
from src.config import MAX_CONTEXT_TOKENS

logger = logging.getLogger(__name__)

# --- Funciones de Nodos ---

def node_orchestrator(state: AgentState):
    """Nodo 1: Orquestador / Planificador"""
    logger.info("Ejecutando nodo Orquestador")
    # Lógica base del orquestador: inicializar y decidir
    if "raw_scan" not in state or not state["raw_scan"]:
        return {"messages": [SystemMessage(content="Error: No raw_scan provided.")]}
    
    return {"messages": [SystemMessage(content=ORCHESTRATOR_PROMPT)]}

def node_parser(state: AgentState):
    """Nodo 2: Invocación del Parser"""
    logger.info("Ejecutando nodo Parser")
    # Mock de parseo o integración futura
    # Idealmente aquí invoca una tool o un script
    parsed = {"status": "parsed_mock", "services": []}
    return {"parsed_services": parsed}

def node_intel(state: AgentState):
    """Nodo 3: Consulta al RAG de Inteligencia (CVE)"""
    logger.info("Ejecutando nodo Intel")
    # Mock de búsqueda de CVEs
    findings = [{"cve": "CVE-TEST-001", "severity": "HIGH"}]
    return {"cve_findings": findings}

def node_compliance(state: AgentState):
    """Nodo 4: Consulta al RAG de Cumplimiento (Hardening)"""
    logger.info("Ejecutando nodo Compliance")
    # Mock de generación de propuestas
    proposals = [{"recommendation": "Update to latest version."}]
    return {"hardening_proposals": proposals}

def node_critic(state: AgentState):
    """Nodo 5: Evaluación del Crítico / QA"""
    logger.info("Ejecutando nodo Critic")
    result = evaluate_proposals(state)
    return result

def node_final_report(state: AgentState):
    """Nodo 6: Generación del reporte final"""
    logger.info("Ejecutando nodo Final Report")
    report = f"Reporte Final. Estado: Aprobado.\nCVEs: {state.get('cve_findings')}\nHardening: {state.get('hardening_proposals')}"
    return {"final_report": report}


# --- Sliding Window / Context Pruning (Tarea 3) ---

def prune_context(state: AgentState):
    """
    Función que resume o poda mensajes anteriores para no desbordar 
    la ventana de contexto del LLM local.
    """
    messages = state.get("messages", [])
    if not messages:
        return {}
    
    # Pruning simplificado: Si hay demasiados mensajes, nos quedamos con los X últimos.
    # El valor real de MAX_CONTEXT_TOKENS (ej 8192) idealmente debería calcular los tokens reales (tiktoken).
    # Aquí lo limitaremos por cantidad de mensajes a modo de placeholder
    max_messages = 10 # Limite simplificado basado en el requerimiento
    if len(messages) > max_messages:
        # Se remueven los mensajes antiguos excepto el primero (si es el System prompt)
        messages_to_remove = []
        start_idx = 1 if isinstance(messages[0], SystemMessage) else 0
        end_idx = len(messages) - max_messages + 1
        
        for msg in messages[start_idx:end_idx]:
            if msg.id: # Solo podemos remover si tienen ID en langgraph v0.1+
                messages_to_remove.append(RemoveMessage(id=msg.id))
        
        if messages_to_remove:
            return {"messages": messages_to_remove}
    
    return {}

# --- Construcción del Grafo ---

def build_graph():
    """
    Construye el grafo Multiagente de LangGraph (Tarea 4).
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
    
    # 2. Definir punto de entrada
    builder.set_entry_point("Orquestador")
    
    # 3. Definir Transiciones / Edges
    builder.add_edge("Orquestador", "Parser")
    builder.add_edge("Parser", "Intel")
    builder.add_edge("Intel", "Compliance")
    builder.add_edge("Compliance", "Critic")
    
    # Transición condicional del Crítico
    def router_critic(state: AgentState):
        verdict = state.get("critic_verdict", "reject")
        if verdict == "approve":
            return "FinalReport"
        else:
            # Si se rechaza, podemos volver al Compliance para mejorar
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
    
    # 4. Manejo de Human-in-the-Loop (Tarea 5)
    memory = MemorySaver()
    # Interrumpimos antes del FinalReport para que el usuario pueda aprobar (Human-in-the-loop)
    graph = builder.compile(
        checkpointer=memory,
        interrupt_before=["FinalReport"]
    )
    
    return graph

# Exportamos el grafo compilado
agent_graph = build_graph()
