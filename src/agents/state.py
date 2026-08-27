from typing import TypedDict, Annotated, Sequence
import operator
from langchain_core.messages import BaseMessage

class AgentState(TypedDict):
    """
    Estado global del grafo multiagente.
    """
    raw_scan: str
    parsed_services: dict
    cve_findings: list[dict]
    hardening_proposals: list[dict]
    critic_verdict: str
    critic_feedback: str
    final_report: str
    # Usamos Annotated y operator.add para que los mensajes se vayan sumando a la lista
    messages: Annotated[Sequence[BaseMessage], operator.add]
