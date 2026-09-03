import json
import re
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage
from src.config import OLLAMA_BASE_URL, OLLAMA_MODEL
from src.agents.interpreter import BATCH_INTERPRETER_PROMPT

cands = [
    {"cve_id": "CVE-2021-21972", "product": "vcenter", "service_name": "vmware-authd", "port": 902, "raw_content": "Vulnerability ID: CVE-2021-21972 Target Service: vcenter..."},
]
prompt_lines = [f"Interpreta las siguientes vulnerabilidades para el sistema Windows 11:\n"]
for cand in cands:
    prompt_lines.append(f"--- Vulnerabilidad: {cand['cve_id']} ---")
    prompt_lines.append(f"Servicio: {cand['service_name']} (Puerto {cand['port']})")
    prompt_lines.append(f"Información técnica: {cand['raw_content']}\n")
prompt_user = "\n".join(prompt_lines)

llm = ChatOllama(model=OLLAMA_MODEL, temperature=0.1, base_url=OLLAMA_BASE_URL)
response = llm.invoke([
    SystemMessage(content=BATCH_INTERPRETER_PROMPT.format(host_os="Windows 11")),
    HumanMessage(content=prompt_user)
])
print("RAW RESPONSE:")
print(response.content.strip())
