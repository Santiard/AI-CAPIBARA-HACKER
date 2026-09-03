import json
from src.agents.interpreter import batch_interpret_vulnerabilities

cands = [
    {"cve_id": "CVE-2021-21972", "product": "vcenter", "service_name": "vmware-authd", "port": 902, "raw_content": "Vulnerability ID: CVE-2021-21972 Target Service: vcenter..."},
    {"cve_id": "CVE-2024-23897", "product": "jenkins", "service_name": "GoogleDriveFS", "port": 7679, "raw_content": "Vulnerability ID: CVE-2024-23897..."}
]
res = batch_interpret_vulnerabilities(cands)
print(json.dumps(res, indent=2))
