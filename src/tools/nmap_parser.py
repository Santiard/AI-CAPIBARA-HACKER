"""
Herramienta de análisis y parsing de escaneos de red (Nmap / Nessus).
Extrae puertos abiertos, servicios, versiones y CPEs en formatos estructurados.
Incluye decorador @tool de LangChain y fallback a escaneo simulado (Mock).
"""
import os
import json
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field
from langchain_core.tools import tool


class DiscoveredService(BaseModel):
    port: int = Field(description="Número de puerto")
    protocol: str = Field(default="tcp", description="Protocolo (tcp/udp)")
    state: str = Field(default="open", description="Estado del puerto")
    service: str = Field(description="Nombre general del servicio (ej. http, ssh, ftp)")
    product: Optional[str] = Field(default=None, description="Nombre específico del producto/software")
    version: Optional[str] = Field(default=None, description="Versión exacta detectada")
    extrainfo: Optional[str] = Field(default=None, description="Información adicional del banner")
    cpe: Optional[str] = Field(default=None, description="Identificador CPE (Common Platform Enumeration)")


class ScanTargetReport(BaseModel):
    target_ip: str = Field(description="Dirección IP del objetivo")
    hostname: Optional[str] = Field(default=None, description="Nombre de host resuelto")
    os_match: Optional[str] = Field(default=None, description="Sistema operativo detectado")
    open_ports_count: int = Field(default=0, description="Total de puertos abiertos")
    services: List[DiscoveredService] = Field(default_factory=list, description="Lista de servicios descubiertos")
    raw_summary: Optional[str] = Field(default=None, description="Resumen textual del escaneo")


def parse_nmap_xml(xml_source: str) -> ScanTargetReport:
    """
    Parsea un archivo XML de Nmap o una cadena con contenido XML.
    Retorna un objeto estructurado ScanTargetReport.
    """
    if os.path.isfile(xml_source):
        with open(xml_source, "r", encoding="utf-8") as f:
            xml_content = f.read()
    else:
        xml_content = xml_source.strip()

    root = ET.fromstring(xml_content)
    
    # Extraer host
    host_elem = root.find("host")
    if host_elem is None:
        raise ValueError("No se encontraron elementos <host> en el XML de Nmap.")

    # IP
    address_elem = host_elem.find("address")
    target_ip = address_elem.get("addr", "127.0.0.1") if address_elem is not None else "127.0.0.1"

    # Hostname
    hostname = None
    hostname_elem = host_elem.find(".//hostname")
    if hostname_elem is not None:
        hostname = hostname_elem.get("name")

    # OS
    os_match = None
    osmatch_elem = host_elem.find(".//osmatch")
    if osmatch_elem is not None:
        os_match = osmatch_elem.get("name")

    # Puertos y servicios
    services: List[DiscoveredService] = []
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
            
            # Solo incluir puertos abiertos o filtrados relevantes
            if state != "open":
                continue

            port_id = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")
            
            service_elem = port_elem.find("service")
            service_name = "unknown"
            product = None
            version = None
            extrainfo = None
            cpe = None

            if service_elem is not None:
                service_name = service_elem.get("name", "unknown")
                product = service_elem.get("product")
                version = service_elem.get("version")
                extrainfo = service_elem.get("extrainfo")
                
                cpe_elem = service_elem.find("cpe")
                if cpe_elem is not None and cpe_elem.text:
                    cpe = cpe_elem.text

            services.append(
                DiscoveredService(
                    port=port_id,
                    protocol=protocol,
                    state=state,
                    service=service_name,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                    cpe=cpe
                )
            )

    # Resumen de ejecución
    runstats_elem = root.find(".//finished")
    summary = runstats_elem.get("summary") if runstats_elem is not None else "Escaneo completado."

    return ScanTargetReport(
        target_ip=target_ip,
        hostname=hostname,
        os_match=os_match,
        open_ports_count=len(services),
        services=services,
        raw_summary=summary
    )


def generate_mock_scan() -> ScanTargetReport:
    """
    Genera un escaneo simulado realista para pruebas sin requerir ejecución real de Nmap.
    """
    return ScanTargetReport(
        target_ip="192.168.1.50",
        hostname="srv-corp-production.local",
        os_match="Linux Ubuntu 20.04 LTS (Kernel 5.4)",
        open_ports_count=5,
        services=[
            DiscoveredService(
                port=21,
                protocol="tcp",
                state="open",
                service="ftp",
                product="vsftpd",
                version="2.3.4",
                cpe="cpe:/a:vsftpd:vsftpd:2.3.4"
            ),
            DiscoveredService(
                port=22,
                protocol="tcp",
                state="open",
                service="ssh",
                product="OpenSSH",
                version="7.4p1",
                extrainfo="Debian 10+deb9u7",
                cpe="cpe:/a:openbsd:openssh:7.4p1"
            ),
            DiscoveredService(
                port=80,
                protocol="tcp",
                state="open",
                service="http",
                product="Apache httpd",
                version="2.4.29",
                extrainfo="(Ubuntu)",
                cpe="cpe:/a:apache:http_server:2.4.29"
            ),
            DiscoveredService(
                port=3306,
                protocol="tcp",
                state="open",
                service="mysql",
                product="MySQL",
                version="5.7.33",
                cpe="cpe:/a:mysql:mysql:5.7.33"
            ),
            DiscoveredService(
                port=8080,
                protocol="tcp",
                state="open",
                service="http",
                product="Apache Tomcat",
                version="9.0.30",
                cpe="cpe:/a:apache:tomcat:9.0.30"
            )
        ],
        raw_summary="Nmap mock scan completed: 5 open ports detected on target 192.168.1.50"
    )


@tool
def parse_nmap_scan_tool(scan_path_or_content: str) -> str:
    """
    Herramienta para el agente: Analiza la salida de un escaneo Nmap (ruta de archivo XML o contenido en texto).
    Retorna un JSON estructurado con los puertos, servicios y versiones encontrados.
    Si el input es 'mock' o el archivo no existe, devuelve un escaneo simulado de prueba.
    """
    try:
        if scan_path_or_content.strip().lower() in ["mock", "demo", "default"]:
            report = generate_mock_scan()
        elif os.path.exists(scan_path_or_content) or "<nmaprun" in scan_path_or_content:
            report = parse_nmap_xml(scan_path_or_content)
        else:
            # Fallback a mock si no se encuentra archivo
            report = generate_mock_scan()
        
        return report.model_dump_json(indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error parseando el escaneo de Nmap: {str(e)}"})
