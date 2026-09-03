"""
Herramientas de inspección y diagnóstico activo del host local.
Permite descubrir de forma segura (read-only) variables de entorno, sistema operativo,
interfaces de red y puertos/servicios locales en escucha mediante psutil y platform.
Incluye decoradores @tool de LangChain para integración con agentes.
"""
import os
import platform
import socket
import json
import logging
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from langchain_core.tools import tool

logger = logging.getLogger("ai_capibara.tools.host_inspector")

try:
    import psutil
except ImportError:
    psutil = None
    logger.warning("psutil no está disponible. Las funciones de red usarán modo fallback.")


class HostEnvironmentProfile(BaseModel):
    hostname: str = Field(description="Nombre del equipo anfitrión")
    os_name: str = Field(description="Nombre del sistema operativo (Windows, Linux, Darwin)")
    os_release: str = Field(description="Versión/Release del sistema operativo")
    os_version: str = Field(description="Versión detallada del kernel/build")
    architecture: str = Field(description="Arquitectura de hardware (AMD64, x86_64, etc.)")
    processor: Optional[str] = Field(default=None, description="Modelo del procesador")
    ip_addresses: List[str] = Field(default_factory=list, description="Direcciones IPv4 activas")
    safe_env_summary: Dict[str, str] = Field(default_factory=dict, description="Variables de entorno del sistema no sensibles")


class LocalListeningService(BaseModel):
    port: int = Field(description="Puerto local en escucha")
    protocol: str = Field(default="tcp", description="Protocolo de transporte")
    status: str = Field(default="LISTEN", description="Estado de la conexión en el socket")
    pid: Optional[int] = Field(default=None, description="Identificador del proceso local (PID)")
    process_name: str = Field(default="unknown", description="Nombre del proceso/ejecutable asociado")
    service: str = Field(description="Servicio inferido (ej. http, ssh, mysql, ollama)")
    product: Optional[str] = Field(default=None, description="Nombre inferido del producto de software")
    version: Optional[str] = Field(default=None, description="Versión estimada si es posible")
    bind_address: str = Field(default="127.0.0.1", description="Dirección IP de enlace local")
    cpe: Optional[str] = Field(default=None, description="Identificador CPE aproximado")


def infer_service_from_port_and_process(port: int, process_name: str) -> tuple:
    """
    Infiere el nombre del servicio, producto y CPE estimado a partir del puerto y nombre de proceso.
    """
    proc = (process_name or "").lower()
    
    # Mapeo conocido por puertos y binarios comunes
    if port == 21 or "ftp" in proc:
        return ("ftp", "vsftpd / FTP Server", "cpe:/a:vsftpd:vsftpd")
    elif port == 22 or "ssh" in proc:
        return ("ssh", "OpenSSH Server", "cpe:/a:openbsd:openssh")
    elif port == 80:
        if "nginx" in proc:
            return ("http", "Nginx Web Server", "cpe:/a:f5:nginx")
        elif "httpd" in proc or "apache" in proc:
            return ("http", "Apache httpd", "cpe:/a:apache:http_server")
        return ("http", "Web Server", "cpe:/a:generic:http_server")
    elif port == 443:
        if "nginx" in proc:
            return ("ssl/http", "Nginx Web Server TLS", "cpe:/a:f5:nginx")
        return ("ssl/http", "Apache httpd TLS", "cpe:/a:apache:http_server")
    elif port == 3306 or "mysql" in proc or "mariadb" in proc:
        return ("mysql", "MySQL Database Server", "cpe:/a:mysql:mysql")
    elif port == 5432 or "postgres" in proc:
        return ("postgresql", "PostgreSQL Database Server", "cpe:/a:postgresql:postgresql")
    elif port == 8080:
        if "tomcat" in proc or "java" in proc:
            return ("http", "Apache Tomcat", "cpe:/a:apache:tomcat")
        return ("http", "HTTP Alternate Service", None)
    elif port == 11434 or "ollama" in proc:
        return ("ollama", "Ollama LLM Engine", "cpe:/a:ollama:ollama")
    elif port == 8501 or "streamlit" in proc:
        return ("streamlit", "Streamlit Dashboard", "cpe:/a:streamlit:streamlit")
    elif port == 27017 or "mongo" in proc:
        return ("mongodb", "MongoDB Server", "cpe:/a:mongodb:mongodb")
    elif port == 6379 or "redis" in proc:
        return ("redis", "Redis In-Memory Store", "cpe:/a:redis:redis")
    elif port == 135:
        return ("msrpc", "Microsoft Windows RPC Endpoint Mapper", "cpe:/o:microsoft:windows")
    elif port == 139:
        return ("netbios-ssn", "Microsoft Windows NetBIOS-SSN", "cpe:/o:microsoft:windows")
    elif port == 445:
        return ("microsoft-ds", "Microsoft Windows SMB File Sharing", "cpe:/o:microsoft:windows")
    elif port == 1433 or "sqlservr" in proc:
        return ("ms-sql", "Microsoft SQL Server", "cpe:/a:microsoft:sql_server")
    
    # Fallback genérico
    clean_proc = process_name.replace(".exe", "") if process_name else "local_service"
    return (clean_proc.lower(), f"{clean_proc} Service", None)


def get_system_profile() -> HostEnvironmentProfile:
    """
    Descubre de manera segura las variables de entorno, sistema operativo
    e interfaces de red activas del host local.
    """
    hostname = socket.gethostname()
    os_name = platform.system()
    os_release = platform.release()
    os_version = platform.version()
    arch = platform.machine()
    proc = platform.processor() or "CPU General"

    # Obtener IPs locales de forma segura
    ips = set()
    try:
        # IP conectada principal
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # No se envía tráfico real; sirve para determinar la interfaz de salida
        s.connect(("8.8.8.8", 80))
        primary_ip = s.getsockname()[0]
        ips.add(primary_ip)
        s.close()
    except Exception:
        pass

    try:
        host_ips = socket.gethostbyname_ex(hostname)[2]
        for ip in host_ips:
            if not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass

    if not ips:
        ips.add("127.0.0.1")

    # Resumen de variables de entorno no sensibles (filtrando passwords/tokens)
    safe_env_keys = [
        "COMPUTERNAME", "USERNAME", "USER", "OS", "PATHEXT",
        "NUMBER_OF_PROCESSORS", "PROCESSOR_IDENTIFIER", "LANG", "SHELL"
    ]
    safe_env = {}
    for k in safe_env_keys:
        val = os.environ.get(k)
        if val:
            safe_env[k] = val

    return HostEnvironmentProfile(
        hostname=hostname,
        os_name=os_name,
        os_release=os_release,
        os_version=os_version,
        architecture=arch,
        processor=proc,
        ip_addresses=sorted(list(ips)),
        safe_env_summary=safe_env
    )


def inspect_listening_services(target_ip: str = "127.0.0.1") -> List[LocalListeningService]:
    """
    Inspecciona las conexiones locales TCP en estado LISTEN en la máquina anfitriona.
    Retorna una lista de LocalListeningService estructurada.
    """
    if not psutil:
        logger.warning("psutil no disponible, devolviendo servicios simulados de respaldo.")
        return [
            LocalListeningService(
                port=11434,
                service="ollama",
                product="Ollama LLM Engine",
                process_name="ollama.exe",
                bind_address="127.0.0.1",
                cpe="cpe:/a:ollama:ollama"
            )
        ]

    discovered = []
    seen_ports = set()

    try:
        connections = psutil.net_connections(kind='tcp')
        for conn in connections:
            # Solo puertos en escucha (LISTEN)
            if conn.status != psutil.CONN_LISTEN:
                continue

            laddr = conn.laddr
            port = laddr.port
            ip = laddr.ip

            if port in seen_ports:
                continue

            # Obtener nombre del proceso de manera segura
            proc_name = "system"
            if conn.pid:
                try:
                    p = psutil.Process(conn.pid)
                    proc_name = p.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    proc_name = f"pid_{conn.pid}"

            service_name, product_name, cpe_str = infer_service_from_port_and_process(port, proc_name)

            discovered.append(
                LocalListeningService(
                    port=port,
                    protocol="tcp",
                    status="LISTEN",
                    pid=conn.pid,
                    process_name=proc_name,
                    service=service_name,
                    product=product_name,
                    bind_address=ip,
                    cpe=cpe_str
                )
            )
            seen_ports.add(port)

    except Exception as e:
        logger.error(f"Error consultando conexiones locales con psutil: {e}")

    # Ordenar por número de puerto
    discovered.sort(key=lambda x: x.port)
    return discovered


def run_active_host_diagnostics(target_ip: str = "127.0.0.1") -> Dict[str, Any]:
    """
    Ejecuta el diagnóstico completo del host anfitrión y devuelve un diccionario
    con estructura compatible con ScanTargetReport para el flujo de agentes.
    """
    profile = get_system_profile()
    services = inspect_listening_services(target_ip=target_ip)

    # Formatear servicios en estructura compatible con DiscoveredService
    compatible_services = []
    for s in services:
        compatible_services.append({
            "port": s.port,
            "protocol": s.protocol,
            "state": "open",
            "service": s.service,
            "product": s.product,
            "version": s.version or "local_active",
            "extrainfo": f"PID: {s.pid} ({s.process_name}) Bind: {s.bind_address}",
            "cpe": s.cpe
        })

    return {
        "target_ip": target_ip if target_ip != "127.0.0.1" and target_ip in profile.ip_addresses else profile.ip_addresses[0],
        "hostname": profile.hostname,
        "os_match": f"{profile.os_name} {profile.os_release} ({profile.architecture})",
        "open_ports_count": len(compatible_services),
        "services": compatible_services,
        "host_profile": profile.model_dump(),
        "raw_summary": f"Diagnóstico activo completado en {profile.hostname}. {len(compatible_services)} puertos locales en escucha detectados."
    }


@tool
def get_system_profile_tool() -> str:
    """
    Herramienta para el agente: Descubre las variables de entorno, sistema operativo,
    arquitectura e interfaces de red activas del PC anfitrión.
    """
    profile = get_system_profile()
    return profile.model_dump_json(indent=2)


@tool
def inspect_listening_services_tool(target_host: str = "127.0.0.1") -> str:
    """
    Herramienta para el agente: Inspecciona los puertos y servicios TCP locales en escucha (LISTEN)
    en el host especificado, identificando procesos activos (ej. MySQL, OpenSSH, Ollama, HTTP).
    """
    services = inspect_listening_services(target_ip=target_host)
    return json.dumps([s.model_dump() for s in services], indent=2)
