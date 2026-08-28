import streamlit as st
import pandas as pd
import plotly.express as px

def render_agent_timeline(current_node: str):
    """
    Renderiza la línea de tiempo visual mostrando qué agente está activo.
    """
    st.subheader("⏱️ Línea de Tiempo de Ejecución")
    
    # Definimos el orden y los iconos de los nodos
    nodes_info = {
        "Orquestador": {"icon": "🧭", "desc": "Planificador"},
        "Parser": {"icon": "🔍", "desc": "Análisis de Red"},
        "Intel": {"icon": "🛡️", "desc": "Búsqueda CVE"},
        "Compliance": {"icon": "📋", "desc": "Hardening"},
        "Critic": {"icon": "⚖️", "desc": "QA y Validación"},
        "FinalReport": {"icon": "📄", "desc": "Generación de Reporte"}
    }
    
    # Crear columnas para simular una línea de tiempo horizontal
    cols = st.columns(len(nodes_info))
    
    for i, (node_name, info) in enumerate(nodes_info.items()):
        with cols[i]:
            if node_name == current_node:
                st.info(f"{info['icon']} **{node_name}**\n\n*(Activo)*")
            else:
                st.write(f"{info['icon']} {node_name}")


def render_live_logs(logs: list):
    """
    Renderiza los logs o mensajes emitidos por los agentes.
    """
    st.subheader("📡 Logs en Tiempo Real")
    log_container = st.container(height=300)
    with log_container:
        for log in logs:
            st.code(log, language="text")

def render_finding_cards(cve_findings: list, hardening_proposals: list):
    """
    Renderiza tarjetas individuales con los hallazgos de seguridad.
    """
    st.subheader("🚨 Hallazgos y Propuestas (Preview)")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Vulnerabilidades (CVEs)**")
        if cve_findings:
            for finding in cve_findings:
                severity = finding.get("severity", "UNKNOWN")
                color = "red" if severity == "HIGH" else "orange" if severity == "MEDIUM" else "gray"
                st.markdown(f"**{finding.get('cve', 'N/A')}** - <span style='color:{color}'>{severity}</span>", unsafe_allow_html=True)
        else:
            st.write("No se detectaron CVEs.")
            
    with col2:
        st.markdown("**Propuestas de Hardening**")
        if hardening_proposals:
            for prop in hardening_proposals:
                st.info(prop.get("recommendation", "N/A"))
        else:
            st.write("No hay propuestas generadas.")


def render_cvss_charts(cve_findings: list):
    """
    Genera un gráfico de distribución de severidad usando Plotly y Pandas.
    """
    st.subheader("📊 Distribución de Severidad")
    
    if not cve_findings:
        st.info("No hay datos para graficar.")
        return
        
    df = pd.DataFrame(cve_findings)
    if "severity" in df.columns:
        severity_counts = df["severity"].value_counts().reset_index()
        severity_counts.columns = ["Severidad", "Cantidad"]
        
        # Mapeo de colores estandar
        color_discrete_map = {
            "CRITICAL": "darkred",
            "HIGH": "red",
            "MEDIUM": "orange",
            "LOW": "green",
            "UNKNOWN": "gray"
        }
        
        fig = px.pie(
            severity_counts, 
            values="Cantidad", 
            names="Severidad", 
            title="Vulnerabilidades por Severidad",
            color="Severidad",
            color_discrete_map=color_discrete_map,
            hole=0.4
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("Faltan datos de severidad en los hallazgos.")
