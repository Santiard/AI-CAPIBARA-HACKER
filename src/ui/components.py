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
    Renderiza los logs en una única terminal interactiva,
    resaltando en color cian/neón brillante el log activo más reciente.
    """
    st.markdown("##### 📡 Consola Multi-Agente en Tiempo Real")
    
    if not logs:
        st.info("Esperando inicio de la auditoría...")
        return
        
    html_lines = []
    total = len(logs)
    
    for i, log in enumerate(logs):
        is_current = (i == total - 1)
        clean_log = str(log).replace("<", "&lt;").replace(">", "&gt;")
        
        if is_current:
            line_html = f'<div style="background-color: rgba(6, 182, 212, 0.2); border-left: 4px solid #06b6d4; padding: 6px 10px; margin: 4px 0; border-radius: 4px; color: #67e8f9; font-weight: 600; font-family: monospace; font-size: 13px;"><span style="color: #22d3ee; margin-right: 6px;">▶️ [EN CURSO]</span> {clean_log}</div>'
        else:
            line_html = f'<div style="padding: 4px 10px; margin: 2px 0; color: #94a3b8; font-family: monospace; font-size: 12px; border-left: 2px solid #334155;"><span style="color: #22c55e; margin-right: 6px;">✓</span> {clean_log}</div>'
        html_lines.append(line_html)
        
    all_lines = "".join(html_lines)
    terminal_html = f'<div style="background-color: #0b0f19; border: 1px solid #1e293b; border-radius: 8px; padding: 12px; max-height: 320px; overflow-y: auto; box-shadow: inset 0 2px 6px rgba(0,0,0,0.6);">{all_lines}</div>'
    st.markdown(terminal_html, unsafe_allow_html=True)


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
