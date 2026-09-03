import os
import streamlit as st
import json
from langchain_core.messages import SystemMessage

# Importamos nuestro grafo compilado y herramientas de diagnóstico
from src.agents.graph import agent_graph
from src.tools.host_inspector import get_system_profile
from src.ui.components import render_agent_timeline, render_live_logs, render_finding_cards, render_cvss_charts

st.set_page_config(page_title="AI-CAPIBARA-HACKER", page_icon="🦫", layout="wide")

def initialize_state():
    if "logs" not in st.session_state:
        st.session_state.logs = []
    if "current_node" not in st.session_state:
        st.session_state.current_node = None
    if "graph_state" not in st.session_state:
        st.session_state.graph_state = None
    if "execution_finished" not in st.session_state:
        st.session_state.execution_finished = False
    if "human_review_pending" not in st.session_state:
        st.session_state.human_review_pending = False
    if "thread_config" not in st.session_state:
        st.session_state.thread_config = {"configurable": {"thread_id": "session_capibara_1"}}

def render_loading_capybara():
    st.markdown("""
        <style>
        .capy-loader-container {
            width: 100%;
            max-width: 480px;
            margin: 12px auto;
            padding: 8px 12px;
            text-align: center;
        }
        .capy-track {
            position: relative;
            width: 100%;
            height: 8px;
            background: #1e293b;
            border-radius: 6px;
            overflow: visible;
            margin-top: 26px;
            margin-bottom: 10px;
            box-shadow: 0 0 10px rgba(6, 182, 212, 0.15);
        }
        .capy-bar-fill {
            position: absolute;
            top: 0;
            left: 0;
            height: 100%;
            background: linear-gradient(90deg, #06b6d4, #3b82f6, #10b981);
            border-radius: 6px;
            animation: fillBar 2.2s ease-in-out infinite alternate;
        }
        .capy-walker {
            position: absolute;
            top: -24px;
            font-size: 22px;
            line-height: 1;
            filter: drop-shadow(0 2px 4px rgba(6, 182, 212, 0.5));
            animation: walkAcross 2.2s ease-in-out infinite alternate;
            user-select: none;
        }
        @keyframes walkAcross {
            0% { left: 0%; transform: scaleX(1); }
            48% { transform: scaleX(1); }
            52% { transform: scaleX(-1); }
            100% { left: calc(100% - 24px); transform: scaleX(-1); }
        }
        @keyframes fillBar {
            0% { width: 12%; }
            100% { width: 100%; }
        }
        .capy-text {
            font-family: monospace;
            font-size: 13px;
            font-weight: 600;
            color: #38bdf8;
            letter-spacing: 0.4px;
            margin-top: 6px;
        }
        </style>
    """, unsafe_allow_html=True)
    
    placeholder = st.empty()
    with placeholder.container():
        st.markdown('''
            <div class="capy-loader-container">
                <div class="capy-track">
                    <div class="capy-walker">🦫</div>
                    <div class="capy-bar-fill"></div>
                </div>
                <div class="capy-text">Auditoría en curso: agentes analizando y correlacionando inteligencia...</div>
            </div>
        ''', unsafe_allow_html=True)
    return placeholder


def main():
    initialize_state()
    
    st.title("🦫 AI-CAPIBARA-HACKER")
    st.markdown("### Sistema Multi-Agente de Auditoría de Seguridad & Diagnóstico Defensivo")
    
    # --- Sidebar: Selección de Modo ---
    with st.sidebar:
        st.header("⚙️ Configuración de Auditoría")
        
        mode_choice = st.radio(
            "Selecciona el Modo:",
            ["📂 Modo Pasivo (Escaneo Nmap)", "🖥️ Modo Activo (Diagnóstico Local del PC)"],
            index=0
        )
        
        raw_scan_data = ""
        is_active_mode = "Activo" in mode_choice
        start_execution = False
        
        if not is_active_mode:
            st.subheader("📂 Ingestión de Escaneo")
            uploaded_file = st.file_uploader("Arrastra archivo XML o JSON de Nmap", type=["xml", "json"])
            test_example = st.button("🚀 Cargar sample_scan.xml de prueba")
            
            if test_example:
                sample_path = os.path.join("data", "scans", "sample_scan.xml")
                if os.path.exists(sample_path):
                    with open(sample_path, "r", encoding="utf-8") as f:
                        raw_scan_data = f.read()
                    st.success("sample_scan.xml cargado (6 puertos: FTP, SSH, Apache, MySQL, Tomcat).")
            elif uploaded_file is not None:
                raw_scan_data = uploaded_file.getvalue().decode("utf-8")
                st.success("Archivo de escaneo cargado exitosamente.")
                
            start_execution = st.button("▶️ Iniciar Auditoría Pasiva", type="primary", disabled=not raw_scan_data)
        
        else:
            st.subheader("🖥️ Diagnóstico Activo Local")
            try:
                prof = get_system_profile()
                st.info(f"**Host:** `{prof.hostname}`\n\n**OS:** `{prof.os_name} {prof.os_release}` ({prof.architecture})\n\n**IPs:** `{', '.join(prof.ip_addresses)}`")
            except Exception as e:
                st.warning(f"No se pudo precargar perfil del host: {e}")
                
            auth_granted = st.checkbox(
                "🔒 **Autorizo la inspección local** de sockets TCP en estado LISTEN y procesos del sistema (read-only).",
                value=False
            )
            
            start_execution = st.button(
                "▶️ Iniciar Diagnóstico Activo",
                type="primary",
                disabled=not auth_granted
            )
            raw_scan_data = "active_mode_trigger"

    # --- Línea de Tiempo de Agentes ---
    render_agent_timeline(st.session_state.current_node)
    
    # Contenedores dinámicos con placeholders únicos
    logs_col, cards_col = st.columns([1, 1])
    logs_placeholder = logs_col.empty()
    cards_placeholder = cards_col.empty()
    
    # Renderizar el estado inicial o actual en el placeholder
    with logs_placeholder.container():
        render_live_logs(st.session_state.logs)
        
    if st.session_state.graph_state:
        with cards_placeholder.container():
            render_finding_cards(
                st.session_state.graph_state.get("cve_findings", []),
                st.session_state.graph_state.get("hardening_proposals", [])
            )
    
    if start_execution and raw_scan_data:
        mode_str = "active" if is_active_mode else "passive"
        st.session_state.logs = [f"Iniciando flujo multiagente en Modo {mode_str.upper()}..."]
        st.session_state.execution_finished = False
        st.session_state.human_review_pending = False
        
        # Iniciar thread único para LangGraph
        import uuid
        st.session_state.thread_config = {"configurable": {"thread_id": f"session_{uuid.uuid4().hex[:8]}"}}
        
        initial_state = {
            "audit_mode": mode_str,
            "human_approval_granted": True,
            "raw_scan": raw_scan_data,
            "messages": [],
            "critic_retry_count": 0
        }
        
        loader_placeholder = render_loading_capybara()
        
        try:
            for event in agent_graph.stream(initial_state, st.session_state.thread_config):
                for node_name, _ in event.items():
                    st.session_state.current_node = node_name
                    st.session_state.logs.append(f"Agente [{node_name}] completó su tarea.")
                    
                    # Actualizar en el mismo contenedor en tiempo real
                    with logs_placeholder.container():
                        render_live_logs(st.session_state.logs)
                    
                    st.session_state.graph_state = agent_graph.get_state(st.session_state.thread_config).values
                    with cards_placeholder.container():
                        render_finding_cards(
                            st.session_state.graph_state.get("cve_findings", []),
                            st.session_state.graph_state.get("hardening_proposals", [])
                        )
        except Exception as e:
            st.error(f"Error durante la ejecución del grafo: {e}")
            st.session_state.logs.append(f"Error: {e}")
        finally:
            loader_placeholder.empty()
        
        # Verificar pausa de Human-in-the-loop antes de FinalReport
        current_graph_state = agent_graph.get_state(st.session_state.thread_config)
        if current_graph_state.next:
            st.session_state.human_review_pending = True
            st.session_state.logs.append("⏸️ Ejecución pausada por el Agente Crítico. Esperando revisión humana.")
            with logs_placeholder.container():
                render_live_logs(st.session_state.logs)

    # --- Renderizar Revisión Humana si aplica ---
    if st.session_state.graph_state:
        state = st.session_state.graph_state
            
        if st.session_state.human_review_pending:
            st.warning("⚠️ **Revisión del Agente Crítico & Human-in-the-Loop**")
            st.markdown(f"**Veredicto del Crítico (Qwen 2.5 14B):** `{state.get('critic_verdict', 'N/A').upper()}`")
            st.info(f"**Justificación de QA:** {state.get('critic_feedback', 'Sin comentarios.')}")
            
            if st.button("✅ Aprobar Dictamen y Emitir Reporte Final", type="primary"):
                with st.spinner("Generando reporte técnico y exportando PDF..."):
                    for event in agent_graph.stream(None, st.session_state.thread_config):
                        for node_name, _ in event.items():
                            st.session_state.current_node = node_name
                            st.session_state.logs.append(f"Agente [{node_name}] completó su tarea.")
                            with logs_placeholder.container():
                                render_live_logs(st.session_state.logs)
                    
                    st.session_state.human_review_pending = False
                    st.session_state.execution_finished = True
                    st.session_state.graph_state = agent_graph.get_state(st.session_state.thread_config).values
                    st.rerun()


    # --- Renderizado Final del Reporte ---
    if st.session_state.execution_finished and st.session_state.graph_state:
        state = st.session_state.graph_state
        st.divider()
        st.header("📄 Informe Técnico de Auditoría Final")
        
        col_report, col_charts = st.columns([2, 1])
        
        with col_report:
            final_md = state.get("final_report", "Error: No se generó el reporte.")
            st.markdown(final_md)
            
            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                st.download_button(
                    label="📥 Descargar Reporte (Markdown)",
                    data=final_md,
                    file_name="auditoria_ai_capibara.md",
                    mime="text/markdown"
                )
            with col_btn2:
                pdf_path = "exports/audit_report.pdf"
                if os.path.exists(pdf_path):
                    with open(pdf_path, "rb") as pdf_file:
                        pdf_bytes = pdf_file.read()
                    st.download_button(
                        label="📄 Descargar Informe Oficial (PDF)",
                        data=pdf_bytes,
                        file_name="auditoria_ai_capibara.pdf",
                        mime="application/pdf"
                    )

        with col_charts:
            render_cvss_charts(state.get("cve_findings", []))

if __name__ == "__main__":
    main()

