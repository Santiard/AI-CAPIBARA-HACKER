import streamlit as st
import json
from langchain_core.messages import SystemMessage

# Importamos nuestro grafo compilado
from src.agents.graph import agent_graph
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
        # Checkpointer en langgraph necesita un thread_id
        st.session_state.thread_config = {"configurable": {"thread_id": "session_1"}}

def render_loading_capybara():
    # Custom CSS for a pulsing/floating animation
    st.markdown("""
        <style>
        .capybara-loader {
            display: block;
            margin-left: auto;
            margin-right: auto;
            width: 250px;
            border-radius: 20px;
            box-shadow: 0 0 20px rgba(0, 255, 255, 0.5);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(1); box-shadow: 0 0 20px rgba(0, 255, 255, 0.5); }
            50% { transform: scale(1.05); box-shadow: 0 0 40px rgba(0, 255, 255, 0.9); }
            100% { transform: scale(1); box-shadow: 0 0 20px rgba(0, 255, 255, 0.5); }
        }
        .loading-text {
            text-align: center;
            font-size: 20px;
            font-weight: bold;
            color: #00ffff;
            margin-top: 15px;
            font-family: monospace;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # We use st.empty() as a placeholder so we can clear it later
    placeholder = st.empty()
    with placeholder.container():
        # Using a relative path or base64 can be tricky in streamlit without proper static config,
        # so we read the local file and display it natively, but apply our custom class if possible,
        # or we just encode it to base64 to put it strictly inside the HTML.
        import base64
        with open("src/ui/assets/hacker_capybara.jpg", "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode()
        
        st.markdown(f'''
            <img class="capybara-loader" src="data:image/jpeg;base64,{encoded_string}">
            <p class="loading-text">Hackeando el sistema... (Agentes trabajando)</p>
        ''', unsafe_allow_html=True)
    return placeholder

def main():
    initialize_state()
    
    st.title("🦫 AI-CAPIBARA-HACKER")
    st.markdown("### Dashboard de Auditoría Multi-Agente")
    
    # --- Sidebar: Uploader ---
    with st.sidebar:
        st.header("📂 Cargar Escaneo")
        uploaded_file = st.file_uploader("Arrastra tu archivo XML/JSON aquí", type=["xml", "json"])
        
        test_example = st.button("🚀 Cargar Ejemplo de Prueba")
        
        raw_scan_data = None
        if test_example:
            raw_scan_data = '{"host": "192.168.1.100", "ports": [{"port": 22, "service": "ssh", "version": "OpenSSH 8.2p1"}], "status": "up"}'
            st.success("Ejemplo cargado.")
        elif uploaded_file is not None:
            raw_scan_data = uploaded_file.getvalue().decode("utf-8")
            st.success("Archivo cargado exitosamente.")
            
        start_execution = st.button("▶️ Iniciar Auditoría", type="primary", disabled=not raw_scan_data)

    # --- Lógica Principal de Ejecución ---
    
    # Visualización de estado actual
    render_agent_timeline(st.session_state.current_node)
    
    # Contenedores dinámicos
    logs_col, cards_col = st.columns([1, 1])
    
    if start_execution and raw_scan_data:
        # Reiniciar estado
        st.session_state.logs = [f"Iniciando auditoría con archivo de {len(raw_scan_data)} bytes..."]
        st.session_state.execution_finished = False
        st.session_state.human_review_pending = False
        
        # Estado inicial para el grafo
        initial_state = {"raw_scan": raw_scan_data, "messages": []}
        
        # Ejecutar grafo en modo stream mostrando el loader pro del capibara
        loader_placeholder = render_loading_capybara()
        
        for event in agent_graph.stream(initial_state, st.session_state.thread_config):
            # event es un dict {node_name: {state_updates}}
            for node_name, state_update in event.items():
                st.session_state.current_node = node_name
                st.session_state.logs.append(f"[{node_name}] completó su tarea.")
                
                # Actualizar UI para cada paso
                with logs_col:
                    render_live_logs(st.session_state.logs)
                
                # Guardamos el último estado conocido del grafo
                st.session_state.graph_state = agent_graph.get_state(st.session_state.thread_config).values
        
        # Limpiamos el loader animado una vez terminó la ejecución sincrónica
        loader_placeholder.empty()
        
        # Chequear si está pausado (Human in the loop)
        current_graph_state = agent_graph.get_state(st.session_state.thread_config)
        if current_graph_state.next:
            # Significa que está esperando para ejecutar el next node (FinalReport)
            st.session_state.human_review_pending = True
            st.session_state.logs.append("⏸️ Ejecución pausada por el Crítico. Esperando revisión humana.")
                
    # --- Mostrar UI con estado actual ---
    if st.session_state.graph_state:
        state = st.session_state.graph_state
        
        with cards_col:
            render_finding_cards(state.get("cve_findings", []), state.get("hardening_proposals", []))
            
        if st.session_state.human_review_pending:
            st.warning("⚠️ **Revisión Requerida**")
            st.write(f"**Veredicto del Crítico:** {state.get('critic_verdict', 'N/A')}")
            st.write(f"**Feedback:** {state.get('critic_feedback', 'N/A')}")
            
            if st.button("✅ Aprobar y Generar Reporte Final"):
                with st.spinner("Generando reporte final..."):
                    # Continuar ejecución (mandamos resume)
                    for event in agent_graph.stream(None, st.session_state.thread_config):
                        for node_name, _ in event.items():
                            st.session_state.current_node = node_name
                            st.session_state.logs.append(f"[{node_name}] completó su tarea.")
                    
                    st.session_state.human_review_pending = False
                    st.session_state.execution_finished = True
                    st.session_state.graph_state = agent_graph.get_state(st.session_state.thread_config).values
                    st.rerun()

    # --- Renderizado Final ---
    if st.session_state.execution_finished and st.session_state.graph_state:
        state = st.session_state.graph_state
        st.divider()
        st.header("📄 Reporte Final")
        
        col_report, col_charts = st.columns([2, 1])
        
        with col_report:
            final_md = state.get("final_report", "Error: No se generó el reporte.")
            st.markdown(final_md)
            
            st.download_button(
                label="📥 Descargar Reporte (Markdown)",
                data=final_md,
                file_name="auditoria_ai_capibara.md",
                mime="text/markdown"
            )
            
        with col_charts:
            render_cvss_charts(state.get("cve_findings", []))

if __name__ == "__main__":
    main()
