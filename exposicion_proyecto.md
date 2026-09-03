# Guión de Exposición: AI-CAPIBARA-HACKER
**Materia:** AI Agentic Engineering (Corte 1)
**Duración estimada:** 10 - 15 minutos
**Integrantes:** 3 Personas (Persona A, Persona B, Persona C)

---

## 🎤 Introducción (Persona A - 3 mins)
**Tema de la clase aplicado:** Semana 1 (LLM Fundamentals) y Semana 4 (Introducción a RAG)

**[Persona A]:**
"Hola a todos, hoy vamos a presentar nuestro proyecto **AI-CAPIBARA-HACKER**. Nuestro objetivo fue construir un asistente de ciberseguridad impulsado por inteligencia artificial que no solo detecta vulnerabilidades en un sistema, sino que las analiza, explica y propone planes de mitigación basados en estándares internacionales.

Para lograr esto, nos enfrentamos al problema clásico de los LLMs: un modelo de lenguaje por sí solo no conoce las vulnerabilidades del día de hoy ni los manuales de hardening específicos a menos que se lo proporcionemos. Como vimos en la **Semana 1**, un LLM es fundamentalmente un motor de predicción de *tokens*. Si le pedimos que evalúe un reporte de Nmap crudo, puede alucinar o dar información genérica.

Para resolverlo, implementamos la arquitectura **RAG (Retrieval-Augmented Generation)** que vimos en la **Semana 4**. 
En lugar de depender del conocimiento pre-entrenado del modelo, construimos un *pipeline* de cuatro etapas:
1. **Ingestión e Indexación:** Tomamos bases de conocimiento extensas (como bases de datos de CVEs y manuales de CIS Benchmarks) y las indexamos en una base de datos vectorial llamada **ChromaDB**.
2. **Recuperación (Retrieval):** Cuando el sistema detecta un puerto abierto o un servicio vulnerable, nuestro sistema transforma ese hallazgo en *Embeddings* (usando el modelo `nomic-embed-text`) y realiza una búsqueda de similitud semántica mediante la distancia Coseno en ChromaDB.
3. **Generación (Generation):** Extraemos los fragmentos (chunks) más relevantes de ChromaDB y se los inyectamos en el contexto del LLM para que su respuesta esté 100% fundamentada en datos técnicos reales."

---

## 🧠 Context Engineering y Salidas Estructuradas (Persona B - 4 mins)
**Tema de la clase aplicado:** Semana 2 (System Prompts, JSON Mode) y Semana 1 (Parámetros de Inferencia)

**[Persona B]:**
"Una vez que recuperamos la información con RAG, necesitábamos que el LLM procesara la información y nos la devolviera de forma estructurada para mostrarla en nuestra interfaz (construida con Streamlit). Aquí aplicamos fuertemente los conceptos de **Context Engineering (Semana 2)**.

En lugar de usar un prompt genérico, diseñamos **System Prompts** estrictos para cada uno de nuestros agentes. Por ejemplo, nuestro Agente 'Intel' tiene una instrucción de sistema (System Instruction) que define su rol como Experto en Vulnerabilidades y le dicta restricciones claras, como por ejemplo: *'Debes traducir todo y responder únicamente en español'*.

Pero el mayor reto no era el idioma, sino el formato. Como la salida del modelo alimenta nuestra aplicación en Python, utilizamos **Structured JSON Output (Schema Forcing)**. Le indicamos al LLM que debe responder estrictamente con un objeto JSON que contenga tres claves específicas para cada vulnerabilidad:
- `summary`
- `os_behavior`
- `risk_impact`

Para garantizar que el modelo no se pusiera 'creativo' y rompiera el JSON, ajustamos los **Parámetros de Inferencia (Semana 1)**. Específicamente, bajamos la **Temperatura a 0.1**. Como aprendimos en clase, una temperatura baja colapsa la distribución de probabilidad hacia los *tokens* más deterministas, lo cual es ideal para tareas de extracción de datos y formateo JSON estricto, reduciendo a cero el riesgo de que el modelo empiece a generar texto fuera de la estructura."

---

## ⚙️ Manejo de Contexto y Orquestación Multi-Agente (Persona C - 4 mins)
**Tema de la clase aplicado:** Semana 3 (Context Windows, Batching) y preparativos para el Corte 2

**[Persona C]:**
"Finalmente, nos enfrentamos a las limitaciones de infraestructura y del **Context Window (Semana 3)**. Al correr modelos locales (como `qwen2.5:14b` o `llama3.2`) vía Ollama, nos dimos cuenta de que procesar 10 o 15 vulnerabilidades una por una era increíblemente lento y costoso a nivel de cómputo. Cada llamada al LLM implicaba re-procesar todo el contexto, y enviar las 15 juntas superaba el límite de *tokens*.

Para manejar la ventana de contexto de forma eficiente, implementamos una estrategia de **Procesamiento en Lote (Batching) y compresión**:
1. Filtramos y truncamos la información cruda que viene de ChromaDB (pasando solo los primeros cientos de caracteres) para no desperdiciar *tokens* de entrada.
2. Agrupamos las N vulnerabilidades más críticas y se las enviamos al LLM en un solo prompt consolidado.
3. Le configuramos explícitamente al modelo un `num_ctx=8192` y un `num_predict=4096` para asegurar que tuviera espacio suficiente en su ventana para generar el JSON largo de respuesta sin cortarse por la mitad.

Todo esto está orquestado mediante **Grafos de Estado (State Graphs)**, donde la información fluye de un nodo a otro (Parser -> Intel -> Compliance -> Critic), lo cual sienta perfectamente las bases para los Sistemas Multi-Agente que veremos en el Corte 2.

En resumen: AI-CAPIBARA-HACKER no es un simple chat. Es un sistema RAG determinista, con prompts fuertemente tipados, control de parámetros de inferencia y optimización de tokens de contexto, cumpliendo al 100% con los principios de Ingeniería de Agentes de IA."

---

## 📝 Consejos adicionales para el equipo:
> [!TIP]
> - **Demostración en Vivo:** Sería ideal que mientras la Persona C habla, muestren la interfaz web de Streamlit funcionando y cómo el JSON estructurado se convierte mágicamente en las tarjetas de la interfaz gráfica.
> - **Preguntas del Profesor:** Si el profesor les pregunta por qué usaron Ollama en lugar de la API de Gemini (que es la del curso), respondan que como es una herramienta de Ciberseguridad que analiza hosts, es una buena práctica mantener la privacidad de los datos corriendo modelos locales (*open-weights*) como se vio en la Semana 1.
