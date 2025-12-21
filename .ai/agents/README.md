# BMader Development Team - AI Agents

Este directorio contiene el equipo completo de agentes AI para desarrollo de software usando la metodología BMad Method.

## 🎯 Equipo de Desarrollo Completo

**10 agentes especializados** configurados para cargar automáticamente los protocolos del proyecto desde `protocols/` según la configuración en `bmad.yml`.

### 🧙 BMad Master - Orchestrador Principal

**Archivo**: `bmad-master.agent.yaml`
**Icono**: 🧙
**Rol**: Master Task Executor + BMad Expert + Workflow Orchestrator

**Responsabilidades**:

- Orquestar workflows y tareas
- Conocimiento comprehensivo de BMad Core
- Gestión de recursos en runtime
- Punto de entrada principal para operaciones BMad

**Comandos Principales**:

- `*list-tasks` - Listar tareas disponibles
- `*list-workflows` - Listar workflows disponibles
- `*party-mode` - Chat grupal con todos los agentes

### 📋 John - Product Manager

**Archivo**: `pm.agent.yaml`
**Icono**: 📋
**Rol**: Investigative Product Strategist + Market-Savvy PM

**Responsabilidades**:

- Investigación de mercado y análisis competitivo
- Creación de Product Requirements Documents (PRD)
- Gestión de epics y user stories
- Validación de alineación entre requisitos e implementación

**Comandos Principales**:

- `*workflow-status` - Ver estado del workflow
- `*create-prd` - Crear Product Requirements Document
- `*create-epics-and-stories` - Crear Epics y User Stories
- `*implementation-readiness` - Validar preparación para implementación

### 📊 Mary - Business Analyst

**Archivo**: `analyst.agent.yaml`
**Icono**: 📊
**Rol**: Strategic Business Analyst + Requirements Expert

**Responsabilidades**:

- Investigación de mercado y análisis de dominio
- Brainstorming de proyectos
- Creación de Product Briefs
- Documentación de proyectos existentes

**Comandos Principales**:

- `*brainstorm-project` - Sesión de brainstorming guiada
- `*research` - Investigación de mercado/dominio/competencia
- `*product-brief` - Crear Product Brief
- `*document-project` - Documentar proyecto existente

### 🏗️ Winston - Architect

**Archivo**: `architect.agent.yaml`
**Icono**: 🏗️
**Rol**: System Architect + Technical Design Leader

**Responsabilidades**:

- Diseño de arquitectura de sistemas
- Selección de tecnologías
- Patrones de diseño escalables
- Creación de diagramas técnicos

**Comandos Principales**:

- `*create-architecture` - Crear documento de arquitectura
- `*implementation-readiness` - Validar arquitectura
- `*create-excalidraw-diagram` - Crear diagrama de sistema
- `*create-excalidraw-dataflow` - Crear diagrama de flujo de datos

### 🎨 Sally - UX Designer

**Archivo**: `ux-designer.agent.yaml`
**Icono**: 🎨
**Rol**: User Experience Designer + UI Specialist

**Responsabilidades**:

- Diseño de experiencia de usuario
- Investigación de usuarios
- Diseño de interfaces
- Creación de wireframes

**Comandos Principales**:

- `*create-ux-design` - Generar diseño UX y plan UI
- `*validate-design` - Validar especificación UX
- `*create-excalidraw-wireframe` - Crear wireframe

### 🏃 Bob - Scrum Master

**Archivo**: `sm.agent.yaml`
**Icono**: 🏃
**Rol**: Technical Scrum Master + Story Preparation Specialist

**Responsabilidades**:

- Planificación de sprints
- Preparación de user stories
- Ceremonias ágiles
- Retrospectivas de equipo

**Comandos Principales**:

- `*sprint-planning` - Generar sprint-status.yaml
- `*create-story` - Crear user story
- `*validate-create-story` - Validar story
- `*epic-retrospective` - Retrospectiva después de epic

### 💻 Amelia - Developer

**Archivo**: `dev.agent.yaml`
**Icono**: 💻
**Rol**: Senior Software Engineer

**Responsabilidades**:

- Implementación de user stories
- Desarrollo siguiendo TDD (Test-Driven Development)
- Code review
- Ejecución de tests

**Comandos Principales**:

- `*dev-story` - Ejecutar workflow de desarrollo
- `*code-review` - Realizar code review

**Principios Clave**:

- Ciclo red-green-refactor
- Tests al 100% antes de completar
- Story file es la única fuente de verdad

### 🧪 Murat - Test Architect

**Archivo**: `tea.agent.yaml`
**Icono**: 🧪
**Rol**: Master Test Architect

**Responsabilidades**:

- Arquitectura de testing
- CI/CD y quality gates
- Testing automatizado
- Estrategia de testing basada en riesgo

**Comandos Principales**:

- `*framework` - Inicializar framework de testing
- `*atdd` - Generar tests E2E (antes de implementación)
- `*automate` - Generar test automation
- `*test-design` - Crear escenarios de testing
- `*trace` - Mapear requisitos a tests
- `*ci` - Scaffolding de pipeline CI/CD

### 📚 Paige - Technical Writer

**Archivo**: `tech-writer.agent.yaml`
**Icono**: 📚
**Rol**: Technical Documentation Specialist + Knowledge Curator

**Responsabilidades**:

- Documentación técnica
- Creación de diagramas (Mermaid, Excalidraw)
- Mejora de READMEs
- Estándares de documentación

**Comandos Principales**:

- `*document-project` - Documentación comprehensiva de proyecto
- `*generate-mermaid` - Crear diagramas Mermaid
- `*validate-doc` - Validar documentación
- `*improve-readme` - Mejorar READMEs
- `*explain-concept` - Explicar conceptos complejos

### 🚀 Barry - Quick Flow Solo Dev

**Archivo**: `quick-flow-solo-dev.agent.yaml`
**Icono**: 🚀
**Rol**: Elite Full-Stack Developer + Quick Flow Specialist

**Responsabilidades**:

- Desarrollo full-stack end-to-end autónomo
- Quick Flow workflow (concepto a deployment)
- Arquitectura de specs técnicas
- Implementación rápida sin handoffs
- Ship features completas de forma independiente

**Comandos Principales**:

- `*create-tech-spec` - Arquitectar spec técnica con stories listas (paso 1)
- `*quick-dev` - Implementar spec end-to-end solo (core de Quick Flow)
- `*code-review` - Review y mejora de código

**Principios Clave**:

- Planning y ejecución van juntos
- Código que shippea > código perfecto que no shippea
- Documentación durante desarrollo, no después
- Ship early, ship often

**Cuándo Usar a Barry**:

- Proyectos pequeños a medianos que un dev puede manejar
- Features completas que no requieren coordinación de equipo
- Quick wins y MVPs rápidos
- Cuando necesitas velocidad sobre proceso

## 🔧 Cómo Usar los Agentes

### Método 1: Cargar en IDE (Claude Code, Cursor, Windsurf, etc.)

1. **Instalar BMad Method** (si no está instalado):

   ```bash
   npx bmad-method@alpha install
   ```

2. **Cargar un agente** en tu IDE de IA favorito:
   - Abre el archivo `.yaml` del agente que necesitas
   - El agente se cargará con todos sus comandos disponibles

3. **Ejecutar comandos**:
   - Usa el trigger del comando (ej: `*create-prd`)
   - O simplemente conversa con el agente

### Método 2: Uso Directo

Los agentes también pueden ser usados directamente conversando con ellos:

```
"John (PM), necesito crear un PRD para [descripción del proyecto]"
```

### Método 3: Party Mode

Invoca múltiples agentes en una sesión grupal:

```
*party-mode
```

## 📋 Carga Automática de Protocolos

**IMPORTANTE**: Todos los agentes están configurados para cargar automáticamente los protocolos del proyecto:

### Proceso de Carga Automática

1. Al inicializarse, cada agente:
   - Lee `{project-root}/bmad.yml`
   - Identifica protocolos con `required: true`
   - Carga cada protocolo en memoria

2. Durante la ejecución:
   - Sigue las guías de los protocolos cargados
   - Referencia protocolos en decisiones
   - Aplica reglas de protocolos automáticamente

### Protocolos Activos

- **[Versioning](../../protocols/versioning.md)** - Gestión de versiones semánticas
  - Todos los agentes lo cargan automáticamente
  - Nunca hacer bump manual de versiones
  - Seguir flujo: dev → test → prod → main

## 🔄 Workflow Típico de Desarrollo

### 1. Fase de Análisis

1. **Mary (Analyst)**: `*brainstorm-project` o `*research`
2. **Mary (Analyst)**: `*product-brief`

### 2. Fase de Planificación

1. **John (PM)**: `*create-prd`
2. **Sally (UX Designer)**: `*create-ux-design`
3. **Winston (Architect)**: `*create-architecture`
4. **John (PM)**: `*create-epics-and-stories`

### 3. Fase de Validación

1. **John (PM)**: `*implementation-readiness`
2. **Sally (UX Designer)**: `*validate-design`

### 4. Fase de Implementación

1. **Bob (Scrum Master)**: `*sprint-planning`
2. **Bob (Scrum Master)**: `*create-story` para cada story
3. **Murat (TEA)**: `*atdd` (tests antes de implementación)
4. **Amelia (Developer)**: `*dev-story`
5. **Amelia (Developer)**: `*code-review`

### 5. Fase de Testing

1. **Murat (TEA)**: `*automate`
2. **Murat (TEA)**: `*trace`
3. **Murat (TEA)**: `*test-review`

### 6. Fase de Documentación

1. **Paige (Tech Writer)**: `*document-project`
2. **Paige (Tech Writer)**: `*improve-readme`

### 7. Retrospectiva

1. **Bob (Scrum Master)**: `*epic-retrospective`

## 🚀 Quick Flow (Desarrollo Rápido)

Para proyectos pequeños/medianos o features independientes:

1. **Barry (Quick Flow Solo Dev)**: `*create-tech-spec`
2. **Barry (Quick Flow Solo Dev)**: `*quick-dev`
3. **Barry (Quick Flow Solo Dev)**: `*code-review`

Barry maneja todo el ciclo de forma autónoma - ideal para MVPs y desarrollo rápido.

## 🎭 Personalidades de los Agentes

Cada agente tiene una personalidad distintiva:

- **BMad Master**: Directo, comprehensivo, usa tercera persona
- **John (PM)**: Detective implacable, pregunta "¿POR QUÉ?" constantemente
- **Mary (Analyst)**: Cazadora de tesoros, emocionada por patrones
- **Winston (Architect)**: Pragmático y calmado, defensor de "tecnología aburrida"
- **Sally (UX Designer)**: Storyteller empática, pinta con palabras
- **Bob (Scrum Master)**: Ultra-preciso, intolerancia a la ambigüedad
- **Amelia (Developer)**: Ultra-sucinta, habla en paths y IDs, cero fluff
- **Murat (TEA)**: Mezcla datos con instinto, "opiniones fuertes, débilmente sostenidas"
- **Paige (Tech Writer)**: Educadora paciente, celebra la claridad
- **Barry (Quick Flow)**: Directo, confiado, tech slang, resultados sobre todo

## 🌐 Idioma de Comunicación

Por defecto, todos los agentes se comunican en **español** según la configuración en `bmad.yml`:

```yaml
runtime:
  communication_language: "español"
```

Para cambiar el idioma, edita `bmad.yml` y actualiza `communication_language`.

## ⚙️ Configuración

Los agentes leen configuración de:

- **`bmad.yml`** - Configuración principal del proyecto
- **`protocols/`** - Protocolos compartidos
- **`{project-root}/_bmad/core/config.yaml`** - Configuración BMad Core
- **`**/project-context.md`\*\* - Contexto del proyecto (si existe)

## 🔗 Referencias Importantes

- **{project-root}** se resuelve automáticamente al root del proyecto
- Los workflows están en el submódulo `src/_bmad/`
- Los manifests de tareas/workflows en `src/_bmad/_config/`

## 🆘 Troubleshooting

### Agente no carga protocolos

1. Verificar que `bmad.yml` existe y está configurado
2. Verificar que archivos de protocolos existen en `protocols/`
3. Revisar `required: true` en configuración de protocolo

### Workflow no encontrado

1. Verificar que submódulo `src` está inicializado:
   ```bash
   git submodule update --init --recursive
   ```
2. Verificar rutas en comandos del agente

### Comandos no funcionan

1. Asegurarse de que BMad Method está instalado:
   ```bash
   npx bmad-method@alpha install
   ```
2. Verificar que el agente está cargado correctamente en el IDE

## 📞 Soporte

- Ver documentación completa en `docs/README.md`
- Revisar protocolos en `protocols/README.md`
- Consultar BMad Method en `src/README.md`

---

**¡El equipo está listo para desarrollar!** 🚀

Carga cualquier agente y comienza a trabajar. Todos cargarán automáticamente los protocolos y estarán sincronizados.
