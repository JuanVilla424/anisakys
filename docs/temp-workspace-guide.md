# Guía de Uso: Carpeta Temporal y Current Context

**Versión**: 1.0.0
**Fecha**: 2025-12-17
**Proyecto**: BMader Template

---

## 📋 Tabla de Contenidos

1. [Introducción](#introducción)
2. [Estructura de temp/](#estructura-de-temp)
3. [Current Context](#current-context)
4. [Casos de Uso](#casos-de-uso)
5. [Flujo de Trabajo](#flujo-de-trabajo)
6. [Comandos Útiles](#comandos-útiles)
7. [Integración con Agentes](#integración-con-agentes)
8. [Mejores Prácticas](#mejores-prácticas)

---

## Introducción

La carpeta `temp/` es el espacio de trabajo temporal estándar para todos los proyectos BMad. Su propósito es:

- ✅ Mantener el contexto actual de trabajo
- ✅ Almacenar archivos temporales sin ensuciar el repositorio
- ✅ Facilitar la colaboración entre agentes y desarrolladores
- ✅ Proporcionar un espacio de cache y logs centralizado

**Importante**: Todo el contenido de `temp/` está excluido del control de versiones mediante `.gitignore`.

---

## Estructura de temp/

```
temp/
├── current-context/           # 🎯 Contexto actual de trabajo
│   ├── session-notes.md      # Notas de la sesión
│   ├── decisions.md          # Decisiones técnicas documentadas
│   ├── todo.md               # Lista de tareas
│   └── artifacts/            # Archivos generados temporalmente
├── cache/                    # 💾 Cache temporal
└── logs/                     # 📝 Logs de ejecución
```

### Descripción de Carpetas

#### `current-context/`

Almacena el estado actual del trabajo. Es el corazón del sistema temporal.

**Archivos principales**:

- **session-notes.md**: Registro cronológico de actividades, problemas y observaciones
- **decisions.md**: Documentación formal de decisiones técnicas y arquitectónicas
- **todo.md**: Lista de tareas pendientes, en progreso y completadas

**Subcarpeta artifacts/**: Para archivos generados (exports, diagramas, análisis, etc.)

#### `cache/`

Cache temporal para operaciones que se benefician de persistencia entre ejecuciones:

- Resultados de análisis de código
- Índices generados
- Datos descargados temporalmente
- Compilaciones parciales

#### `logs/`

Logs de ejecución de scripts, workflows y operaciones:

- Logs de tests
- Output de builds
- Logs de workflows de BMad
- Traces de debugging

---

## Current Context

### ¿Qué es el Current Context?

El **Current Context** es un sistema de documentación continua que captura:

1. **Estado actual del trabajo**: Qué se está haciendo ahora
2. **Decisiones tomadas**: Por qué se tomaron ciertas decisiones
3. **Tareas pendientes**: Qué queda por hacer
4. **Conocimiento temporal**: Información útil que aún no se ha documentado permanentemente

### Archivos del Current Context

#### 1. session-notes.md

**Propósito**: Bitácora de la sesión actual

**Estructura recomendada**:

```markdown
# Notas de Sesión

**Fecha de inicio**: YYYY-MM-DD
**Proyecto**: [nombre] v[versión]
**Agente/Desarrollador**: [nombre]

## Objetivo de la Sesión

[Qué se quiere lograr]

## Actividades Realizadas

- Actividad 1
- Actividad 2

## Problemas Encontrados

- Problema y su solución

## Observaciones Importantes

- Observación 1

## Referencias Útiles

- Links, documentos, código relevante

## Próximos Pasos

- [ ] Siguiente tarea
```

**Cuándo actualizar**: A medida que trabajas, agrega notas continuamente

#### 2. decisions.md

**Propósito**: Registro formal de decisiones arquitectónicas y técnicas (ADR - Architecture Decision Records)

**Estructura recomendada**:

```markdown
## Decisión XXX: [Título]

**Fecha**: YYYY-MM-DD
**Estado**: ✅ Aprobada | 🔄 En revisión | ❌ Rechazada
**Decisor**: [Nombre/Rol]

### Contexto

[Por qué se necesita una decisión]

### Decisión

[Qué se decidió]

### Justificación

**Ventajas**: [Lista]
**Desventajas**: [Lista]
**Alternativas Consideradas**: [Lista con razones de rechazo]

### Trade-offs

[Compromisos aceptados]

### Impacto

[Consecuencias de la decisión]
```

**Cuándo actualizar**: Cada vez que se toma una decisión técnica importante

#### 3. todo.md

**Propósito**: Gestión de tareas de la sesión actual

**Estructura recomendada**:

```markdown
## 🔄 En Progreso

- [x] Tarea en curso

## 📋 Pendientes

- [ ] Tarea pendiente

## ✅ Completadas

- [x] Tarea terminada

## 📌 Bloqueadas

- [ ] Tarea bloqueada (razón)
```

**Cuándo actualizar**: Al iniciar, completar o bloquear tareas

---

## Casos de Uso

### Caso 1: Inicio de Nueva Feature

```bash
# 1. Iniciar nueva sesión
echo "# Nueva Feature: [nombre]" > temp/current-context/session-notes.md
echo "**Fecha**: $(date +%Y-%m-%d)" >> temp/current-context/session-notes.md

# 2. Documentar objetivo
# Editar session-notes.md con el objetivo

# 3. Crear lista de tareas
# Editar todo.md con las tareas necesarias

# 4. Documentar decisiones arquitectónicas
# A medida que tomas decisiones, documentarlas en decisions.md
```

### Caso 2: Debugging

```bash
# 1. Registrar problema en session-notes.md
# 2. Guardar logs en temp/logs/
# 3. Exportar datos de debug a temp/current-context/artifacts/
# 4. Documentar solución cuando la encuentres
# 5. Actualizar todo.md marcando tarea como completada
```

### Caso 3: Refactoring

```bash
# 1. Documentar razón del refactor en decisions.md
# 2. Listar archivos afectados en todo.md
# 3. Ir marcando progreso en todo.md
# 4. Guardar artifacts intermedios en temp/current-context/artifacts/
# 5. Al finalizar, migrar información importante a docs/
```

### Caso 4: Final de Sesión

```bash
# 1. Revisar session-notes.md y completar secciones pendientes
# 2. Migrar decisiones importantes de decisions.md a docs/architecture/
# 3. Mover artifacts valiosos de temp/ a ubicación permanente
# 4. Limpiar o archivar el current context:

# Opción A: Backup antes de limpiar
mkdir -p docs/sessions
cp -r temp/current-context docs/sessions/$(date +%Y%m%d-%H%M%S)
rm -rf temp/*

# Opción B: Solo limpiar
rm -rf temp/*
mkdir -p temp/current-context/artifacts temp/cache temp/logs
```

---

## Flujo de Trabajo

### Flujo Diario

```
1. Inicio de día
   ├─> Revisar temp/current-context/todo.md
   ├─> Actualizar session-notes.md con objetivo del día
   └─> Identificar tareas prioritarias

2. Durante el trabajo
   ├─> Documentar decisiones en decisions.md
   ├─> Actualizar todo.md con progreso
   ├─> Agregar notas en session-notes.md
   └─> Guardar artifacts temporales

3. Fin de día
   ├─> Completar session-notes.md
   ├─> Revisar y migrar información valiosa a docs/
   ├─> Actualizar todo.md con pendientes para mañana
   └─> (Opcional) Backup del current-context
```

### Flujo de Sprint/Milestone

```
1. Inicio de Sprint
   ├─> Limpiar temp/ del sprint anterior
   ├─> Crear nueva sesión en session-notes.md
   ├─> Cargar objetivos del sprint en todo.md
   └─> Revisar protocolos y configuración

2. Durante el Sprint
   ├─> Mantener current-context actualizado diariamente
   ├─> Documentar todas las decisiones importantes
   ├─> Acumular artifacts en temp/current-context/artifacts/
   └─> Migrar documentación lista a docs/

3. Fin de Sprint
   ├─> Review completo de decisions.md
   ├─> Migrar toda decisión importante a docs/architecture/
   ├─> Archivar session-notes.md completo
   ├─> Backup de artifacts valiosos
   └─> Limpieza completa de temp/
```

---

## Comandos Útiles

### Gestión de temp/

```bash
# Crear estructura inicial
mkdir -p temp/current-context/artifacts temp/cache temp/logs

# Limpiar todo
rm -rf temp/* && mkdir -p temp/current-context/artifacts temp/cache temp/logs

# Backup antes de limpiar
backup_dir="docs/sessions/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"
cp -r temp/current-context/* "$backup_dir/"

# Ver estructura
tree temp/

# Tamaño de temp/
du -sh temp/
du -sh temp/*

# Archivos recientes
find temp/ -type f -mtime -1 -ls

# Limpiar cache antiguo (más de 7 días)
find temp/cache -type f -mtime +7 -delete

# Limpiar logs antiguos (más de 7 días)
find temp/logs -type f -mtime +7 -delete
```

### Trabajo con Current Context

```bash
# Iniciar nueva sesión
cat > temp/current-context/session-notes.md << 'EOF'
# Notas de Sesión

**Fecha de inicio**: $(date +%Y-%m-%d)
**Proyecto**: bmader v1.0.1

## Objetivo de la Sesión
[Definir objetivo]

EOF

# Ver notas de sesión
cat temp/current-context/session-notes.md

# Agregar nota rápida
echo "- $(date +%H:%M) - [Nota]" >> temp/current-context/session-notes.md

# Ver tareas pendientes
grep "\[ \]" temp/current-context/todo.md

# Marcar tarea como completada (manual)
# Editar todo.md y cambiar [ ] por [x]

# Listar artifacts
ls -lht temp/current-context/artifacts/

# Buscar en decisiones
grep -i "keyword" temp/current-context/decisions.md
```

---

## Integración con Agentes

### Variables de Entorno

Los agentes BMad tienen acceso a estas variables (definidas en `bmad.yml`):

```yaml
runtime:
  temp_folder: "temp"
  current_context: "temp/current-context"
  temp_cache: "temp/cache"
  temp_logs: "temp/logs"
```

### Uso en Agentes

Los agentes pueden y deben:

1. **Leer el current context** al iniciar:
   - `temp/current-context/session-notes.md` para entender qué se ha hecho
   - `temp/current-context/decisions.md` para conocer decisiones previas
   - `temp/current-context/todo.md` para ver tareas pendientes

2. **Actualizar el current context** durante ejecución:
   - Agregar notas a `session-notes.md`
   - Documentar decisiones en `decisions.md`
   - Actualizar estado de tareas en `todo.md`

3. **Guardar artifacts** en `temp/current-context/artifacts/`:
   - Análisis generados
   - Diagramas creados
   - Exports de datos
   - Resultados intermedios

4. **Usar cache** en `temp/cache/`:
   - Resultados de análisis costosos
   - Índices generados
   - Datos descargados

5. **Escribir logs** en `temp/logs/`:
   - Logs de ejecución
   - Traces de debugging
   - Output de operaciones

### Ejemplo de Integración

```python
# Ejemplo: Agente Python leyendo current context

import os
from pathlib import Path

# Leer configuración
PROJECT_ROOT = Path("/opt/bmader")
TEMP = PROJECT_ROOT / "temp"
CURRENT_CONTEXT = TEMP / "current-context"

# Leer session notes
session_notes_path = CURRENT_CONTEXT / "session-notes.md"
if session_notes_path.exists():
    with open(session_notes_path) as f:
        context = f.read()
    print(f"Contexto cargado: {len(context)} caracteres")

# Agregar nota
from datetime import datetime
note = f"\n- {datetime.now().strftime('%H:%M')} - Agente ejecutado\n"
with open(session_notes_path, "a") as f:
    f.write(note)

# Guardar artifact
artifact_path = CURRENT_CONTEXT / "artifacts" / "analysis-result.json"
with open(artifact_path, "w") as f:
    json.dump({"resultado": "..."}, f)
```

---

## Mejores Prácticas

### ✅ DO

1. **Actualizar continuamente**: Documenta mientras trabajas, no al final
2. **Ser específico**: Escribe notas claras y detalladas
3. **Usar timestamps**: Indica cuándo ocurrió cada evento
4. **Documentar el "por qué"**: No solo qué hiciste, sino por qué
5. **Migrar información valiosa**: Mueve decisiones importantes a docs/
6. **Limpiar regularmente**: No dejes que temp/ crezca indefinidamente
7. **Usar artifacts/**: Para cualquier archivo generado temporalmente
8. **Backup antes de limpiar**: Si hay información valiosa, guárdala primero

### ❌ DON'T

1. **No versionar temp/**: Ya está en .gitignore, mantenlo así
2. **No almacenar secretos**: Nunca guardes passwords, tokens, etc.
3. **No almacenar código fuente**: El código va en src/, no en temp/
4. **No dejar crecer sin control**: Limpia archivos antiguos
5. **No confiar en persistencia**: temp/ puede limpiarse en cualquier momento
6. **No duplicar documentación**: Si ya está en docs/, no lo copies a temp/
7. **No usar para artifacts finales**: Los resultados finales van a output/ o dist/
8. **No ignorar el current context**: Los agentes deben usarlo

### 📐 Convenciones de Nombres

Para **artifacts**:

```
YYYY-MM-DD-descriptive-name.ext
2025-12-17-api-analysis.json
2025-12-17-architecture-diagram.excalidraw
```

Para **logs**:

```
YYYY-MM-DD-HH-MM-SS-operation.log
2025-12-17-14-30-00-build.log
2025-12-17-15-45-30-test-run.log
```

Para **cache**:

```
operation-name.cache
code-analysis.cache
dependency-graph.cache
```

---

## Troubleshooting

### Problema: temp/ no existe

**Solución**:

```bash
mkdir -p temp/current-context/artifacts temp/cache temp/logs
cp src/templates/current-context/* temp/current-context/
```

### Problema: Archivos de current-context vacíos o inexistentes

**Solución**:

```bash
# Crear desde template o manualmente
touch temp/current-context/{session-notes,decisions,todo}.md
```

### Problema: temp/ crece demasiado

**Solución**:

```bash
# Ver qué ocupa espacio
du -sh temp/*
du -sh temp/current-context/artifacts/*

# Limpiar selectivamente
find temp/cache -mtime +7 -delete  # Cache viejo
find temp/logs -mtime +14 -delete   # Logs viejos
# Revisar artifacts manualmente
```

### Problema: Pérdida de contexto entre sesiones

**Solución**:

- Implementar backup automático al final del día
- Usar git hooks para recordar backup antes de push
- Migrar información importante a docs/ regularmente

---

## Recursos Adicionales

- **Configuración**: `/opt/bmader/bmad.yml` (sección runtime)
- **Template README**: `/opt/bmader/temp/README.md`
- **Protocolos**: `/opt/bmader/protocols/`
- **Agente Master**: `/opt/bmader/src/src/core/agents/bmad-master.agent.yaml`

---

## Conclusión

El sistema de carpeta temporal y current context es fundamental para:

- Mantener el estado de trabajo organizado
- Facilitar la colaboración entre agentes y desarrolladores
- Documentar decisiones importantes
- Gestionar artifacts temporales sin ensuciar el repositorio

**Recuerda**: temp/ es temporal, pero el current context es tu memoria de trabajo. Úsalo activamente.

---

**Versión**: 1.0.0
**Última actualización**: 2025-12-17
**Autor**: BMad Team
