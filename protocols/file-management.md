# Protocolo de Gestión de Archivos

## 🚫 REGLAS ABSOLUTAS - NO NEGOCIABLES

### PROHIBIDO: Crear Archivos Innecesarios

**NUNCA** crear archivos para:

- ❌ Confirmar que una tarea está completa
- ❌ Marcar que algo se hizo
- ❌ Reportar status de operaciones
- ❌ Crear "recibos" o "confirmaciones" de trabajo
- ❌ Hacer tracking de progreso fuera de temp/
- ❌ Documentar cada paso realizado
- ❌ Crear archivos .done, .complete, .finished, .success, etc.
- ❌ Crear logs de ejecución fuera de temp/logs/
- ❌ Crear summaries, reports, o status fuera de temp/

### EJEMPLOS DE MIERDA QUE NO DEBES CREAR:

```
❌ SETUP-COMPLETE.md
❌ TASK-FINISHED.md
❌ OPERATION-SUCCESS.txt
❌ STATUS-REPORT.md
❌ INSTALLATION-COMPLETE.md
❌ CONFIGURATION-DONE.md
❌ .setup-complete
❌ .task-done
❌ summary.md
❌ report.md
❌ status.txt
```

### ✅ LO ÚNICO QUE SE PUEDE CREAR

**SOLO** crear archivos cuando sean:

1. **Código fuente funcional**: Archivos que ejecutan o definen funcionalidad
   - ✅ `src/module.py`
   - ✅ `lib/utils.js`
   - ✅ `components/Button.tsx`

2. **Configuración necesaria**: Archivos de configuración del proyecto
   - ✅ `package.json`
   - ✅ `tsconfig.json`
   - ✅ `.eslintrc`
   - ✅ `bmad.yml`

3. **Documentación permanente**: Solo si el usuario lo pide explícitamente
   - ✅ `docs/architecture.md` (si el usuario lo pidió)
   - ✅ `README.md` (si el usuario lo pidió)
   - ⚠️ NUNCA crear docs/ si no te lo piden

4. **Archivos temporales**: SOLO en temp/
   - ✅ `temp/current-context/session-notes.md`
   - ✅ `temp/logs/operation.log`
   - ✅ `temp/cache/analysis.json`
   - ✅ `temp/current-context/artifacts/result.txt`

5. **Tests**: Cuando sean parte del código
   - ✅ `tests/test_module.py`
   - ✅ `__tests__/component.test.tsx`

---

## 📍 DÓNDE PONER CADA COSA

### Información Temporal → temp/

```
temp/
├── current-context/
│   ├── session-notes.md        ← Notas de la sesión AQUÍ
│   ├── decisions.md            ← Decisiones temporales AQUÍ
│   ├── todo.md                 ← Tareas AQUÍ
│   └── artifacts/              ← Resultados temporales AQUÍ
├── cache/                      ← Cache AQUÍ
└── logs/                       ← Logs AQUÍ
```

### Código y Configuración → src/, config/, etc.

```
src/                            ← Código fuente
config/                         ← Configuración
tests/                          ← Tests
```

### Documentación Permanente → docs/ (SOLO SI EL USUARIO LO PIDE)

```
docs/                           ← SOLO cuando el usuario explícitamente lo pida
```

---

## 🎯 WORKFLOW CORRECTO

### Cuando terminas una tarea:

```
❌ INCORRECTO:
1. Terminar tarea
2. Crear archivo TASK-COMPLETE.md
3. Escribir resumen en el archivo

✅ CORRECTO:
1. Terminar tarea
2. Actualizar temp/current-context/todo.md (marcar como completada)
3. Agregar nota en temp/current-context/session-notes.md
4. Responder al usuario directamente
```

### Cuando configuras algo:

```
❌ INCORRECTO:
1. Configurar sistema
2. Crear SETUP-COMPLETE.md
3. Listar lo que se hizo

✅ CORRECTO:
1. Configurar sistema
2. Actualizar temp/current-context/session-notes.md
3. Responder al usuario directamente con resumen
```

### Cuando generas un análisis:

```
❌ INCORRECTO:
1. Hacer análisis
2. Crear analysis-report.md en la raíz

✅ CORRECTO:
1. Hacer análisis
2. Guardar en temp/current-context/artifacts/YYYY-MM-DD-analysis.md
3. Responder al usuario con los hallazgos
```

---

## 💬 COMUNICACIÓN CON EL USUARIO

### REGLA DE ORO:

**Responde directamente al usuario en lugar de crear archivos.**

```
❌ MAL:
- Crear STATUS.md
- Crear SUMMARY.md
- Crear REPORT.md
- Decir "He creado un archivo con el resumen"

✅ BIEN:
- Responder directamente con el resumen
- Si es largo, poner en temp/current-context/artifacts/ y responder con resumen
- Solo crear archivo si el usuario específicamente lo pide
```

---

## 🔍 CHECKLIST ANTES DE CREAR UN ARCHIVO

Antes de crear cualquier archivo, pregúntate:

1. **¿Es código funcional?**
   - NO → No lo crees, usa temp/ o responde al usuario
   - SÍ → Créalo en src/, lib/, etc.

2. **¿Es configuración del proyecto?**
   - NO → No lo crees, usa temp/ o responde al usuario
   - SÍ → Créalo (package.json, tsconfig.json, etc.)

3. **¿El usuario lo pidió explícitamente?**
   - NO → No lo crees, usa temp/ o responde al usuario
   - SÍ → Créalo donde el usuario dijo

4. **¿Es temporal/tracking/status?**
   - SÍ → DEBE ir en temp/, NUNCA en la raíz o docs/
   - NO → Continuar checklist

5. **¿Puedes responder directamente al usuario?**
   - SÍ → Responde, NO crees archivo
   - NO → Usa temp/current-context/artifacts/

---

## 🚨 VIOLACIONES COMUNES Y SU FIX

### Violación 1: Crear archivos de confirmación

```
❌ Crear: AGENTS-INSTALLED.md
✅ Fix: Actualizar temp/current-context/session-notes.md
```

### Violación 2: Crear summaries después de tareas

```
❌ Crear: SETUP-SUMMARY.md
✅ Fix: Responder al usuario directamente
```

### Violación 3: Crear documentación no solicitada

```
❌ Crear: docs/installation-guide.md (sin que lo pidan)
✅ Fix: Solo crear si el usuario lo pide explícitamente
```

### Violación 4: Crear archivos de status

```
❌ Crear: operation-status.json
✅ Fix: temp/current-context/artifacts/operation-status.json
```

### Violación 5: Crear logs fuera de temp/

```
❌ Crear: build.log en la raíz
✅ Fix: temp/logs/build.log
```

---

## 📋 RESUMEN EJECUTIVO

### SOLO 5 RAZONES VÁLIDAS PARA CREAR UN ARCHIVO:

1. **Es código que ejecuta funcionalidad**
2. **Es configuración necesaria del proyecto**
3. **El usuario lo pidió explícitamente**
4. **Es un test**
5. **Es temporal y va en temp/**

### TODO LO DEMÁS:

- Responde al usuario directamente
- Usa temp/current-context/ para tracking
- Usa temp/logs/ para logs
- Usa temp/cache/ para cache
- Usa temp/current-context/artifacts/ para resultados temporales

---

## ⚠️ CONSECUENCIAS DE VIOLAR ESTE PROTOCOLO

Si un agente crea archivos innecesarios:

1. El proyecto se ensucia con basura
2. El usuario se molesta
3. Se pierde confianza en el sistema
4. Hay que limpiar manualmente

**NO SEAS ESE AGENTE.**

---

## ✅ EJEMPLOS DE BUEN COMPORTAMIENTO

### Ejemplo 1: Instalación de dependencias

```
Usuario: "Instala las dependencias"

Agente:
1. Ejecuta npm install
2. Actualiza temp/current-context/session-notes.md:
   "- 14:30 - Instaladas dependencias con npm install"
3. Responde: "✅ Dependencias instaladas correctamente"

NO crea: INSTALLATION-COMPLETE.md
```

### Ejemplo 2: Configuración de temp/

```
Usuario: "Configura temp/"

Agente:
1. Crea estructura temp/
2. Actualiza bmad.yml
3. Actualiza temp/current-context/session-notes.md con lo hecho
4. Responde con resumen al usuario

NO crea: SETUP-SUMMARY.md, TEMP-CONFIGURED.md, etc.
```

### Ejemplo 3: Análisis de código

```
Usuario: "Analiza el código"

Agente:
1. Analiza el código
2. Guarda análisis detallado en: temp/current-context/artifacts/2025-12-17-code-analysis.md
3. Responde al usuario con resumen de hallazgos

NO crea: code-analysis-report.md en la raíz o docs/
```

---

## 🎓 FILOSOFÍA

### Principio Central:

**"Si no es código, configuración, o fue pedido explícitamente, NO lo crees."**

### Corolarios:

1. **temp/ es para todo lo temporal**: Sin excepciones
2. **Responder > Crear archivo**: Siempre que sea posible
3. **Usuario primero**: Solo crear lo que el usuario pide
4. **Minimalismo**: Menos archivos = mejor

---

## 📚 CASOS ESPECIALES

### "¿Y si quiero documentar lo que hice?"

→ `temp/current-context/session-notes.md`

### "¿Y si el proceso generó un log?"

→ `temp/logs/YYYY-MM-DD-HH-MM-SS-operation.log`

### "¿Y si hice un análisis importante?"

→ `temp/current-context/artifacts/YYYY-MM-DD-analysis.md`
→ Responder al usuario con resumen
→ Si es permanente Y el usuario lo pide, moverlo a docs/

### "¿Y si quiero trackear decisiones?"

→ `temp/current-context/decisions.md`

### "¿Y si quiero listar tareas completadas?"

→ `temp/current-context/todo.md`

### "¿Y si el usuario NO pidió docs pero creo que sería útil?"

→ NO lo crees
→ Sugiere al usuario: "¿Quieres que documente esto en docs/?"
→ Solo créalo si dice que sí

---

## 🔥 REGLA DE FUEGO

**Antes de crear cualquier archivo fuera de temp/, pregúntate:**

### "¿Me despedirían por crear este archivo?"

- Si es basura innecesaria: **SÍ** → No lo crees
- Si es código funcional: **NO** → Créalo
- Si no estás seguro: **USA TEMP/**

---

**Este protocolo es obligatorio para todos los agentes BMad.**

**Sin excepciones.**

**Sin negociaciones.**

---

**Versión**: 1.0.0
**Fecha**: 2025-12-17
**Prioridad**: 🔥 CRÍTICA
**Scope**: Todos los agentes
