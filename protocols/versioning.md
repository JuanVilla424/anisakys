# Protocolo de Versionado

## Visión General

Este protocolo define el sistema de versionado semántico y el flujo de trabajo para gestionar versiones a través de las diferentes ramas del proyecto.

## 🔥 Workflow de Commits (OBLIGATORIO)

### Proceso de Commit Estándar

**TODOS los commits DEBEN seguir este proceso exacto:**

```bash
# 1. Agregar cambios
git add .

# 2. Ejecutar pre-commit hooks
pre-commit run --all-files

# 3. Commit con formato conventional commits (MENSAJE EN INGLÉS)
git commit -m "feat(core): message in lowercase english"

# 4. Push (ejecutar DOS veces por configuración de scripts/)
git push
git push
```

### Formato de Mensajes de Commit

**Formato obligatorio**: `tipo(scope): mensaje en inglés en minúsculas`

- **Mensaje DEBE estar en inglés**
- **Mensaje DEBE estar en minúsculas**
- **DEBE tener tipo y scope**

#### Tipos Permitidos

- **feat**: Nueva funcionalidad
- **fix**: Corrección de bug
- **docs**: Cambios en documentación
- **style**: Formateo, espacios, puntos y comas (sin cambios en código)
- **refactor**: Refactorización de código (sin cambiar funcionalidad)
- **test**: Agregar o modificar tests
- **chore**: Tareas de mantenimiento, configuración, dependencias

#### Scopes Comunes

- **core**: Funcionalidad principal
- **config**: Configuración
- **deps**: Dependencias
- **ci**: CI/CD
- **docs**: Documentación
- **tests**: Tests

#### Ejemplos de Commits Correctos

```bash
git commit -m "feat(core): add user authentication"
git commit -m "fix(api): resolve null pointer in user service"
git commit -m "docs(readme): update installation instructions"
git commit -m "chore(deps): update dependencies"
git commit -m "refactor(core): simplify error handling"
git commit -m "test(auth): add unit tests for login flow"
```

#### Ejemplos de Commits INCORRECTOS

```bash
❌ git commit -m "Added new feature"                    # Sin tipo ni scope
❌ git commit -m "feat: Add User Auth"                  # Sin scope, mayúsculas
❌ git commit -m "FEAT(core): new feature"              # Tipo en mayúsculas
❌ git commit -m "feat(Core): New Feature"              # Scope y mensaje en mayúsculas
❌ git commit -m "feat(core): agregado autenticación"   # En español
```

### ⚠️ IMPORTANTE: git push DOS VECES

**Siempre ejecutar `git push` dos veces**. Esto es requerido por la configuración específica del submódulo `scripts/`.

```bash
git push
git push
```

### Pre-commit Hooks

El proyecto utiliza pre-commit hooks que DEBEN ejecutarse antes de cada commit:

```bash
pre-commit run --all-files
```

Estos hooks verifican:

- Formato de código
- Linting
- Tests básicos
- Configuración correcta

**Si los hooks fallan, NO hacer commit hasta resolver los problemas.**

### Workflow Completo

```bash
# 1. Hacer cambios en el código
# ... editar archivos ...

# 2. Verificar cambios
git status
git diff

# 3. Agregar todos los cambios
git add .

# 4. Ejecutar pre-commit
pre-commit run --all-files

# 5. Si pre-commit pasa, hacer commit (MENSAJE EN INGLÉS)
git commit -m "feat(core): your change description in english"

# 6. Push (DOS VECES)
git push
git push
```

## Sistema de Versionado

### Formato de Versión

El proyecto utiliza **Versionado Semántico** (SemVer): `MAJOR.MINOR.PATCH`

- **MAJOR**: Cambios incompatibles con versiones anteriores
- **MINOR**: Nuevas funcionalidades compatibles con versiones anteriores
- **PATCH**: Correcciones de bugs compatibles con versiones anteriores

### Versión Actual

La versión actual se mantiene en:

- `pyproject.toml` (raíz del proyecto)
- `backend/pyproject.toml` (si existe)
- `frontend/package.json` (si existe)

## Flujo de Ramas

El proyecto sigue un flujo de trabajo de promoción de ramas:

```
dev → test → prod → main
```

### Descripción de Ramas

1. **dev**: Rama de desarrollo activo
   - Aquí se integran todas las nuevas funcionalidades
   - Se realizan pruebas iniciales

2. **test**: Rama de pruebas de integración
   - Se ejecutan pruebas exhaustivas
   - Se valida la integración de funcionalidades

3. **prod**: Rama de pre-producción
   - Ambiente de staging
   - Última validación antes de producción

4. **main**: Rama de producción
   - Código estable y listo para producción
   - Solo recibe código probado y validado

## Proceso de Bump de Versión

### Herramientas

- **bump2version**: Herramienta para incrementar versiones automáticamente
- **GitHub Actions**: Automatización del proceso de versionado

### Configuración

El archivo `.bumpversion.cfg` contiene:

```ini
[bumpversion]
current_version = X.Y.Z
commit = True
tag = False

[bumpversion:file:pyproject.toml]
[bumpversion:file:backend/pyproject.toml]
[bumpversion:file:frontend/package.json]
```

### Comandos de Bump

```bash
# Incrementar PATCH (1.0.0 → 1.0.1)
bump2version patch

# Incrementar MINOR (1.0.0 → 1.1.0)
bump2version minor

# Incrementar MAJOR (1.0.0 → 2.0.0)
bump2version major
```

## Workflow Automatizado

### Trigger

El workflow se activa automáticamente en push a:

- `dev`
- `test`
- `prod`
- `main`

### Proceso

1. **Obtener versión actual**: Lee la versión desde `pyproject.toml`
2. **Obtener mensaje del commit**: Analiza el último commit
3. **Determinar rama siguiente**:
   - `dev` → `test`
   - `test` → `prod`
   - `prod` → `main`
   - `main` → (fin del flujo)

4. **Verificar carácter especial**: Busca el símbolo `→` en el mensaje del commit junto con "Bump version:"
5. **Crear tag**: Si se detecta el bump, crea tag con formato:
   - Para dev/test/prod: `vX.Y.Z-BRANCH_NAME`
   - Para main: `vX.Y.Z`

6. **Crear Pull Request**: Automáticamente crea PR hacia la siguiente rama con formato:
   ```
   🔖 From {rama_actual} → Bump version: vX.Y.Z-{rama_actual} into {rama_siguiente}
   ```

### Tags

Los tags siguen el formato:

- **Ramas intermedias**: `v1.0.0-dev`, `v1.0.0-test`, `v1.0.0-prod`
- **Rama main**: `v1.0.0`

## Integración con Submódulos

El proyecto utiliza submódulos que deben sincronizarse con la rama actual:

```bash
git submodule add -b {BRANCH_NAME} {REPOSITORY_URL}
```

Los submódulos se actualizan automáticamente en el workflow para mantener consistencia entre ramas.

## Dependencias

### Python

```bash
pip install bump2version toml
```

### Archivos Requeridos

- `.bumpversion.cfg`: Configuración de bump2version
- `pyproject.toml`: Archivo principal de versión
- `.github/workflows/version-controller.yml`: Workflow de GitHub Actions

## Mejores Prácticas

1. **No hacer bump manual**: Dejar que el workflow automatizado gestione las versiones
2. **Commits descriptivos**: Usar mensajes claros que indiquen el tipo de cambio
3. **Revisión de PRs**: Siempre revisar los PRs automáticos antes de hacer merge
4. **Tags inmutables**: Nunca modificar o eliminar tags existentes
5. **Flujo lineal**: Seguir siempre el flujo dev → test → prod → main
6. **Sincronización de submódulos**: Asegurar que los submódulos estén en la rama correcta

## Comandos Útiles

```bash
# Ver versión actual
python -c "import toml; print(toml.load('pyproject.toml')['tool']['poetry']['version'])"

# Ver tags
git tag -l

# Ver último commit
git log -1 --pretty=%B

# Actualizar submódulos
git submodule update --remote --merge

# Cambiar rama de submódulo
git config -f .gitmodules submodule.{NAME}.branch {BRANCH_NAME}
git submodule update --remote
```

## Troubleshooting

### El workflow no crea el PR

- Verificar que el mensaje del commit contenga `→` y "Bump version:"
- Confirmar que no existe un PR abierto entre las mismas ramas
- Revisar permisos del GitHub Token

### La versión no se actualiza

- Verificar que `.bumpversion.cfg` esté correctamente configurado
- Confirmar que los archivos listados en la configuración existen
- Revisar que la sintaxis de los archivos sea correcta

### Conflictos en submódulos

- Sincronizar manualmente: `git submodule update --remote --merge`
- Verificar la rama configurada en `.gitmodules`
- Resolver conflictos y hacer commit

## Referencias

- [Semantic Versioning](https://semver.org/)
- [bump2version Documentation](https://github.com/c4urself/bump2version)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
