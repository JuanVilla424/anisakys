# Template Usage Guide

This guide explains how to use BMader as a template for your own projects.

## Quick Start

### Method 1: Use as GitHub Template

If this repository is set up as a GitHub template:

1. Click "Use this template" button on GitHub
2. Create your new repository
3. Clone your new repository
4. Follow [Initial Setup](#initial-setup)

### Method 2: Manual Copy

1. **Create your new project directory**

   ```bash
   mkdir my-new-project
   cd my-new-project
   git init
   ```

2. **Copy template files from BMader**

   ```bash
   # Copy essential directories
   cp -r /path/to/bmader/.ai .
   cp -r /path/to/bmader/.claude .
   cp -r /path/to/bmader/.github .
   cp -r /path/to/bmader/protocols .
   cp -r /path/to/bmader/docs .

   # Copy configuration files
   cp /path/to/bmader/bmad.yml .
   cp /path/to/bmader/.bumpversion.cfg .
   cp /path/to/bmader/.gitignore .
   cp /path/to/bmader/pyproject.toml .  # If using Python
   cp /path/to/bmader/requirements.txt .  # If using Python
   ```

3. Follow [Initial Setup](#initial-setup)

## Initial Setup

After copying the template, configure it for your project:

### 1. Update bmad.yml

Edit `bmad.yml` and update these fields:

```yaml
project:
  name: "your-project-name" # Change this
  version: "0.1.0" # Start version
  description: "Your description" # Change this
  author: "Your Name" # Change this

structure:
  root: "/path/to/your/project" # Change this

runtime:
  project_name: "your-project-name" # Change this
  user_name: "Your Name" # Change this
  communication_language: "english" # Adjust if needed
```

### 2. Update Version Configuration

Edit `.bumpversion.cfg`:

```ini
[bumpversion]
current_version = 0.1.0  # Match bmad.yml version
commit = True
tag = False

# Add or remove files based on your project
[bumpversion:file:pyproject.toml]
[bumpversion:file:package.json]  # If using Node.js
```

### 3. Update Python Configuration (if applicable)

Edit `pyproject.toml`:

```toml
[tool.poetry]
name = "your-project-name"
version = "0.1.0"
description = "Your description"
authors = ["Your Name <your.email@example.com>"]
```

### 4. Update Node Configuration (if applicable)

Create or edit `package.json`:

```json
{
  "name": "your-project-name",
  "version": "0.1.0",
  "description": "Your description",
  "author": "Your Name"
}
```

### 5. Add BMad Method Submodule

```bash
git submodule add -b main https://github.com/bmad-code-org/BMAD-METHOD.git src
git submodule update --init --recursive
```

### 6. Optional: Add Scripts Submodule

```bash
git submodule add -b main https://github.com/JuanVilla424/scripts.git scripts
```

Update `bmad.yml` if you skip this:

```yaml
submodules:
  - name: "src"
    url: "https://github.com/bmad-code-org/BMAD-METHOD.git"
    branch: "main"
    description: "BMad Method core framework"
  # Remove scripts section if not using
```

### 7. Create Branch Structure

```bash
# Create and push all branches
git checkout -b dev
git add .
git commit -m "Initial commit from bmader template"
git push -u origin dev

git checkout -b test
git push -u origin test

git checkout -b prod
git push -u origin prod

git checkout -b main
git push -u origin main

# Set main as default branch on GitHub

# Go back to dev for development
git checkout dev
```

### 8. Configure GitHub Secrets

If using GitHub Actions workflows that require secrets:

1. Go to GitHub repository Settings → Secrets and variables → Actions
2. Add required secrets:
   - `ACCESS_TOKEN` (for submodule access if using private repos)
   - Any other workflow-specific secrets

### 9. Install Dependencies

```bash
# Install BMad Method
npx bmad-method@alpha install

# Install Python dependencies (if applicable)
pip install -r requirements.txt

# Install Node dependencies (if applicable)
npm install
```

### 10. Initialize BMad

Load a BMad agent and run:

```
*workflow-init
```

## Customization Options

### Add Custom Protocols

1. Create a new protocol file:

   ```bash
   touch protocols/code-style.md
   ```

2. Write the protocol (see [Protocol Template](#protocol-template))

3. Update `bmad.yml`:

   ```yaml
   protocols:
     versioning:
       path: "protocols/versioning.md"
       description: "Versioning protocol"
       required: true
       scope: "all"

     code-style: # New protocol
       path: "protocols/code-style.md"
       description: "Code formatting and style guidelines"
       required: true
       scope: "development"
   ```

4. Update `.ai/agent-protocol-loader.md` to reference the new protocol

### Add Custom AI Instructions

1. Create a new file in `.ai/`:

   ```bash
   touch .ai/custom-instructions.md
   ```

2. Write your instructions

3. Update `.ai/README.md` to document the new file

### Modify Workflows

1. Edit or add workflows in `.github/workflows/`
2. Update `bmad.yml` in the `ci_cd.workflows` section
3. Test the workflows in dev branch first

### Add Project Documentation

1. Create markdown files in `docs/`
2. Update `docs/README.md` table of contents
3. Link from main README if needed

## Protocol Template

When creating new protocols, use this template:

```markdown
# Protocol Name

## Purpose

Brief description of what this protocol governs.

## Scope

Who/what must follow this protocol:

- All agents
- Developers
- Specific domains (backend, frontend, etc.)

## Guidelines

### Rule 1: Title

Description and examples.

### Rule 2: Title

Description and examples.

## Examples

### Good Example

\`\`\`
Example code or process
\`\`\`

### Bad Example

\`\`\`
Counter-example
\`\`\`

## Exceptions

When and how exceptions are allowed.

## Enforcement

How compliance is checked:

- Automated tools
- Code review
- CI/CD checks

## Related Protocols

Links to related protocols.

## References

External resources and documentation.
```

## Testing the Template

Before using the template for a real project, test it:

1. **Create a test repository**

   ```bash
   mkdir test-bmader-template
   cd test-bmader-template
   ```

2. **Copy template and configure** as described above

3. **Test version bumping**

   ```bash
   git checkout dev
   bump2version patch
   git push
   # Verify GitHub Action runs
   # Verify PR is created to test branch
   ```

4. **Test BMad integration**
   - Load BMad agents
   - Run workflows
   - Verify protocols are accessible

5. **Test CI/CD**
   - Push commits
   - Create PRs
   - Verify all workflows run

## Common Customization Scenarios

### Scenario 1: Python-Only Project

Remove:

- Node.js workflow references from `bmad.yml`
- `[bumpversion:file:frontend/package.json]` from `.bumpversion.cfg`
- `.github/workflows/node.yml`

Keep:

- Python configurations
- `pyproject.toml`
- `.github/workflows/python.yml`

### Scenario 2: Node.js-Only Project

Remove:

- Python workflow references from `bmad.yml`
- `[bumpversion:file:pyproject.toml]` from `.bumpversion.cfg`
- `[bumpversion:file:backend/pyproject.toml]` from `.bumpversion.cfg`
- `.github/workflows/python.yml`
- `pyproject.toml`
- `requirements.txt`

Keep:

- `package.json`
- `.github/workflows/node.yml`

Update `.bumpversion.cfg`:

```ini
[bumpversion]
current_version = 0.1.0
commit = True
tag = False

[bumpversion:file:package.json]
```

### Scenario 3: Monorepo with Multiple Services

Keep all configurations and add:

```yaml
# In bmad.yml
structure:
  root: "/path/to/project"
  services:
    backend: "services/backend"
    frontend: "services/frontend"
    api: "services/api"
```

Update `.bumpversion.cfg`:

```ini
[bumpversion]
current_version = 0.1.0
commit = True
tag = False

[bumpversion:file:pyproject.toml]
[bumpversion:file:services/backend/pyproject.toml]
[bumpversion:file:services/frontend/package.json]
[bumpversion:file:services/api/package.json]
```

### Scenario 4: Private Submodules

If using private repositories for submodules:

1. Add GitHub secret `ACCESS_TOKEN` with repo access
2. Workflows will use this automatically (already configured in `version-controller.yml`)

## Maintenance

### Keeping Template Updated

To get updates from the BMader template:

1. **Add BMader as a remote**

   ```bash
   git remote add template https://github.com/your-org/bmader.git
   ```

2. **Fetch updates**

   ```bash
   git fetch template
   ```

3. **Merge updates selectively**

   ```bash
   # Check what changed
   git diff template/main -- protocols/
   git diff template/main -- .github/workflows/

   # Merge specific files
   git checkout template/main -- protocols/versioning.md
   git checkout template/main -- .github/workflows/version-controller.yml
   ```

4. **Resolve conflicts and commit**
   ```bash
   git add .
   git commit -m "Update from bmader template"
   ```

## Support

- Check [docs/README.md](README.md) for general documentation
- Review [protocols/versioning.md](../protocols/versioning.md) for versioning issues
- See BMad Method documentation in `src/README.md`

## Checklist

Use this checklist when setting up a new project from the template:

- [ ] Copied all necessary files and directories
- [ ] Updated `bmad.yml` with project details
- [ ] Updated `.bumpversion.cfg` with correct version
- [ ] Updated `pyproject.toml` (if using Python)
- [ ] Updated `package.json` (if using Node.js)
- [ ] Added BMad Method submodule
- [ ] Created all four branches (dev, test, prod, main)
- [ ] Configured GitHub secrets (if needed)
- [ ] Installed dependencies
- [ ] Tested version bumping workflow
- [ ] Tested BMad agent integration
- [ ] Verified CI/CD workflows run
- [ ] Updated documentation with project specifics
- [ ] Added project-specific protocols (if any)
- [ ] Removed unnecessary files for your stack
