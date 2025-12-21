# BMader Project Documentation

## Table of Contents

1. [Overview](#overview)
2. [Project Structure](#project-structure)
3. [Getting Started](#getting-started)
4. [Protocols](#protocols)
5. [Using as a Template](#using-as-a-template)
6. [Configuration](#configuration)
7. [CI/CD](#cicd)

## Overview

BMader is a comprehensive template project that integrates:

- **BMad Method** (BMAD-METHOD) as a git submodule
- **Utility Scripts** for automation
- **Protocol System** for consistent development practices
- **AI Agent Configurations** for Claude, BMad, and other AI assistants
- **Automated Versioning** with semantic versioning and branch workflows

This project can be copied to bootstrap new projects with a complete development infrastructure.

## Project Structure

```
/opt/bmader/
├── .ai/                           # AI agent configurations
│   ├── agent-protocol-loader.md  # Protocol loading instructions
│   └── README.md                  # .ai directory documentation
│
├── .claude/                       # Claude Code specific configs
│   ├── project-context.md        # Claude Code context
│   └── README.md                  # .claude directory documentation
│
├── .github/                       # GitHub configuration
│   └── workflows/                 # GitHub Actions workflows
│       ├── version-controller.yml # Automated versioning
│       ├── release-controller.yml # Release automation
│       ├── python.yml             # Python CI
│       ├── ci.yml                 # General CI
│       └── node.yml               # Node.js CI
│
├── docs/                          # Project documentation
│   └── README.md                  # This file
│
├── protocols/                     # Shared protocols
│   └── versioning.md             # Versioning protocol
│
├── src/                          # BMad Method (git submodule)
│   └── [BMAD-METHOD contents]
│
├── scripts/                      # Utility scripts (git submodule)
│   └── [scripts contents]
│
├── bmad.yml                      # Main project configuration
├── .bumpversion.cfg             # Version bump configuration
├── pyproject.toml               # Python project metadata
└── requirements.txt             # Python dependencies
```

## Getting Started

### Prerequisites

- Node.js >= 20.0.0
- Python >= 3.12
- Git

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd bmader
   ```

2. **Initialize submodules**

   ```bash
   git submodule update --init --recursive
   ```

3. **Install BMad Method**

   ```bash
   npx bmad-method@alpha install
   ```

4. **Install Python dependencies**

   ```bash
   pip install -r requirements.txt
   ```

5. **Set up virtual environment (recommended)**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

### First Steps with BMad

Load any BMad agent and run:

```
*workflow-init
```

This will analyze your project and recommend workflows.

## Protocols

Protocols are shared guidelines that all agents and developers should follow.

### Available Protocols

#### 1. Versioning Protocol

- **File**: `protocols/versioning.md`
- **Purpose**: Define semantic versioning and branch workflow
- **Required for**: All agents and developers
- **Key concepts**:
  - Semantic versioning (MAJOR.MINOR.PATCH)
  - Branch flow: dev → test → prod → main
  - Automated PR creation
  - Tag naming conventions

### Using Protocols

AI agents automatically load required protocols when:

- Configured in `bmad.yml` with `required: true`
- Reading from `.ai/agent-protocol-loader.md`

Developers should:

1. Read relevant protocols before starting work
2. Follow protocol guidelines
3. Update protocols when processes change

### Adding New Protocols

1. Create a markdown file in `protocols/`
2. Document the protocol clearly with:
   - Purpose and scope
   - Rules and guidelines
   - Examples
   - Common issues and solutions

3. Update `bmad.yml`:

   ```yaml
   protocols:
     your-protocol:
       path: "protocols/your-protocol.md"
       description: "Brief description"
       required: true
       scope: "all" # or specific scope
   ```

4. Update `.ai/agent-protocol-loader.md` if needed

## Using as a Template

### Copying to a New Project

1. **Copy the structure**

   ```bash
   # Clone or copy these directories/files:
   - .ai/
   - .claude/
   - .github/
   - protocols/
   - docs/
   - bmad.yml
   - .bumpversion.cfg
   ```

2. **Initialize git in new project**

   ```bash
   git init
   ```

3. **Add BMad Method as submodule**

   ```bash
   git submodule add -b main https://github.com/bmad-code-org/BMAD-METHOD.git src
   ```

4. **Update bmad.yml**
   - Change `project.name`
   - Change `project.version` to `0.1.0` or `1.0.0`
   - Change `project.description`
   - Change `project.author`
   - Update `structure.root` path
   - Update `runtime.project_name`
   - Adjust other project-specific settings

5. **Update .bumpversion.cfg**

   ```ini
   [bumpversion]
   current_version = 0.1.0  # or 1.0.0
   ```

6. **Update pyproject.toml** (if using Python)
   - Change name, version, description, authors

7. **Create branches**

   ```bash
   git checkout -b dev
   git checkout -b test
   git checkout -b prod
   git checkout -b main
   ```

8. **Install and configure**
   ```bash
   npx bmad-method@alpha install
   pip install -r requirements.txt
   ```

### What to Customize

| File/Directory     | What to Update                         |
| ------------------ | -------------------------------------- |
| `bmad.yml`         | Project name, version, paths, settings |
| `.bumpversion.cfg` | Initial version                        |
| `pyproject.toml`   | Package metadata                       |
| `protocols/`       | Add project-specific protocols         |
| `docs/`            | Add project documentation              |
| `.ai/`             | Add project-specific AI instructions   |
| `.claude/`         | Update project context                 |

## Configuration

### bmad.yml

Main configuration file with sections:

- **project**: Basic project metadata
- **structure**: Directory paths
- **submodules**: Git submodule definitions
- **protocols**: Protocol definitions and requirements
- **agents**: Agent configuration and protocol loading
- **runtime**: Runtime variables for agents
- **workflows**: Workflow paths
- **versioning**: Version management settings
- **ci_cd**: CI/CD configuration

See `bmad.yml` for detailed documentation of each section.

### Agent Configuration

Agents are configured to automatically load protocols via:

1. `bmad.yml` - Defines which protocols to load
2. `.ai/agent-protocol-loader.md` - Instructions for loading
3. `.claude/project-context.md` - Claude Code specific context

## CI/CD

### GitHub Actions Workflows

#### version-controller.yml

- **Trigger**: Push to dev, test, prod, main
- **Purpose**: Automated version bumping and PR creation
- **Process**:
  1. Detects version bump commits (containing `→` and "Bump version:")
  2. Creates tags (e.g., `v1.0.0-dev`)
  3. Creates PRs to next branch in flow
  4. Manages submodules

#### release-controller.yml

- **Purpose**: Automated release creation
- **Trigger**: Version tags

#### python.yml, node.yml, ci.yml

- **Purpose**: Run tests and linting
- **Trigger**: Push and pull requests

### Versioning Workflow

```
Developer → bump2version patch
          ↓
Commit with version bump
          ↓
Push to dev branch
          ↓
GitHub Action detects bump
          ↓
Creates tag v1.0.1-dev
          ↓
Creates PR: dev → test
          ↓
Merge PR
          ↓
Repeat for test → prod → main
```

## Best Practices

1. **Always read protocols first** before making decisions
2. **Follow the branch flow** for all changes
3. **Let automation handle versions** - don't manual tag or bump
4. **Update documentation** when changing structure
5. **Keep protocols current** - update as processes evolve
6. **Use BMad agents** for complex tasks
7. **Test in dev** before promoting to test
8. **Load submodules** before working with BMad

## Troubleshooting

### Submodules not loading

```bash
git submodule update --init --recursive
```

### Version bump not working

- Check `.bumpversion.cfg` is correct
- Ensure files listed in config exist
- Verify bump2version is installed

### GitHub Actions not running

- Check workflow triggers
- Verify branch names match
- Check GitHub secrets are configured

### Protocols not loading

- Verify paths in `bmad.yml` are correct
- Check protocol files exist
- Ensure agents have access to files

## Additional Resources

- [BMad Method Documentation](./src/README.md)
- [Versioning Protocol](../protocols/versioning.md)
- [BMad Method GitHub](https://github.com/bmad-code-org/BMAD-METHOD)
- [Semantic Versioning](https://semver.org/)

## Contributing

When contributing to this template:

1. Follow all protocols
2. Update documentation
3. Test in a separate project
4. Create PRs following the branch flow
5. Update CHANGELOG.md

## License

See LICENSE file for details.
