# .ai Configuration Directory

This directory contains AI agent configuration and enhancement files for the BMader project.

## Directories

### agents/

Complete development team with 10 specialized AI agents:

- **BMad Master** - Workflow orchestrator
- **PM (John)** - Product Manager
- **Analyst (Mary)** - Business Analyst
- **Architect (Winston)** - System Architect
- **UX Designer (Sally)** - User Experience Designer
- **Scrum Master (Bob)** - Agile facilitator
- **Developer (Amelia)** - Software Engineer
- **Test Architect (Murat)** - Quality & Testing
- **Tech Writer (Paige)** - Documentation specialist
- **Quick Flow Solo Dev (Barry)** - Elite Full-Stack Developer

See [agents/README.md](agents/README.md) for complete team documentation.

## Files

### agent-protocol-loader.md

Configuration that instructs all BMad agents to automatically load project protocols at runtime.

**Key Functions**:

- Defines protocol loading sequence
- Specifies required protocols for all agents
- Provides implementation guidelines for custom agents

## Usage

### For Development

1. **Load an agent** from `agents/` directory in your IDE
2. **Use commands** like `*create-prd`, `*create-architecture`, etc.
3. **Agents automatically load** all protocols from `protocols/`

### For AI Assistants

AI agents (BMad agents, Claude, Cursor, Windsurf, etc.) should read configurations from this directory when:

- Initializing in the project
- Starting new tasks
- Making project-specific decisions

All agents configured here automatically:

- Load `bmad.yml` configuration
- Load required protocols from `protocols/`
- Follow versioning and other project protocols
- Communicate in configured language (default: español)

## Integration with BMad

This configuration extends BMad's core functionality by:

1. Providing ready-to-use development team
2. Adding project-specific protocol requirements
3. Ensuring consistent behavior across all agents
4. Maintaining protocol compliance automatically

## Quick Start

1. **Choose your workflow phase**:
   - Analysis: Mary (Analyst)
   - Planning: John (PM), Sally (UX), Winston (Architect)
   - Implementation: Bob (Scrum Master), Amelia (Developer)
   - Testing: Murat (TEA)
   - Documentation: Paige (Tech Writer)

2. **Load the agent** in your IDE

3. **Execute workflows** using agent commands

See [agents/README.md](agents/README.md) for detailed agent documentation.

## Adding Configurations

When adding new AI configurations:

1. Create a descriptive markdown file
2. Document the purpose and usage clearly
3. Update this README with the new file
4. Reference it in `bmad.yml` if needed
5. Ensure protocol loading is configured
