# Agent Protocol Loader Configuration

## Purpose

This configuration ensures all BMad agents automatically load the project protocols at runtime.

## Protocol Loading Instructions

### For All BMad Agents

When initializing or being invoked, ALL agents MUST:

1. **Load the bmad.yml configuration**
   - Path: `{project-root}/bmad.yml`
   - Extract protocol definitions from the `protocols` section
   - Identify which protocols are marked as `required: true`

2. **Load required protocols**
   - For each protocol with `scope: "all"` or matching the agent's domain
   - Read the protocol file from the path specified
   - Keep protocol content in working memory for reference during execution

3. **Follow protocol principles**
   - Load resources at runtime, never pre-load before being invoked
   - Apply protocol guidelines to all decisions and actions
   - Reference protocols when making architectural or procedural decisions

## Required Protocols (Auto-load)

All agents must load these protocols automatically:

### 1. Versioning Protocol

- **Path**: `protocols/versioning.md`
- **When to load**: At agent initialization
- **Scope**: All agents
- **Key points to remember**:
  - Semantic versioning: MAJOR.MINOR.PATCH
  - Branch flow: dev → test → prod → main
  - Never manually tag or bump versions
  - Always follow the automated workflow
  - Use bump2version for version increments

## Protocol Loading Sequence

```
1. Agent receives invocation
2. Load {project-root}/bmad.yml
3. Parse protocols section
4. For each protocol where required=true:
   - Read protocol file
   - Add to agent context
   - Mark as loaded
5. Begin agent tasks with protocols in context
```

## Implementation for Custom Agents

If creating custom agents, include this in the agent definition:

```yaml
agent:
  critical_actions:
    - "Load {project-root}/bmad.yml configuration"
    - "Load all required protocols from protocols/ directory"
    - "Apply versioning protocol to all version-related decisions"
    - "Reference protocols when making procedural decisions"
```

## Verification

Agents can verify protocol loading by:

1. Confirming protocols are accessible in memory
2. Referencing protocol content when relevant to task
3. Following protocol guidelines in decision-making

## Adding New Protocols

When new protocols are added to the `protocols/` directory:

1. Update `bmad.yml` in the `protocols` section
2. Define: path, description, required status, scope
3. Document the protocol's purpose in its markdown file
4. Agents will automatically load it on next invocation (if required=true)

## Example Protocol Reference

When an agent needs to make a version-related decision:

```
Agent thought process:
"I need to bump the version. Let me check the versioning protocol..."
[Loads protocols/versioning.md from memory]
"According to the protocol, I should use bump2version and follow
the dev → test → prod → main flow. I will NOT manually create tags."
```

## Protocol Categories (Future)

As more protocols are added, they may be categorized:

- **Core Protocols**: versioning, project-structure, git-workflow
- **Development Protocols**: code-style, testing, documentation
- **Communication Protocols**: commit-messages, pr-descriptions, changelogs
- **Deployment Protocols**: ci-cd, release-process, rollback

## Notes

- Protocols are living documents that can be updated
- Agents should always use the latest version of protocols
- If a protocol conflicts with an agent's base instructions, the protocol takes precedence for project-specific decisions
- Runtime loading ensures protocols are always current
