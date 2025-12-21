# Protocols Directory

This directory contains shared development protocols that all team members and AI agents must follow.

## What are Protocols?

Protocols are standardized guidelines and procedures that ensure:

- Consistency across the project
- Best practices compliance
- Team alignment
- Automated workflow efficiency
- AI agent coordination

## How Protocols Work

### For AI Agents

All BMad agents and AI assistants (Claude Code, Cursor, etc.) are configured to:

1. Load protocols automatically at runtime
2. Follow protocol guidelines in all decisions
3. Reference protocols when making procedural choices

Configuration for automatic loading:

- Defined in `bmad.yml` in the `protocols` section
- Instructions in `.ai/agent-protocol-loader.md`
- Context provided in `.claude/project-context.md`

### For Developers

Developers should:

1. Read relevant protocols before starting work
2. Follow protocol guidelines in day-to-day tasks
3. Suggest updates when processes evolve
4. Ensure code and practices comply with protocols

## Available Protocols

### 1. [Versioning Protocol](versioning.md)

**Status**: ✅ Active | **Required**: Yes | **Scope**: All

Defines the semantic versioning system and automated workflow for managing versions across branches.

**Key Topics**:

- Semantic versioning (MAJOR.MINOR.PATCH)
- Branch flow: dev → test → prod → main
- Automated version bumping with bump2version
- GitHub Actions integration
- Tag naming conventions
- Pull request automation
- Submodule synchronization

**When to Use**:

- Before bumping any version
- When creating releases
- When merging between branches
- When configuring CI/CD

## Protocol Compliance

### AI Agent Compliance

AI agents check protocols by:

- Loading from `bmad.yml` configuration
- Reading protocol files at runtime
- Referencing protocols in decision-making
- Applying protocol rules automatically

### Developer Compliance

Developers ensure compliance through:

- Reading protocols before relevant tasks
- Following documented procedures
- Code review (checking protocol adherence)
- CI/CD automated checks

## Adding New Protocols

When creating a new protocol:

### 1. Create the Protocol File

Create a markdown file in this directory:

```bash
touch protocols/your-protocol-name.md
```

### 2. Use the Protocol Template

```markdown
# Protocol Name

## Purpose

Brief description of what this protocol governs.

## Scope

Who/what must follow this protocol.

## Guidelines

Detailed rules and procedures.

## Examples

Good and bad examples.

## Enforcement

How compliance is verified.

## References

Links and resources.
```

### 3. Register in bmad.yml

Add to the `protocols` section:

```yaml
protocols:
  your-protocol:
    path: "protocols/your-protocol-name.md"
    description: "Brief description"
    required: true # or false
    scope: "all" # or specific scope like "development", "deployment"
```

### 4. Update Documentation

- Update this README with protocol details
- Add to `.ai/agent-protocol-loader.md` if needed
- Document in `docs/README.md`

### 5. Announce and Train

- Announce new protocol to team
- Provide examples and training if needed
- Update onboarding materials

## Protocol Categories

As the project grows, protocols may be organized into categories:

### Core Protocols

- **Versioning** - Version management and releases
- Project structure
- Git workflow

### Development Protocols

- Code style and formatting
- Testing requirements
- Documentation standards

### Communication Protocols

- Commit message format
- PR descriptions
- Code review process

### Deployment Protocols

- CI/CD procedures
- Release process
- Rollback procedures

## Protocol Lifecycle

### Creation

1. Identify need for standardization
2. Draft protocol document
3. Review with team
4. Register in bmad.yml
5. Announce and implement

### Maintenance

1. Review protocols periodically
2. Update as processes evolve
3. Ensure accuracy and relevance
4. Archive obsolete protocols

### Deprecation

1. Announce deprecation with timeline
2. Provide migration path
3. Update bmad.yml to mark as deprecated
4. Remove after grace period
5. Move to `protocols/archived/` if needed

## Protocol Governance

### Who Can Create Protocols?

Any team member can propose a protocol:

1. Draft the protocol
2. Open a PR to dev branch
3. Team reviews and discusses
4. Merge when consensus reached

### Who Enforces Protocols?

Everyone enforces protocols:

- **AI Agents**: Automatically follow loaded protocols
- **Developers**: Adhere to protocols in daily work
- **Code Review**: Check compliance during review
- **CI/CD**: Automated checks where possible

### Resolving Conflicts

If a protocol conflicts with project needs:

1. Discuss in team meeting or issue
2. Propose update to protocol
3. Follow standard PR process
4. Update protocol document

## Best Practices

### Writing Protocols

- **Be Clear**: Use simple, unambiguous language
- **Be Specific**: Provide concrete examples
- **Be Practical**: Ensure protocols are actionable
- **Be Concise**: Keep focused on essentials
- **Provide Context**: Explain the "why" not just the "what"

### Using Protocols

- **Read Before Acting**: Check protocols before starting work
- **Ask Questions**: Clarify if protocol is unclear
- **Suggest Improvements**: Protocols should evolve
- **Share Knowledge**: Help others understand protocols

### AI Agent Integration

- **Load at Runtime**: Agents load protocols when invoked
- **Apply Consistently**: Agents follow protocols uniformly
- **Reference Explicitly**: Agents cite protocols in decisions
- **Stay Current**: Agents always use latest protocol version

## Quick Reference

| Protocol                    | Required | Scope | Purpose                         |
| --------------------------- | -------- | ----- | ------------------------------- |
| [Versioning](versioning.md) | ✅ Yes   | All   | Version management and releases |

## Troubleshooting

### Protocol Not Loading in AI Agent

1. Check `bmad.yml` has correct path
2. Verify `required: true` is set
3. Ensure protocol file exists
4. Check `.ai/agent-protocol-loader.md` configuration

### Protocol Conflicts

1. Determine which protocol takes precedence
2. Update conflicting protocol
3. Document exception if needed
4. Communicate change to team

### Protocol Too Vague

1. Add specific examples
2. Provide step-by-step procedures
3. Include diagrams or flowcharts if helpful
4. Link to external resources

## Resources

- [Main Documentation](../docs/README.md)
- [Template Usage Guide](../docs/TEMPLATE-USAGE.md)
- [bmad.yml Configuration](../bmad.yml)
- [AI Agent Loader Config](../.ai/agent-protocol-loader.md)
- [Claude Code Context](../.claude/project-context.md)

## Contributing to Protocols

See [Contributing Guidelines](../README.md#-contributing) for information on proposing new protocols or updating existing ones.

---

**Remember**: Protocols exist to help the team work efficiently and consistently. They should be living documents that evolve with the project. If a protocol doesn't serve the project well, update it!
