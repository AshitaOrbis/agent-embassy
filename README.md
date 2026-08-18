# Agent Embassy

> **Note: This project is archived.** The embassy pattern demonstrated several useful hardening layers (Docker isolation, an egress proxy, and output validation), but those layers do not form a containment primitive or complete agent sandbox. See the [post-mortem blog series](https://ashitaorbis.com/posts/033-the-container-that-forgot-to-stop) for what we learned. For active alternatives, see [Docker AI Sandboxes](https://docs.docker.com/ai/sandbox/) and [AISI Sandboxing](https://github.com/UKGovernmentBEIS/aisi-sandboxing).

Archived Docker Compose **hardening template** for running AI agents you broadly trust. Supply an agent image and its real entrypoint, then configure the operative controls directly. It applies defense-in-depth (egress allowlist, dropped capabilities, read-only root filesystem, resource limits, and best-effort output validation).

> **Not a containment boundary for actively malicious code.** This is layered hardening on ordinary Docker isolation, not a security sandbox. An adversarial agent has documented paths to defeat it: DNS-based egress can bypass the proxy on some Docker/Moby versions; the output validator observes files rather than gating them (symlink/path-traversal/validate-then-mutate/fail-open bypasses exist); and writable host bind mounts are reachable outside the "controlled" channel. For untrusted or potentially-compromised agents use a real isolation layer (gVisor, Firecracker/Kata, or a network-firewalled VM). Treat this repo as a starting pattern to harden, not a guarantee.

## Why

AI agents need internet access to be useful but unrestricted access is dangerous. Agent Embassy implements the "embassy pattern": your agent lives in a controlled environment where it can communicate with the outside world only through supervised channels.

**The problem:** You want to run an AI agent that calls APIs, browses the web, or processes data. But you don't want it reading your SSH keys, exfiltrating data to arbitrary endpoints, or consuming unlimited resources.

**The solution:** Three containers working together:

```
                    ┌─────────────┐
  inbox/ ──ro──────>│             │──────rw──> outbox/
  (tasks)           │    Agent    │            (results)
                    │  Container  │
                    │             │
                    └──────┬──────┘
                           │ HTTP/HTTPS only
                    ┌──────┴──────┐
                    │   Egress    │──────> Allowed domains only
                    │    Proxy    │   X──> Everything else blocked
                    └─────────────┘

  outbox/ ──rw─────>┌─────────────┐
                    │  Validator  │──────> outbox/rejected/
                    └─────────────┘
```

- **Agent container**: Read-only filesystem, dropped capabilities, resource limits, no direct internet
- **Egress proxy**: Squid-based allowlist. Agent can only reach domains you approve.
- **Validator**: Watches outbox for sensitive data leaks, oversized files, and policy violations

## Quick Start

```bash
# 1. Clone
git clone https://github.com/AshitaOrbis/agent-embassy.git
cd agent-embassy

# 2. Configure
cp .env.example .env
# Set AGENT_IMAGE to an image that already contains your agent program
# Set AGENT_COMMAND to that program's entrypoint inside the image
# Edit config/squid.conf to allowlist your agent's API endpoints
# Edit config/validation-rules.json for observational output checks
# config/agent.yml is optional metadata for the agent itself; Compose ignores it

# 3. Create directories
mkdir -p inbox outbox logs agent-state

# 4. Run
docker compose up -d

# 5. Submit a task
echo '{"type": "task", "prompt": "Hello, agent"}' > inbox/task-001.json

# 6. Check results
ls outbox/
```

## Configuration

### Agent Definition (`config/agent.yml`)

This file is optional metadata mounted into the agent container. Docker Compose does **not** read it to configure policy:

```yaml
agent:
  name: my-research-agent
  description: "Searches papers and summarizes findings"
```

Set image, command, and resource limits in `.env`; edit `config/squid.conf` for egress destinations; and edit `config/validation-rules.json` for observational output checks.

### Egress Proxy (`config/squid.conf`)

Control exactly which domains your agent can reach. By default, everything is blocked. Add domains explicitly:

```
acl allowed_hosts dstdomain api.openai.com
acl allowed_hosts dstdomain .github.com
```

### Output Validation (`config/validation-rules.json`)

Observational checks over new top-level, non-hidden outbox files. Directories
and dotfiles are skipped, and files inside subdirectories are never examined —
this does not scan everything the agent writes:

```json
{
  "max_file_size": 5242880,
  "reject_symlinks": true,
  "blocked_patterns": [
    "-----BEGIN.*PRIVATE KEY-----",
    "sk-[a-zA-Z0-9]{48}",
    "AKIA[0-9A-Z]{16}"
  ]
}
```

The validator exits on a missing or malformed policy instead of silently selecting weaker defaults. Rejected files are moved to `outbox/rejected/` with a JSON report explaining why.

### Environment Variables (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_IMAGE` | Required | Docker image that already contains your agent program |
| `AGENT_COMMAND` | Required | Entrypoint present inside `AGENT_IMAGE` |
| `AGENT_MEM_LIMIT` | `2G` | Memory limit |
| `AGENT_CPUS` | `2` | CPU limit |
| `AGENT_PIDS_LIMIT` | `100` | Process limit (prevents fork bombs) |

**Credential injection is not implemented by this template.** Compose defines no
Docker secrets and mounts no credentials path into the agent container. If your
agent needs API keys, you must design and review your own injection mechanism;
this repository does not document one.

## Security Model (hardening layers, best-effort)

These layers raise the cost of misbehavior for a *broadly-trusted* agent. They are **not** guarantees against adversarial code — see the caveats column.

| Layer | Hardening | Adversarial caveat |
|-------|-----------|--------------------|
| **Filesystem** | Read-only rootfs, tmpfs for temp files | Writable host bind mounts (outbox/logs/state) are still reachable |
| **Capabilities** | All Linux capabilities dropped | Container isolation only; not a syscall sandbox |
| **Privileges** | `no-new-privileges`, non-root user | — |
| **Network** | Internal network + egress proxy allowlist | DNS-based egress can bypass the proxy on some Docker/Moby versions |
| **Resources** | Memory, CPU, and PID limits | Disk/inode exhaustion via host mounts not bounded |
| **Output** | Host-side validation of agent output | **Observational, not a gate** — symlink, path-traversal, validate-then-mutate, and fail-open bypasses exist |
| **Communication** | Inbox read-only, outbox write-only (agent's view) | — |

### What the agent CAN do
- Read tasks from inbox; write results to outbox
- Call APIs on allowlisted domains (through egress proxy)
- Use /tmp for scratch space (tmpfs, size-limited)

### What this is designed to resist (for trusted agents — defeatable by adversarial code)
- Casual host-filesystem access, non-allowlisted egress, privilege escalation
- Fork bombs and memory exhaustion (PID/mem limits)
- Accidental secret leakage and oversized/symlinked outbox files (best-effort validation)

A determined or compromised agent can defeat each of these — see the top-of-README note and the [post-mortem](https://ashitaorbis.com/posts/033-the-container-that-forgot-to-stop).

## Examples

See the `examples/` directory for metadata and operative Squid-policy examples. Metadata files alone do not configure Compose:

- `examples/openai-agent/` - Agent that calls OpenAI API
- `examples/web-scraper/` - Agent that scrapes allowlisted sites

## Project Structure

```
agent-embassy/
├── docker-compose.yml          # Three-container orchestration
├── config/
│   ├── agent.yml               # Optional metadata; not Compose policy
│   ├── squid.conf              # Egress proxy allowlist
│   └── validation-rules.json   # Observational output checks
├── scripts/
│   └── validate_outbox.py      # Host-side output validator
├── inbox/                      # Tasks → Agent (read-only for agent)
├── outbox/                     # Agent → Host (observed, not gated)
│   └── rejected/               # Failed validation
├── logs/                       # Audit trail
├── agent-state/                # Persistent agent state
├── examples/                   # Example agent configurations
├── .env.example                # Environment template
├── LICENSE                     # MIT
└── README.md
```

## How It Works

1. **You** write task files to `inbox/`
2. **Agent** reads tasks, does work, writes results to `outbox/`
3. **Egress proxy** applies its allowlist to traffic that reaches the proxy
4. **Validator** observes new output files and checks them against its policy
5. **You** independently decide whether an output is safe to consume

These are best-effort hardening layers, not guarantees: the agent can reach writable host bind mounts, DNS behavior can bypass the proxy on affected Docker/Moby versions, and the validator is observational rather than a gate, so outputs can be consumed, mutated, or missed before validation.

## Acknowledgements

Born from running AI agents in production at [Ashita Orbis](https://ashitaorbis.com). The pattern emerged from needing to give an AI agent internet access without giving it the keys to the kingdom.

## License

MIT
