# Agent Embassy

> **Note: This project is archived.** The embassy pattern proved sound as a containment primitive (Docker isolation, egress proxy, output validation) but insufficient as a complete agent sandboxing solution. See the [post-mortem blog series](https://ashitaorbis.com/posts/033-the-container-that-forgot-to-stop) for what we learned. For active alternatives, see [Docker AI Sandboxes](https://docs.docker.com/ai/sandbox/) and [AISI Sandboxing](https://github.com/UKGovernmentBEIS/aisi-sandboxing).

Turnkey Docker Compose setup for sandboxing AI agents. Drop in your agent, configure allowed domains, run one command. Your agent is isolated with an egress proxy, no host filesystem access, and host-side output validation.

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
# Edit config/agent.yml with your agent's settings
# Edit config/squid.conf to allowlist your agent's API endpoints

# 3. Create directories
mkdir -p inbox outbox logs agent-state secrets

# 4. Run
docker compose up -d

# 5. Submit a task
echo '{"type": "task", "prompt": "Hello, agent"}' > inbox/task-001.json

# 6. Check results
ls outbox/
```

## Configuration

### Agent Definition (`config/agent.yml`)

Define what your agent is, what it can access, and how its output is validated:

```yaml
agent:
  name: my-research-agent
  description: "Searches papers and summarizes findings"

allowed_domains:
  - api.openai.com
  - api.semanticscholar.org
  - arxiv.org

resources:
  memory: 4G
  cpus: 2
  pids: 100
```

### Egress Proxy (`config/squid.conf`)

Control exactly which domains your agent can reach. By default, everything is blocked. Add domains explicitly:

```
acl allowed_hosts dstdomain api.openai.com
acl allowed_hosts dstdomain .github.com
```

### Output Validation (`config/validation-rules.yml`)

Scan every file the agent writes for sensitive data:

```yaml
blocked_patterns:
  - "-----BEGIN.*PRIVATE KEY-----"
  - "sk-[a-zA-Z0-9]{48}"
  - "AKIA[0-9A-Z]{16}"

max_file_size: 5242880  # 5MB
rate_limit: 10          # files per hour
reject_symlinks: true
```

Rejected files are moved to `outbox/rejected/` with a JSON report explaining why.

### Environment Variables (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_IMAGE` | `node:22-slim` | Docker image for your agent |
| `AGENT_COMMAND` | `node /app/agent.js` | Entrypoint command |
| `AGENT_MEM_LIMIT` | `2G` | Memory limit |
| `AGENT_CPUS` | `2` | CPU limit |
| `AGENT_PIDS_LIMIT` | `100` | Process limit (prevents fork bombs) |

## Security Model

| Layer | Protection |
|-------|-----------|
| **Filesystem** | Read-only rootfs, tmpfs for temp files |
| **Capabilities** | All Linux capabilities dropped |
| **Privileges** | `no-new-privileges`, non-root user |
| **Network** | Internal network only; egress proxy allowlist |
| **Resources** | Memory, CPU, and PID limits |
| **Output** | Host-side validation of all agent output |
| **Communication** | Inbox read-only, outbox write-only (from agent's perspective) |

### What the agent CAN do
- Read tasks from inbox
- Write results to outbox
- Call APIs on allowlisted domains (through egress proxy)
- Use /tmp for scratch space (tmpfs, size-limited)

### What the agent CANNOT do
- Access host filesystem
- Reach non-allowlisted domains
- Escalate privileges
- Fork-bomb (PID limit)
- Exhaust memory (mem limit)
- Write symlinks to outbox (rejected by validator)
- Exfiltrate secrets (blocked by content patterns)

## Examples

See the `examples/` directory for ready-to-use agent configurations:

- `examples/openai-agent/` - Agent that calls OpenAI API
- `examples/web-scraper/` - Agent that scrapes allowlisted sites

## Project Structure

```
agent-embassy/
├── docker-compose.yml          # Three-container orchestration
├── config/
│   ├── agent.yml               # Agent definition
│   ├── squid.conf              # Egress proxy allowlist
│   └── validation-rules.yml    # Output validation rules
├── scripts/
│   └── validate_outbox.py      # Host-side output validator
├── inbox/                      # Tasks → Agent (read-only for agent)
├── outbox/                     # Agent → Host (validated)
│   └── rejected/               # Failed validation
├── logs/                       # Audit trail
├── agent-state/                # Persistent agent state
├── secrets/                    # API keys (mounted as Docker secrets)
├── examples/                   # Example agent configurations
├── .env.example                # Environment template
├── LICENSE                     # MIT
└── README.md
```

## How It Works

1. **You** write task files to `inbox/`
2. **Agent** reads tasks, does work, writes results to `outbox/`
3. **Egress proxy** filters all network traffic through domain allowlist
4. **Validator** checks every output file for sensitive data, size limits, and policy compliance
5. **You** consume validated results from `outbox/`

The agent never touches your host filesystem. It never reaches domains you didn't approve. Every output file is scanned before you see it.

## Acknowledgements

Born from running AI agents in production at [Ashita Orbis](https://ashitaorbis.com). The pattern emerged from needing to give an AI agent internet access without giving it the keys to the kingdom.

## License

MIT
