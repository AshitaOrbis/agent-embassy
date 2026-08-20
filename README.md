# Agent Embassy

> **Note: This project is archived.** The embassy pattern demonstrated several useful hardening layers (Docker isolation, an egress proxy, and output validation), but those layers do not form a containment primitive or complete agent sandbox. See the [post-mortem blog series](https://ashitaorbis.com/posts/033-the-container-that-forgot-to-stop) for what we learned. For active alternatives, see [Docker AI Sandboxes](https://docs.docker.com/ai/sandbox/) and [AISI Sandboxing](https://github.com/UKGovernmentBEIS/aisi-sandboxing).

Archived Docker Compose **hardening template** for running AI agents you broadly trust. Supply an agent image and its real entrypoint, then configure the operative controls directly. It applies defense-in-depth (egress allowlist, dropped capabilities, read-only root filesystem, resource limits, and best-effort output validation).

> **Not a containment boundary for actively malicious code.** This is layered hardening on ordinary Docker isolation, not a security sandbox. An adversarial agent has documented paths to defeat it: DNS-based egress can bypass the proxy on some Docker/Moby versions; the output validator observes files rather than gating them (symlink/path-traversal/validate-then-mutate/fail-open bypasses exist); and writable host bind mounts are reachable outside the "controlled" channel. For untrusted or potentially-compromised agents use a real isolation layer (gVisor, Firecracker/Kata, or a network-firewalled VM). Treat this repo as a starting pattern to harden, not a guarantee.

## Why

AI agents need internet access to be useful but unrestricted access is dangerous. Agent Embassy implements the "embassy pattern": your agent lives in a hardened environment where its ordinary HTTP(S) traffic is routed through supervised channels. Supervision covers traffic that reaches the proxy — the documented bypasses in the note above remain open.

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
- **Egress proxy**: Squid-based allowlist, applied to HTTP/HTTPS traffic that reaches the proxy. DNS and the other documented bypasses stay outside this control.
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

# 4. Make the writable mounts writable by the container UID/GID (see below)
sudo chown -R 1000:1000 outbox logs agent-state

# 5. Run
docker compose up -d

# 6. Submit a task
echo '{"type": "task", "prompt": "Hello, agent"}' > inbox/task-001.json

# 7. Check results
ls outbox/
```

> **Prerequisite: `outbox`, `logs`, and `agent-state` must be writable by the
> configured container UID/GID.** `docker-compose.yml` runs both the agent and
> the validator as `1000:1000`. On a checkout owned by any other UID under a
> normal `022` umask those directories are mode `0755` and owned by you, so both
> containers get `EACCES` — the agent writes no results, logs, or state, and the
> validator cannot create `outbox/rejected/` or quarantine a file. `docker
> compose up -d` still reports success, so the failure is silent. `inbox` is
> mounted read-only and only needs to be readable.
>
> Step 4 above takes the first of three options:
>
> ```bash
> # A. Give the container identity ownership of the writable mounts
> sudo chown -R 1000:1000 outbox logs agent-state
>
> # B. Or keep your ownership and grant UID 1000 access with an ACL
> sudo setfacl -R -m u:1000:rwX outbox logs agent-state
> sudo setfacl -d -m u:1000:rwx outbox logs agent-state   # new files inherit it
>
> # C. Or run the containers as yourself: replace every 1000 in
> #    docker-compose.yml — the two `user:` lines and the agent `tmpfs`
> #    uid=/gid= options — with `id -u` and `id -g`
> ```
>
> If you already ran `docker compose up -d` before fixing ownership, apply one of
> the above and restart: `docker compose down && docker compose up -d`.

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

Controls which domains the agent can reach over HTTP/HTTPS traffic that goes through Squid (DNS and the other documented bypasses are outside this control). The shipped policy allows the reserved placeholder `.example.com` and denies everything else — it is not a deny-all default until you remove that placeholder line. Add your domains explicitly:

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

The policy is schema-checked before the validator starts watching. Both mandatory
keys must be present with these exact JSON types; the three optional keys are
checked whenever they appear:

| Key | Required | Type | Notes |
|-----|----------|------|-------|
| `max_file_size` | yes | number | Whole bytes, `1` .. `1099511627776`; `true` and `"5242880"` are rejected |
| `reject_symlinks` | yes | boolean | Only `true`/`false`; `null` and `0` are rejected |
| `blocked_patterns` | no | array of strings | Every entry must compile as a Python regex, checked at startup |
| `required_json_fields` | no | array of strings | Applied to `.json` outputs |
| `allowed_extensions` | no | array of strings | Lowercase, leading dot, e.g. `".json"` |

**An optional check is disabled by omitting its key, never by giving it a falsy
value.** A present-but-empty array, a wrong-typed value, or a misspelled key
(`blocked_paterns`) is a schema error, not a silently weaker policy. The validator
prints `POLICY ERROR: ...` naming the offending field and exits `2` before it
reports itself ready to watch — a missing policy file, unparseable JSON, and a
non-object root behave the same way. Rejected files are moved to
`outbox/rejected/` with a JSON report explaining why.

### Environment Variables (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_IMAGE` | Required | Docker image that already contains your agent program. Compose forces UID/GID 1000 and sets `HOME=/home/node` (a leftover of the removed Node default): the image must run as UID 1000 with a read-only or absent `/home/node`, or you must adapt those fields in `docker-compose.yml`. The host `outbox`, `logs`, and `agent-state` directories must be writable by that same UID/GID — see the Quick Start prerequisite |
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

**Execution is not reproducible.** `docker-compose.yml` pulls mutable image tags (`ubuntu/squid:latest`, `python:3.12-slim`), so a clone today runs whatever those tags point at now — not bytes reviewed when this repository was archived. Do not treat the archive as a known-good runtime; pin your own digests if you need one.

| Layer | Hardening | Adversarial caveat |
|-------|-----------|--------------------|
| **Filesystem** | Read-only rootfs, tmpfs for temp files | Writable host bind mounts (outbox/logs/state) are still reachable |
| **Capabilities** | All Linux capabilities dropped | Container isolation only; not a syscall sandbox |
| **Privileges** | `no-new-privileges`, non-root user | — |
| **Network** | Internal network + egress proxy allowlist | DNS-based egress can bypass the proxy on some Docker/Moby versions |
| **Resources** | Memory, CPU, and PID limits | Disk/inode exhaustion via host mounts not bounded |
| **Output** | Host-side validation of agent output | **Observational, not a gate** — symlink, path-traversal, validate-then-mutate, and fail-open bypasses exist |
| **Communication** | Inbox read-only bind mount; outbox is a read/write host bind mount | Outbox is not one-way: the agent can read, alter, or delete anything in it — including files the host or validator has already seen. It is no confidentiality boundary between runs or agents |

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

See the `examples/` directory for metadata and reference Squid policies. Nothing under `examples/` is read by Compose — to use an example egress policy, copy it over `config/squid.conf` before starting (e.g. `cp examples/openai-agent/squid.conf config/squid.conf`):

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
├── logs/                       # Agent-writable log storage (not an audit trail)
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
