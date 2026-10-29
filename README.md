# linux-ops-mcp

A secure, self-hosted **Model Context Protocol (MCP) server** for operating
remote Linux servers over SSH/SFTP. It lets any MCP-compatible agent run
shell commands, edit files, transfer files, run background jobs, deploy
services, and perform read-only security/intrusion triage — with a built-in
risk gate so mutating and destructive actions always require explicit user
confirmation.

- Pure Python, stdio transport, no daemon/open port of its own.
- Single-process **multi-host profiles**; one config can describe many servers.
- Reuses `~/.ssh/config`; key, password and SSH-agent authentication.
- Credentials are never logged; every action is written to a local audit log.

## Why

Generic "run any SSH command" MCP servers tend to execute whatever the model
sends with no guardrails. This project puts a deterministic command risk
classifier and confirmation gate in front of the SSH connection, following the
[MCP security best practices](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices)
and the [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).

## Architecture

```
scripts/
├── linux_ops_core.py   # secure core: config, risk engine, SSH/SFTP, audit, forwards
├── mcp_server.py       # MCP stdio server (25 tools)
├── cli.py              # equivalent CLI fallback (no MCP binding required)
└── requirements.txt
```

The MCP server and the CLI share the same core, so behavior and safety rules
are identical across both entry points.

## Security model

Every command is first classified. Compound commands are split on
`; && || | & newline` (quoted literals are masked so hidden operators cannot
bypass analysis):

| Level    | Meaning                                                        | Required to run                     |
|----------|----------------------------------------------------------------|-------------------------------------|
| `safe`   | Read-only (ls/cat/grep/ps/df/free/ss, query systemctl, etc.)  | runs immediately                    |
| `caution`| File edits, package installs, service start/stop, kill, etc.  | `confirm=True`                      |
| `danger` | `rm -rf /`, mkfs, block-device writes, reboot, firewall flush, reverse shell, sudoers/account changes, log wiping | `confirm=True` + `accept_risk=True` |

- Writes, uploads, patches, job stops and port forwards also require `confirm`.
- Host keys are **strictly verified** by default. An unknown key requires
  out-of-band fingerprint verification, then `trust_host` (TOFU). A changed key
  (possible MITM) is refused.
- Passwords/passphrases are read from environment variables and redacted from
  output and the audit log.
- Blocked actions are never retried or reworded to bypass the gate.

## Quick start (installer)

The installer picks a Python that already has `mcp` + `paramiko`, otherwise
creates an isolated venv, deploys the server to `~/.linux-ops/server`,
generates a config and a ready-to-paste MCP registration snippet.

- Windows PowerShell:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; .\install.ps1
  ```
- Linux / macOS / Git Bash:
  ```bash
  bash install.sh
  ```

## Manual install

```bash
pip install -r scripts/requirements.txt
cp scripts/config.example.json ~/.linux-ops/config.json   # edit host/user/key
```

Register a local stdio MCP with any MCP client:

```json
{
  "mcpServers": {
    "linux-ops": {
      "command": "python",
      "args": ["/absolute/path/to/scripts/mcp_server.py"],
      "env": { "LINUX_OPS_CONFIG": "/absolute/path/config.json" }
    }
  }
}
```

## Multi-host profiles

One config file can define many servers. The optional `host` argument on every
tool selects a profile; explicit selection overrides the global default, and
connections are cached per profile without cross-talk. See
[`config.example.multi.json`](config.example.multi.json).

```json
{
  "active_host": "web1",
  "defaults": { "port": 22, "username": "deploy", "auth_method": "key" },
  "hosts": {
    "web1": { "host": "10.0.0.10", "key_path": "~/.ssh/id_ed25519" },
    "db1":  { "host": "10.0.0.20", "key_path": "~/.ssh/id_ed25519" }
  }
}
```

A profile may set `ssh_config_host` to reuse an alias from `~/.ssh/config`
(path overridable with `ssh_config_file`). Only fields not explicitly defined
in the profile are filled, so explicit values always win. Configs are validated
on load and fail early with readable errors.

## Port forwarding (separate, permission-gated)

Forwarding is a separate capability that clients can choose not to grant. It
binds to loopback by default; binding to a non-loopback address such as
`0.0.0.0` additionally requires `accept_risk`.

- `start_port_forward(direction, local_port, remote_port, ...)` — `local`
  forwards a local port through the gateway; `remote` requests a gateway-side
  port that tunnels back to a local target.
- `list_port_forwards()` / `stop_port_forward(forward_id)`.

## Tools (25)

- **Profiles:** `list_hosts`, `current_host`, `use_host`
- **Connection:** `test_connection`, `trust_host`
- **Commands:** `assess_command_risk`, `run_command`, `run_script`
- **Files (SFTP):** `list_directory`, `read_file`, `write_file`, `upload_file`,
  `download_file`
- **Background jobs:** `start_job`, `list_jobs`, `get_job`, `stop_job`
- **Atomic patch:** `patch_file`
- **Read-only views:** `system_overview`, `check_services`, `check_logs`,
  `security_check`
- **Port forwarding:** `start_port_forward`, `list_port_forwards`,
  `stop_port_forward`

## CLI

The CLI is the fallback when no MCP binding is available. Every command prints
JSON; `--host` selects a profile.

```bash
python scripts/cli.py hosts
python scripts/cli.py --host web1 run "df -h"
python scripts/cli.py run "systemctl reload nginx" --confirm
python scripts/cli.py security
```

## Testing

The project ships deterministic, network-free verification suites plus a stdio
handshake smoke test:

```bash
python verify_enhancements.py    # ssh config, validation, forwarding, gating
python verify_multi_host.py      # profile routing, isolation, audit
python smoke_stdio.py            # initialize + tools/list over real stdio
```

## License

[MIT](LICENSE)
