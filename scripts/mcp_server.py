#!/usr/bin/env python3
"""
mcp_server.py — MCP server exposing secure Linux server operations.

Run directly (stdio transport, used by an MCP client/host):
    python mcp_server.py

Dependencies: mcp>=2.0, paramiko (see requirements.txt).

2026-10-29: supports a single process serving MULTIPLE host profiles.
Every connection-dependent tool accepts an optional `host` (profile name);
explicit host takes precedence over the global active_host, and connections
are cached per profile so concurrent agents never step on each other.

Safety model:
  * Read-only tools run immediately.
  * Mutating tools (run_command on a non-read-only command, write_file,
    upload_file) are blocked until the corresponding confirmation flag is
    set, which the agent must only supply after the *user* explicitly
    confirms. High-risk commands additionally require accept_risk.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Allow running both as "python mcp_server.py" and as an imported module.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp.server.mcpserver import MCPServer

import linux_ops_core as core

server = MCPServer(
    name="linux-ops",
    instructions=(
        "Secure remote Linux operations over SSH/SFTP. Supports multiple host "
        "profiles: pass host=<profile> to target a specific machine, otherwise "
        "the active profile is used. Read-only tools run directly; any mutating "
        "or destructive tool requires explicit user confirmation, and high-risk "
        "commands also require accept_risk."
    ),
)

_state: dict = {"cfg": None, "servers": {}, "forwarder": core.PortForwardManager()}


def _server(host: str | None = None) -> core.Server:
    """按档案名缓存连接；host 为空时用 active_host。

    2026-10-29：支持单进程多主机。不同 Agent 可显式传 host，
    连接按档案隔离，避免"切了配置影响别人"。
    """
    if _state["cfg"] is None:
        _state["cfg"] = core.load_config()
    cfg = _state["cfg"]
    label = host or cfg.get("active_host") or "_default"
    servers = _state["servers"]
    if label not in servers:
        srv = core.Server(core.config_for_host(cfg, host))
        srv._host_label = label
        servers[label] = srv
    return servers[label]


def _err(exc: Exception) -> dict:
    cfg = _state.get("cfg")
    return {"error": core.redact(str(exc), cfg), "type": exc.__class__.__name__}


def _tag(res: dict, label: str) -> dict:
    """在返回体里带上档案名，便于确认实际打到了哪台。"""
    if isinstance(res, dict):
        res["host"] = label
    return res


# --------------------------------------------------------------------------- #
# Connection
# --------------------------------------------------------------------------- #


@server.tool()
def test_connection(host: str | None = None) -> dict:
    """Test SSH connectivity to the configured Linux server.

    host: 可选档案名（多档案配置下指定具体机器）；留空用 active_host。
    Returns basic identity info (whoami / hostname / uptime). Read-only.
    """
    try:
        srv = _server(host)
        srv.connect()
        r = srv.run("whoami; hostname; uptime")
        return {"connected": True, "host": getattr(srv, "_host_label", ""),
                "info": r.get("stdout", "")}
    except Exception as exc:  # noqa: BLE001 - surface as structured error
        return {"connected": False, **_err(exc)}


@server.tool()
def list_hosts() -> dict:
    """List all configured host profiles.

    多档案配置下返回每个档案的名称/地址/标签/描述；单主机配置返回提示。
    Read-only.
    """
    try:
        cfg = _state["cfg"] or core.load_config()
        _state["cfg"] = cfg
        names = core.host_names(cfg)
        if not names:
            return {"hosts": [], "active": None,
                    "note": "当前为单主机配置（无 hosts 字段）",
                    "current": {"host": cfg.get("host"),
                                "username": cfg.get("username")}}
        items = []
        for n in names:
            h = core.config_for_host(cfg, n)
            items.append({
                "name": n,
                "host": h.get("host"),
                "port": h.get("port"),
                "username": h.get("username"),
                "tags": h.get("tags") or [],
                "description": h.get("description") or "",
                "default_dir": h.get("default_dir") or "",
                "last_connect": core.connection_status(h, n),
            })
        return {"hosts": items, "active": cfg.get("active_host")}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def current_host() -> dict:
    """Show the active host profile and its resolved connection parameters. Read-only."""
    try:
        cfg = _state["cfg"] or core.load_config()
        _state["cfg"] = cfg
        h = core.config_for_host(cfg)
        return {
            "name": cfg.get("active_host") or h.get("_host_name"),
            "host": h.get("host"),
            "port": h.get("port"),
            "username": h.get("username"),
            "auth_method": h.get("auth_method"),
            "key_path": h.get("key_path") or "",
            "default_dir": h.get("default_dir") or "",
        }
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def use_host(name: str) -> dict:
    """Switch the default host profile and persist it to the config file.

    只改"默认"，不影响已建立的其他档案连接（不断开其他连接，
    以免打断正在运行的后台任务）。切换动作写入 config_switch 审计。
    """
    try:
        cfg = _state["cfg"] or core.load_config()
        _state["cfg"] = cfg
        core.set_active_host(cfg, name)
        core.audit(cfg, "config_switch", f"active_host -> {name}", ok=True)
        return {"ok": True, "active": name}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def trust_host(host: str | None = None) -> dict:
    """Trust and remember a server's SSH host key (TOFU).

    host: 可选档案名；留空用 active_host。Only invoke after the user has
    verified the host-key fingerprint out of band (e.g. server console).
    Performs one connection with trust_new=True.
    """
    try:
        srv = _server(host)
        label = getattr(srv, "_host_label", "")
        srv.connect(trust_new=True)
        r = srv.run("whoami; hostname")
        core.audit(srv.cfg, "trust_host", srv.cfg.get("host", ""), ok=True)
        return {"trusted": True, "host": label, "info": r.get("stdout", "")}
    except Exception as exc:  # noqa: BLE001
        return {"trusted": False, **_err(exc)}


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


@server.tool()
def assess_command_risk(command: str) -> dict:
    """Assess a shell command's risk WITHOUT executing it.

    Returns level (safe/caution/danger), whether it is read-only, and reasons.
    Pure local analysis; no connection, so no host parameter.
    """
    return core.assess_command(command)


@server.tool()
def run_command(
    command: str,
    timeout: int | None = None,
    confirm: bool = False,
    accept_risk: bool = False,
    host: str | None = None,
) -> dict:
    """Execute a shell command on the remote Linux server.

    host: 可选档案名，显式指定优先于 active_host。Read-only commands run
    directly. Caution-level commands require confirm=True after explicit user
    approval; danger-level commands require both confirm=True and
    accept_risk=True. Use assess_command_risk first if unsure. `timeout` is in
    seconds; omit it to use config command_timeout (default 120s).
    """
    try:
        srv = _server(host)
        label = getattr(srv, "_host_label", "")
        return _tag(srv.run(command, timeout=timeout, confirm=confirm,
                            accept_risk=accept_risk), label)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def run_script(
    script_b64: str,
    interpreter: str = "bash",
    timeout: int = 120,
    confirm: bool = False,
    accept_risk: bool = False,
    host: str | None = None,
) -> dict:
    """Run a script on the remote server without shell-quoting problems.

    host: 可选档案名。`script_b64` is the Base64-encoded script text (pure
    ASCII), so long or multi-line scripts never break tool-call parameter
    validation. The script is uploaded to a temp file, executed, then removed.

    Read-only scripts run directly; mutating scripts require confirm=True;
    high-risk scripts also require accept_risk=True.
    """
    import base64 as _b64
    import binascii
    import uuid as _uuid

    if interpreter not in ("bash", "sh", "python3"):
        return {"error": "interpreter 仅支持 bash / sh / python3"}

    try:
        raw = _b64.b64decode((script_b64 or "").encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return {"error": "script_b64 不是合法的 Base64"}
    if not raw:
        return {"error": "脚本内容为空"}
    if len(raw) > 256 * 1024:
        return {"error": "脚本过大（上限 256KB）"}

    text = raw.decode("utf-8", "replace")
    risk = core.assess_command(text)
    if not risk.get("read_only") and not confirm:
        return {"error": "需要 confirm=True（用户已明确同意执行该脚本）",
                "risk": risk}
    if risk.get("level") == "danger" and not accept_risk:
        return {"error": "高风险脚本需要 accept_risk=True", "risk": risk}

    srv = _server(host)
    label = getattr(srv, "_host_label", "")
    ext = {"bash": "sh", "sh": "sh", "python3": "py"}[interpreter]
    remote = f"/tmp/.mcp-script-{_uuid.uuid4().hex}.{ext}"
    client = None
    sftp = None
    try:
        client = srv._ensure()
        sftp = client.open_sftp()
        with sftp.file(remote, "w") as fh:
            fh.write(text)
        sftp.close()
        sftp = None
        # 复用 run() 的超时、审计与脱敏逻辑；脚本已预检风险
        res = srv.run(f"{interpreter} {remote}", timeout=timeout,
                      confirm=True, accept_risk=True)
        res["risk"] = risk
        return _tag(res, label)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    finally:
        try:
            if client is not None:
                cleanup_sftp = client.open_sftp()
                try:
                    cleanup_sftp.remove(remote)
                finally:
                    cleanup_sftp.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Files
# --------------------------------------------------------------------------- #


@server.tool()
def list_directory(path: str = ".", host: str | None = None) -> dict:
    """List a remote directory (name, type, size, permissions, mtime). Read-only.

    host: 可选档案名。
    """
    try:
        srv = _server(host)
        return _tag(srv.list_directory(path), getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def read_file(path: str, host: str | None = None) -> dict:
    """Read a remote text file (capped; use download_file for large/binary). Read-only.

    host: 可选档案名。
    """
    try:
        srv = _server(host)
        return _tag(srv.read_file(path), getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def write_file(
    path: str,
    content: str,
    backup: bool = True,
    confirm: bool = False,
    host: str | None = None,
) -> dict:
    """Create/overwrite a remote text file. Requires explicit user confirmation
    (confirm=True). When backup=True, the previous file is kept as a timestamped
    .bak before overwriting. host: 可选档案名。
    """
    try:
        srv = _server(host)
        return _tag(srv.write_file(path, content, backup=backup, confirm=confirm),
                    getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def upload_file(
    local: str,
    remote: str,
    confirm: bool = False,
    host: str | None = None,
) -> dict:
    """Upload a local file to the server via SFTP. Requires explicit user
    confirmation (confirm=True). host: 可选档案名。
    """
    try:
        srv = _server(host)
        return _tag(srv.upload_file(local, remote, confirm=confirm),
                    getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def download_file(
    remote: str,
    local: str,
    host: str | None = None,
) -> dict:
    """Download a remote file to the local machine via SFTP. Read-only on the
    server. host: 可选档案名。
    """
    try:
        srv = _server(host)
        return _tag(srv.download_file(remote, local),
                    getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


# --------------------------------------------------------------------------- #
# Background jobs
# --------------------------------------------------------------------------- #


@server.tool()
def start_job(
    command: str,
    confirm: bool = False,
    accept_risk: bool = False,
    host: str | None = None,
) -> dict:
    """Start a long-running command (e.g. build/deploy) in the background.

    Returns a job_id; output streams to a local log file and a bounded tail.
    Same gating as run_command: caution needs confirm, danger needs confirm
    and accept_risk. host: 可选档案名。
    """
    try:
        srv = _server(host)
        return _tag(srv.start_job(command, confirm=confirm,
                                  accept_risk=accept_risk),
                    getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def list_jobs(host: str | None = None) -> dict:
    """List all tracked background jobs with status/pid/exit code (no output).

    host: 可选档案名；任务按档案隔离，需在启动它的同一档案查询。
    """
    try:
        srv = _server(host)
        return _tag(srv.list_jobs(), getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def get_job(
    job_id: str,
    tail_bytes: int = 16384,
    host: str | None = None,
) -> dict:
    """Return one background job's status and the tail of its streamed output.

    host: 可选档案名。
    """
    try:
        srv = _server(host)
        return _tag(srv.get_job(job, tail_bytes=tail_bytes),
                    getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def stop_job(
    job_id: str,
    confirm: bool = False,
    host: str | None = None,
) -> dict:
    """Terminate a background job's remote process group. Requires confirm=True.

    host: 可选档案名。
    """
    try:
        srv = _server(host)
        return _tag(srv.stop_job(job_id, confirm=confirm),
                    getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


# --------------------------------------------------------------------------- #
# Atomic patching
# --------------------------------------------------------------------------- #


@server.tool()
def patch_file(
    path: str,
    operations: list[dict],
    backup: bool = True,
    confirm: bool = False,
    host: str | None = None,
) -> dict:
    """Apply exact find/replace edits to a remote file atomically.

    operations is a list of {"find": str, "replace": str, "replace_all"?:
    bool}. Each `find` must currently exist and be unique (unless
    replace_all); otherwise the whole patch aborts unchanged. The result is
    staged in a temp file then atomically renamed over the target. Requires
    confirm=True; backup=True keeps a timestamped copy. host: 可选档案名。
    """
    try:
        srv = _server(host)
        return _tag(srv.patch_file(path, operations, backup=backup,
                                   confirm=confirm),
                    getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


# --------------------------------------------------------------------------- #
# Curated operational views (all read-only)
# --------------------------------------------------------------------------- #


@server.tool()
def system_overview(host: str | None = None) -> dict:
    """Return host OS, kernel, uptime, CPU, memory, disk and load summary. Read-only.

    host: 可选档案名。
    """
    try:
        srv = _server(host)
        return _tag(core.system_overview(srv), getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def check_services(host: str | None = None) -> dict:
    """List failed systemd units and running services. Read-only.

    host: 可选档案名。
    """
    try:
        srv = _server(host)
        return _tag(core.check_services(srv), getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def check_logs(
    service: str = "",
    lines: int = 50,
    host: str | None = None,
) -> dict:
    """Read recent logs. With a service name, that unit's journal; otherwise the
    last warning-level journal entries. Read-only. host: 可选档案名。
    """
    try:
        srv = _server(host)
        return _tag(core.check_logs(srv, service or None, lines),
                    getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def security_check(host: str | None = None) -> dict:
    """Read-only intrusion/exposure triage: failed & successful logins, users
    online, listening ports, firewall, top processes, cron persistence, sshd
    settings, fail2ban. Makes no changes. host: 可选档案名。
    """
    try:
        srv = _server(host)
        return _tag(core.security_check(srv), getattr(srv, "_host_label", ""))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


# --------------------------------------------------------------------------- #
# Port forwarding (separate, permission-gated capability)
# --------------------------------------------------------------------------- #


@server.tool()
def start_port_forward(
    direction: str,
    local_port: int,
    remote_port: int,
    remote_host: str = "127.0.0.1",
    bind_address: str = "127.0.0.1",
    confirm: bool = False,
    accept_risk: bool = False,
    host: str | None = None,
) -> dict:
    """Start an SSH port forward. A separate, permission-gated capability.

    direction="local": 本机 local_port 经网关转发到 remote_host:remote_port。
    direction="remote": 网关 remote_port 反向转发到本机可达的
    remote_host:local_port（remote_host 通常为 127.0.0.1）。
    默认绑定回环；bind_address=0.0.0.0 暴露到所有网卡，需 accept_risk。
    需 confirm=True。host: 可选档案名。
    """
    try:
        if direction not in ("local", "remote"):
            return {"error": "direction 仅支持 local / remote"}
        if not confirm:
            return {"executed": False, "blocked": True, "needs": "confirm",
                    "message": "端口转发属于变更类网络操作，需要明确确认。"}
        if bind_address not in ("127.0.0.1", "localhost") and not accept_risk:
            return {"executed": False, "blocked": True,
                    "needs": "accept_risk",
                    "message": "绑定到非回环地址会暴露端口，需要 accept_risk。"}
        srv = _server(host)
        label = getattr(srv, "_host_label", "")
        manager = _state["forwarder"]
        if direction == "local":
            res = manager.start_local(srv, local_port, remote_host,
                                      remote_port, bind_address)
        else:
            res = manager.start_remote(srv, remote_port, remote_host,
                                       local_port, bind_address)
        return _tag(res, label)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def list_port_forwards(host: str | None = None) -> dict:
    """List tracked port forwards. host: 可选档案名（管理器为进程级）。"""
    try:
        cfg = _state.get("cfg")
        label = host or (cfg.get("active_host", "") if cfg else "")
        return _tag(_state["forwarder"].list_forwards(), label)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@server.tool()
def stop_port_forward(
    forward_id: str,
    confirm: bool = False,
    host: str | None = None,
) -> dict:
    """Stop a port forward by id. Requires confirm=True. host: 可选档案名。"""
    try:
        if not confirm:
            return {"executed": False, "blocked": True, "needs": "confirm",
                    "message": f"停止端口转发 {forward_id} 需要明确确认。"}
        cfg = _state.get("cfg")
        label = host or (cfg.get("active_host", "") if cfg else "")
        return _tag(_state["forwarder"].stop_forward(forward_id), label)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
