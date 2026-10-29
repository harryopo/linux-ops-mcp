#!/usr/bin/env python3
"""
linux_ops_core.py — Secure SSH/SFTP operations core for remote Linux servers.

Design goals:
  * Credentials never logged; passwords read from environment by default.
  * Strict host-key verification (TOFU only on explicit trust).
  * Every command is risk-assessed; mutating/destructive commands need
    explicit confirmation before execution.
  * All actions are written to a local audit log (secrets redacted).

All public functions return plain JSON-serializable dicts so they can be
wrapped by either the MCP server (mcp_server.py) or the CLI (cli.py).
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import re
import shlex
import socket
import stat
import threading
from pathlib import Path

import paramiko

# --------------------------------------------------------------------------- #
# Paths / constants
# --------------------------------------------------------------------------- #

DEFAULT_DIR = Path.home() / ".linux-ops"
DEFAULT_CONFIG = DEFAULT_DIR / "config.json"
DEFAULT_KNOWN_HOSTS = DEFAULT_DIR / "known_hosts"
DEFAULT_AUDIT_LOG = DEFAULT_DIR / "audit.log"

MAX_COMMAND_OUTPUT = 64 * 1024       # bytes returned per stream
MAX_FILE_READ = 256 * 1024            # bytes returned when reading a file
DEFAULT_COMMAND_TIMEOUT = 30
DEFAULT_CONNECT_TIMEOUT = 10

RISK_SAFE = "safe"
RISK_CAUTION = "caution"
RISK_DANGER = "danger"

# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #


def _now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _truncate(data: str, limit: int) -> str:
    b = data.encode("utf-8", errors="replace")
    if len(b) <= limit:
        return data
    head = b[:limit].decode("utf-8", errors="replace")
    return (
        head
        + f"\n...[truncated {len(b) - limit} more bytes; "
        f"use a narrower command or download the file]..."
    )


def fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def redact(text: str, cfg: dict | None = None) -> str:
    """Best-effort removal of known secrets from a string."""
    if not text:
        return text
    secrets = []
    if cfg:
        for key in ("password", "key_passphrase"):
            v = cfg.get(key)
            if v:
                secrets.append(v)
    for env in ("LINUX_OPS_PASSWORD", "LINUX_OPS_KEY_PASSPHRASE"):
        v = os.environ.get(env)
        if v:
            secrets.append(v)
    for s in secrets:
        if s and len(s) >= 4 and s in text:
            text = text.replace(s, "***REDACTED***")
    return text


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def _merge_host(base: dict, name: str) -> dict:
    """把 defaults + 指定档案 + 顶层通用字段 合并成一份扁平配置。

    2026-10-29 新增：支持单进程多主机档案。
    """
    hosts = base.get("_hosts_raw") or {}
    if name not in hosts:
        avail = "、".join(hosts.keys()) or "(空)"
        raise ConfigError(f"未知主机档案 {name!r}；可用档案：{avail}")
    out: dict = {}
    for layer in (base.get("_defaults") or {}, hosts.get(name) or {}):
        if isinstance(layer, dict):
            out.update(layer)
    for k in ("known_hosts", "audit_log", "connect_timeout", "command_timeout",
              "host_key_policy", "password_env", "key_passphrase_env"):
        if k not in out and base.get(k) is not None:
            out[k] = base[k]
    out["_host_name"] = name
    return out


def load_config(path: str | None = None) -> dict:
    """Load server configuration.

    Precedence (highest first): environment variables > config file > defaults.
    Passwords are only read from the environment or a file field the user
    deliberately set; they are never written anywhere by this program.
    """
    cfg_path = Path(path) if path else Path(
        os.environ.get("LINUX_OPS_CONFIG", str(DEFAULT_CONFIG))
    )
    cfg: dict = {}
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"配置文件不是合法 JSON: {cfg_path} ({exc})")

    def env_or(key, env, cast=str):
        v = os.environ.get(env)
        if v is not None and v != "":
            cfg[key] = cast(v)

    env_or("host", "LINUX_OPS_HOST")
    env_or("port", "LINUX_OPS_PORT", int)
    env_or("username", "LINUX_OPS_USER")
    env_or("key_path", "LINUX_OPS_KEY_PATH")
    env_or("auth_method", "LINUX_OPS_AUTH")

    explicit_keys = set(cfg.keys())   # 文件 + 环境变量显式提供的字段

    cfg.setdefault("port", 22)
    cfg.setdefault("auth_method", "key")
    cfg.setdefault("host_key_policy", "strict")     # strict | trust_new
    cfg.setdefault("known_hosts", str(DEFAULT_KNOWN_HOSTS))
    cfg.setdefault("audit_log", str(DEFAULT_AUDIT_LOG))
    cfg.setdefault("connect_timeout", DEFAULT_CONNECT_TIMEOUT)
    cfg.setdefault("command_timeout", DEFAULT_COMMAND_TIMEOUT)
    cfg["_config_path"] = str(cfg_path)
    # 2026-10-29：保存"未合并任何档案"的基底，供 config_for_host 逐档案解析。
    # 否则 A 档案的独有字段（default_dir / tags / description）会串到 B 档案上。
    cfg["_base"] = dict(cfg)

    # ---- 2026-10-29：多主机档案 ----
    # 老格式（顶层直接写 host/username）行为完全不变；
    # 新格式：{ "active_host": "128", "defaults": {...}, "hosts": { "128": {...} } }
    raw_hosts = cfg.get("hosts")
    if isinstance(raw_hosts, dict) and raw_hosts:
        cfg["_hosts_raw"] = dict(raw_hosts)
        cfg["_defaults"] = cfg.get("defaults") or {}
        active = str(cfg.get("active_host") or "")
        if active not in raw_hosts:
            active = next(iter(raw_hosts))
        cfg["active_host"] = active
        merged = _merge_host(cfg, active)
        # 环境变量是"临时显式覆盖"，优先级最高
        for _k, _env in (("host", "LINUX_OPS_HOST"), ("port", "LINUX_OPS_PORT"),
                         ("username", "LINUX_OPS_USER"), ("key_path", "LINUX_OPS_KEY_PATH"),
                         ("auth_method", "LINUX_OPS_AUTH")):
            _v = os.environ.get(_env)
            if _v not in (None, ""):
                merged[_k] = int(_v) if _k == "port" else _v
        cfg.update(merged)

    # Normalize user-supplied paths so "~" and environment variables expand
    # correctly on Windows, macOS and Linux.
    for _pk in ("known_hosts", "audit_log", "key_path"):
        if cfg.get(_pk):
            cfg[_pk] = os.path.expanduser(os.path.expandvars(str(cfg[_pk])))

    # Resolve password / passphrase from referenced env vars, else direct field.
    pw_env = cfg.get("password_env", "LINUX_OPS_PASSWORD")
    if cfg.get("auth_method") == "password":
        cfg["password"] = os.environ.get(pw_env, cfg.get("password"))
    kp_env = cfg.get("key_passphrase_env", "LINUX_OPS_KEY_PASSPHRASE")
    cfg["key_passphrase"] = os.environ.get(kp_env, cfg.get("key_passphrase"))

    _apply_ssh_config(cfg, explicit_keys)
    validate_config(cfg)
    return cfg


class ConfigError(Exception):
    pass


def host_names(cfg: dict) -> list[str]:
    """返回配置里已定义的档案名；单主机模式返回空列表。"""
    return list((cfg.get("_hosts_raw") or {}).keys())


def set_active_host(cfg: dict, name: str) -> dict:
    """切换默认档案并原子写回配置文件（临时文件 + os.replace）。"""
    hosts = cfg.get("_hosts_raw") or {}
    if not hosts:
        raise ConfigError("当前配置未启用多档案（缺少 hosts 字段）")
    if name not in hosts:
        raise ConfigError(f"未知主机档案 {name!r}；可用：{'、'.join(hosts)}")
    path = Path(cfg.get("_config_path") or DEFAULT_CONFIG)
    raw = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    raw["active_host"] = name
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    cfg["active_host"] = name
    return cfg


def config_for_host(cfg: dict, name: str | None = None) -> dict:
    """返回指定档案的扁平配置。

    单主机模式（无 hosts 字段）下忽略 name 直接返回原配置；
    只有显式指定了不存在的档案名才报错。
    """
    hosts = cfg.get("_hosts_raw") or {}
    if not hosts:
        if name and name not in ("", "default", cfg.get("_host_name")):
            raise ConfigError(f"当前为单主机配置，无法指定 host={name!r}")
        return dict(cfg)
    target = name or cfg.get("active_host") or next(iter(hosts))
    out = dict(cfg.get("_base") or cfg)
    out.update(_merge_host(cfg, target))
    for _pk in ("known_hosts", "audit_log", "key_path"):
        if out.get(_pk):
            out[_pk] = os.path.expanduser(os.path.expandvars(str(out[_pk])))
    pw_env = out.get("password_env") or ""
    if out.get("auth_method") == "password" and pw_env:
        out["password"] = os.environ.get(pw_env, out.get("password"))
    kp_env = out.get("key_passphrase_env") or ""
    out["key_passphrase"] = os.environ.get(kp_env) if kp_env else None
    out["_host_name"] = target
    _defaults = cfg.get("_defaults") or {}
    _entry = (cfg.get("_hosts_raw") or {}).get(target, {})
    _explicit = set(_defaults.keys()) | (
        set(_entry.keys()) if isinstance(_entry, dict) else set())
    _apply_ssh_config(out, _explicit)
    validate_config(out)
    return out


def _apply_ssh_config(cfg: dict, explicit: set[str] | None = None) -> dict:
    """当档案指定 ssh_config_host 时，用 paramiko.SSHConfig 解析 ~/.ssh/config。

    explicit 为该档案在配置文件中显式定义的字段集合；这些字段不被覆盖。
    只补未显式定义的 host/username/port/key_path，显式值优先。
    借鉴 smooth-ssh-mcp / mcp-ssh-ops 复用系统 SSH 配置的做法。
    """
    alias = cfg.get("ssh_config_host")
    if not alias:
        return cfg
    explicit = explicit or set()
    ssh_file = os.path.expanduser(cfg.get("ssh_config_file") or "~/.ssh/config")
    if not Path(ssh_file).exists():
        raise ConfigError(
            f"ssh_config_host={alias!r} 但 SSH 配置文件不存在: {ssh_file}")
    ssh_config = paramiko.SSHConfig()
    with open(ssh_file, encoding="utf-8") as fh:
        ssh_config.parse(fh)
    if str(alias) not in ssh_config.get_hostnames():
        raise ConfigError(f"SSH 配置中找不到 Host 别名 {alias!r}: {ssh_file}")
    found = ssh_config.lookup(str(alias))

    if "host" not in explicit and not cfg.get("host") and found.get("hostname"):
        cfg["host"] = found["hostname"]
    if "username" not in explicit and not cfg.get("username") and found.get("user"):
        cfg["username"] = found["user"]
    if "port" not in explicit and found.get("port"):
        cfg["port"] = int(found["port"])
    if "key_path" not in explicit and not cfg.get("key_path"):
        for candidate in found.get("identityfile") or []:
            resolved = os.path.expanduser(candidate)
            if Path(resolved).exists():
                cfg["key_path"] = resolved
                break
    return cfg


def validate_config(cfg: dict) -> None:
    """启动期 schema 校验，错误早失败（OWASP：在服务层校验输入）。"""
    if not isinstance(cfg.get("host"), str) or not cfg.get("host"):
        raise ConfigError("配置缺少有效 host（服务器地址）")
    if not cfg.get("username"):
        raise ConfigError("配置缺少 username（登录用户名）")
    try:
        port = int(cfg.get("port", 22))
        if not (1 <= port <= 65535):
            raise ValueError
    except (TypeError, ValueError):
        raise ConfigError(
            f"port 必须是 1-65535 的整数，当前: {cfg.get('port')}")
    if cfg.get("auth_method") not in ("key", "password", "agent"):
        raise ConfigError(
            f"auth_method 仅支持 key/password/agent，当前: {cfg.get('auth_method')}")
    if cfg.get("host_key_policy") not in ("strict", "trust_new"):
        raise ConfigError("host_key_policy 仅支持 strict/trust_new")
    if cfg.get("auth_method") == "key" and not cfg.get("key_path"):
        raise ConfigError("auth_method=key 需要 key_path（私钥路径）")
    for field in ("connect_timeout", "command_timeout"):
        value = cfg.get(field)
        if value is not None and (not isinstance(value, int) or value <= 0):
            raise ConfigError(f"{field} 必须是正整数秒，当前: {value}")


# 进程内"上次连通"缓存（不主动探活），供 list_hosts 展示。
_connect_cache: dict[str, dict] = {}


def _cache_key(cfg: dict) -> str:
    return str(cfg.get("_host_name") or cfg.get("host") or "_default")


def record_connection(cfg: dict, ok: bool, error: str | None = None) -> None:
    try:
        entry = {"ok": ok, "time": _now(), "host": cfg.get("host"),
                 "port": cfg.get("port")}
        if error:
            entry["error"] = redact(error, cfg)[:300]
        _connect_cache[_cache_key(cfg)] = entry
    except Exception:
        pass


def connection_status(cfg: dict, label: str | None = None) -> dict | None:
    key = label or _cache_key(cfg)
    found = _connect_cache.get(key)
    return dict(found) if found else None


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #


def audit(cfg: dict, action: str, detail: str, ok: bool = True) -> None:
    try:
        log_path = Path(cfg.get("audit_log", DEFAULT_AUDIT_LOG))
        log_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "time": _now(),
            "host": cfg.get("host"),
            "profile": cfg.get("_host_name"),
            "user": cfg.get("username"),
            "action": action,
            "ok": ok,
            "detail": redact(detail, cfg)[:2000],
        }
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        # Auditing must never break the main operation.
        pass


# --------------------------------------------------------------------------- #
# Command risk assessment
# --------------------------------------------------------------------------- #

# Shell separators used to split a compound command into sub-commands.
_SHELL_SPLIT = re.compile(r"(?:;|&&|\|\||\||\n|&)")

_READ_ONLY_CMDS = {
    "ls", "cat", "head", "tail", "less", "more", "most", "nl", "tac", "od",
    "xxd", "grep", "egrep", "fgrep", "rg", "find", "stat", "file", "tree",
    "whoami", "id", "groups", "hostname", "hostnamectl", "uname", "uptime",
    "df", "du", "free", "lsblk", "lscpu", "lspci", "lsusb", "lsmem", "ps",
    "nproc", "lsmod", "lsns", "getconf", "numactl", "dmidecode", "modinfo",
    "pstree", "slabtop", "strace", "lsof", "fuser", "ldd", "lddtree",
    "top", "htop", "atop", "vmstat", "iostat", "mpstat", "sar", "pidof",
    "pgrep", "ss", "netstat", "ip", "ifconfig", "route", "arp", "nstat",
    "dmesg", "journalctl", "systemctl", "service", "env", "printenv",
    "date", "timedatectl", "localectl", "loginctl", "busctl", "resolvectl",
    "hostnamectl", "systemd-analyze", "runlevel", "pinky", "namei", "watch",
    "cal", "wc", "awk", "sed", "cut", "sort", "uniq", "tr", "paste", "fold",
    "expand", "unexpand", "rev", "column", "numfmt", "join", "seq", "csplit",
    "base32", "base64", "pathchk", "tput", "getopt", "whatis", "apropos",
    "diff", "cmp", "comm", "tee", "ping", "ping6", "traceroute", "tracepath",
    "mtr", "dig", "nslookup", "host", "whois", "last", "lastb", "lastlog",
    "who", "w", "utmpdump", "getenforce", "sestatus", "ufw", "firewall-cmd",
    "iptables", "ip6tables", "nft", "crontab", "lsb_release", "os-release",
    "sensors", "lsof", "fuser", "journalctl", "fail2ban-client", "getfacl",
    "sysctl", "getcap", "auditctl", "ausearch", "aureport", "which", "whereis", "type",
    "command", "echo", "true", "false", "test", "expr", "basename", "dirname",
    "realpath", "readlink", "md5sum", "sha1sum", "sha256sum", "cksum",
}

# (regex, reason) — high severity, hard to reverse or system-wide / security.
_DANGER_RULES = [
    (re.compile(r"\brm\b[^|;&]*\s+-[a-z]*r?[a-z]*f[a-z]*\s+(/|/\*|\$HOME|~|\s*$)"),
     "递归强制删除根目录/家目录，将摧毁系统或数据"),
    (re.compile(r"\bmkfs\b|\bmkfs\.[a-z0-9]+\b|\bwipefs\b|\blkfs\b"),
     "格式化/擦除文件系统，数据不可恢复"),
    (re.compile(r"\bdd\b[^|;&]*\bof=/dev/"), "向块设备直接写入，可摧毁磁盘/系统"),
    (re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:"), "fork 炸弹，耗尽系统资源"),
    (re.compile(r">\s*/dev/(sd|hd|vd|xvd|nvme|mmcblk|loop|sr|fd|disk|blk)"),
     "重定向写入块设备，可摧毁磁盘"),
    (re.compile(r"\b(shutdown|halt|poweroff|reboot|init\s+[06])\b"),
     "关机/重启，会中断线上服务"),
    (re.compile(r"\b(chmod|chown)\b[^|;&]*-R[^|;&]*\s+(/\s|/\*|/etc|/boot)"),
     "递归修改系统目录权限/属主，可致系统不可用"),
    (re.compile(r"\biptables\b[^|;&]*(-F|--flush)|\bufw\s+disable\b|"
                r"\bfirewall-cmd\b[^|;&]*--stop\b|\bnft\s+flush\b"),
     "清空/停用防火墙，主机将暴露"),
    (re.compile(r"\b(kill|pkill|killall)\b[^|;&]*(\b1\b|systemd|init)"),
     "终止 init/systemd(PID 1)，系统将崩溃"),
    (re.compile(r"\b(curl|wget|fetch)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|fi)?sh\b|"
                r"\|\s*(sudo\s+)?python"),
     "从网络下载后直接管道执行，存在供应链/投毒风险"),
    (re.compile(r"/dev/tcp/|bash\s+-i\b|nc\b[^|;&]*-e|ncat\b[^|;&]*-e|"
                r"python\b[^|;&]*socket"),
     "疑似反向 shell / 反弹连接"),
    (re.compile(r"\bvisudo\b|>\s*/etc/sudoers|/etc/sudoers\.d/"),
     "修改 sudo 授权，属于提权敏感操作"),
    (re.compile(r"(?:^|[;&|\s])(passwd|chpasswd|userdel|groupdel)(?:\s|$)|"
                r"(?:^|[;&|\s])usermod\b[^|;&]*-L\b"),
     "修改账号/口令或删除用户，影响登录与安全"),
    (re.compile(r"\bhistory\s+-c\b|>\s*/var/log/[^ ;&]+\.log\b|"
                r"journalctl\b[^|;&]*--vacuum"),
     "清空历史/日志，可能是在掩盖入侵痕迹"),
    (re.compile(r"\b(crontab\s+-r|rm\b[^|;&]*/etc/cron)"), "删除计划任务（可能是持久化项或正常任务）"),
]

# Medium severity — mutating but routine.
_CAUTION_RULES = [
    (re.compile(r"\b(rm|rmdir)\b"), "删除文件/目录"),
    (re.compile(r"\b(systemctl|service)\b[^|;&]*\b(start|stop|restart|reload|"
                r"enable|disable|mask|reset-failed)\b"),
     "变更系统服务状态，可能影响线上服务"),
    (re.compile(r"\b(kill|pkill|killall)\b"), "向进程发送信号"),
    (re.compile(r"\b(apt|apt-get|yum|dnf|pacman|zypper)\b[^|;&]*"
                r"(install|remove|upgrade|update|erase)\b"),
     "安装/升级/卸载软件包，可能改变运行环境"),
    (re.compile(r"\b(pip|pip3|npm|yarn|pnpm|composer)\b[^|;&]*"
                r"(install|uninstall|update|upgrade)\b"),
     "变更应用依赖"),
    (re.compile(r"\b(tar|unzip|cp|mv|ln|mkdir|touch|chmod|chown)\b"),
     "文件系统写操作"),
    (re.compile(r"\b(ip|ifconfig)\b[^|;&]*\b(set|add|del|down|up)\b|"
                r"\bnmcli\b[^|;&]*\b(connect|disconnect|down|up)\b"),
     "变更网络配置，可能导致断连"),
    (re.compile(r"\bsed\b[^|;&]*-i\b|\btee\b"), "就地修改文件"),
    (re.compile(r">\s*(?!/dev/null(?:\s|$|2>&1))[^|;& ]+"), "重定向写文件"),
    (re.compile(r"\bsudo\b"), "以管理员权限执行"),
    (re.compile(r"\b(ba|z|fi|da)?sh\b[^|;&]*\s-c\s|"
                r"\bpython[0-9.]*\b[^|;&]*\s-c\s|\bperl\b[^|;&]*\s-e\s"),
     "通过 -c/-e 执行字符串中的任意代码"),
    # Firewall/crontab mutation is detected by _segment_is_readonly: listing
    # forms (`ufw status`, `firewall-cmd --list*`, `iptables -S`, `crontab -l`)
    # are read-only; other forms are treated as mutating and require confirm.
]


def _first_token(segment: str) -> str:
    segment = segment.strip()
    # Strip leading env assignments like "sudo FOO=bar cmd".
    segment = re.sub(r"^(\s*[A-Za-z_][A-Za-z0-9_]*=\S+\s*)+", "", segment)
    segment = re.sub(r"^(sudo|nohup|nice|ionice|command|exec)\s+", "", segment)
    m = re.match(r"[A-Za-z0-9_.\-/]+", segment)
    if not m:
        return ""
    return Path(m.group(0)).name


def _segment_is_readonly(token: str, seg: str) -> bool:
    """Return True if a single (already split) sub-command is read-only."""
    if not token:
        return False
    # Explicitly mutating forms of otherwise read-only-looking commands.
    if token == "sed" and re.search(r"-i\b", seg):
        return False
    if token in ("systemctl", "service") and re.search(
        r"start|stop|restart|reload|enable|disable|mask", seg
    ):
        return False
    if token == "crontab" and not re.search(r"-l\b", seg):
        return False
    if token == "ufw" and not re.search(r"\bstatus\b", seg):
        return False
    if token in ("iptables", "ip6tables", "nft") and not re.search(
        r"(-L|-S|list)\b", seg
    ):
        return False
    if token == "firewall-cmd" and "--list" not in seg:
        return False
    if token == "ip" and not re.search(r"\b(show|get|list|monitor)\b", seg):
        return False
    if token == "fail2ban-client" and not re.search(r"status|get|banned", seg):
        return False
    if token == "sysctl" and (re.search(r"-w\b", seg) or "=" in seg):
        return False
    return token in _READ_ONLY_CMDS


def _strip_quotes(cmd: str) -> str:
    """Replace quoted string literals with an empty placeholder.

    Text inside quotes (echo strings, grep patterns) must not be parsed as
    shell commands, so pipes/operators hidden there are ignored. Backslash
    escapes are honoured inside double quotes.
    """
    out: list[str] = []
    i, n = 0, len(cmd)
    while i < n:
        ch = cmd[i]
        if ch in ("'", '"'):
            q = ch
            out.append("''")
            i += 1
            while i < n and cmd[i] != q:
                if q == '"' and cmd[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                i += 1
            i += 1  # skip closing quote
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def assess_command(command: str) -> dict:
    """Assess a shell command.

    Returns {level, read_only, reasons:[...]}. Quoted literals are masked so
    operators/words inside grep patterns or echo strings are not parsed as
    commands. High-risk rules run on the FULL (quote-masked) command so
    patterns spanning operators (pipe-to-shell, fork bombs) are detected; the
    command is then split on shell separators for caution/read-only analysis.
    Any command that is not provably read-only is at least caution.
    """
    reasons: list[str] = []
    seen: set[str] = set()

    def add(msg: str) -> None:
        if msg not in seen:
            seen.add(msg)
            reasons.append(msg)

    masked = _strip_quotes(command)
    level = RISK_SAFE

    if re.search(r"\$\(|\`|>\(|<\(", masked):
        add("[注意] 包含命令替换/进程替换，实际执行内容可能被隐藏")
        level = RISK_CAUTION

    # Danger rules against the full, quote-masked command.
    for pattern, reason in _DANGER_RULES:
        if pattern.search(masked):
            add(f"[高危] {reason}: {command.strip()[:160]}")
            level = RISK_DANGER

    segments = [s for s in _SHELL_SPLIT.split(masked) if s.strip()]
    if not segments:
        segments = [masked]

    all_read_only = True
    for seg in segments:
        seg = seg.strip()
        for pattern, reason in _CAUTION_RULES:
            if pattern.search(seg):
                add(f"[注意] {reason}: {seg[:120]}")
                if level != RISK_DANGER:
                    level = RISK_CAUTION
        if not _segment_is_readonly(_first_token(seg), seg):
            all_read_only = False

    if level == RISK_SAFE and all_read_only:
        return {"level": RISK_SAFE, "read_only": True, "reasons": []}
    # Non-read-only with no specific rule is still a mutating operation.
    if level == RISK_SAFE:
        level = RISK_CAUTION
    if not reasons:
        add("命令不属于已识别的只读命令集合，按变更类处理")
    return {"level": level, "read_only": False, "reasons": reasons}


# --------------------------------------------------------------------------- #
# Host-key policy
# --------------------------------------------------------------------------- #


class _HostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, store_path: str, trust_new: bool):
        self.store_path = Path(store_path)
        self.trust_new = trust_new

    def missing_host_key(self, client, hostname, key):
        fp = fingerprint(key)
        if self.trust_new:
            client.get_host_keys().add(hostname, key.get_name(), key)
            self.store_path.parent.mkdir(parents=True, exist_ok=True)
            client.get_host_keys().save(str(self.store_path))
            return
        raise paramiko.SSHException(
            f"UNKNOWN_HOST_KEY|{hostname}|{key.get_name()}|{fp}"
        )


# --------------------------------------------------------------------------- #
# Server connection + operations
# --------------------------------------------------------------------------- #


class Server:
    _lock = threading.Lock()

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.client: paramiko.SSHClient | None = None

    # -- connection -------------------------------------------------------- #

    def connect(self, trust_new: bool | None = None) -> dict:
        cfg = self.cfg
        if trust_new is None:
            trust_new = cfg.get("host_key_policy") == "trust_new"
        client = paramiko.SSHClient()

        known = Path(cfg.get("known_hosts", DEFAULT_KNOWN_HOSTS))
        if known.exists():
            client.load_host_keys(str(known))
        client.set_missing_host_key_policy(
            _HostKeyPolicy(str(known), trust_new)
        )

        kwargs = dict(
            hostname=cfg["host"],
            port=int(cfg["port"]),
            username=cfg["username"],
            timeout=int(cfg.get("connect_timeout", DEFAULT_CONNECT_TIMEOUT)),
            banner_timeout=int(cfg.get("connect_timeout", DEFAULT_CONNECT_TIMEOUT)),
            auth_timeout=int(cfg.get("connect_timeout", DEFAULT_CONNECT_TIMEOUT)),
            allow_agent=False,
            look_for_keys=False,
        )
        method = cfg.get("auth_method", "key")
        if method == "password":
            if not cfg.get("password"):
                raise ConfigError(
                    "密码认证缺少密码：请设置环境变量 "
                    f"{cfg.get('password_env', 'LINUX_OPS_PASSWORD')}。"
                )
            kwargs["password"] = cfg["password"]
        elif method == "agent":
            # Keys offered by a local SSH agent: SSH_AUTH_SOCK on Unix,
            # Pageant on Windows. No key material is handled by this program.
            kwargs["allow_agent"] = True
            kwargs["look_for_keys"] = False
        else:
            key_path = cfg.get("key_path")
            if not key_path:
                raise ConfigError(
                    "密钥认证缺少 key_path（私钥路径），或改用 auth_method=password/agent。"
                )
            if not Path(key_path).exists():
                raise ConfigError(f"私钥文件不存在: {key_path}")
            kwargs["key_filename"] = key_path
            if cfg.get("key_passphrase"):
                kwargs["passphrase"] = cfg["key_passphrase"]

        try:
            client.connect(**kwargs)
        except paramiko.BadHostKeyException as exc:
            record_connection(cfg, False, str(exc))
            raise HostKeyError(
                "服务器主机密钥与已保存记录不一致，可能是服务器重装，"
                "也可能遭遇中间人攻击(MITM)。在核实原因前不要继续连接。"
                f" 期望指纹: {fingerprint(exc.key) if exc.key else '?'}; "
                f"记录指纹: {fingerprint(exc.expected_key) if exc.expected_key else '?'}。"
                f"确认安全后可删除 {known} 中对应条目再信任。"
            )
        except paramiko.SSHException as exc:
            msg = str(exc)
            if msg.startswith("UNKNOWN_HOST_KEY"):
                record_connection(cfg, False, msg)
                _, host, algo, fp = msg.split("|")
                raise HostKeyError(
                    f"首次连接、主机密钥尚未信任：{host} {algo} {fp}。"
                    "请核实该指纹（在服务器控制台执行 "
                    "`ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub` 比对），"
                    "确认无误后运行 trust-host 工具/子命令予以信任。"
                )
            if "Authentication" in msg or "auth" in msg.lower():
                record_connection(cfg, False, msg)
                raise AuthError(f"认证失败：{msg}（检查用户名/密码/私钥是否正确）")
            record_connection(cfg, False, msg)
            raise ConnectionError_(f"SSH 连接失败: {msg}")
        except (socket.timeout, socket.error, OSError) as exc:
            record_connection(cfg, False, str(exc))
            raise ConnectionError_(f"无法连接到 {cfg['host']}:{cfg['port']}：{exc}")

        record_connection(cfg, True)
        self.client = client
        return {"connected": True, "host": cfg["host"], "port": cfg["port"]}

    def close(self) -> None:
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None

    def _ensure(self) -> paramiko.SSHClient:
        if self.client is None:
            self.connect()
        assert self.client is not None
        # Detect a dead transport and reconnect once.
        transport = self.client.get_transport()
        if transport is None or not transport.is_active():
            self.close()
            self.connect()
        return self.client  # type: ignore[return-value]

    # -- command execution ------------------------------------------------- #

    def run(
        self,
        command: str,
        timeout: int | None = None,
        confirm: bool = False,
        accept_risk: bool = False,
    ) -> dict:
        assessment = assess_command(command)
        level = assessment["level"]
        if level == RISK_CAUTION and not confirm:
            return {
                "executed": False,
                "blocked": True,
                "needs": "confirm",
                "assessment": assessment,
                "message": "该命令属于变更类操作，需要你明确确认后才会执行。",
            }
        if level == RISK_DANGER and not (confirm and accept_risk):
            return {
                "executed": False,
                "blocked": True,
                "needs": "confirm+accept_risk",
                "assessment": assessment,
                "message": "该命令属于高危操作，需要明确确认并接受风险后才会执行。",
            }

        timeout = int(timeout or self.cfg.get("command_timeout", DEFAULT_COMMAND_TIMEOUT))
        client = self._ensure()
        audit(self.cfg, "run", command, ok=True)
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            chan = stdout.channel
            exit_code = chan.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
        except socket.timeout:
            return {
                "executed": True,
                "timed_out": True,
                "exit_code": None,
                "timeout": timeout,
                "message": (
                    f"命令在 {timeout}s 后超时，可能仍在远程运行；"
                    "请用 ps/pgrep 确认，必要时再终止。"
                ),
            }
        except paramiko.SSHException as exc:
            audit(self.cfg, "run", command, ok=False)
            return {"executed": False, "error": f"执行失败: {redact(str(exc), self.cfg)}"}

        return {
            "executed": True,
            "exit_code": exit_code,
            "stdout": _truncate(redact(out, self.cfg), MAX_COMMAND_OUTPUT),
            "stderr": _truncate(redact(err, self.cfg), MAX_COMMAND_OUTPUT),
            "timed_out": False,
        }

    # -- file operations --------------------------------------------------- #

    def _sftp(self):
        client = self._ensure()
        return client.open_sftp()

    def list_directory(self, path: str = ".") -> dict:
        with self._lock:
            sftp = self._sftp()
            try:
                attrs = sftp.listdir_attr(path)
                items = []
                for a in sorted(attrs, key=lambda x: x.filename):
                    items.append({
                        "name": a.filename,
                        "type": "dir" if stat.S_ISDIR(a.st_mode or 0)
                        else ("link" if stat.S_ISLNK(a.st_mode or 0) else "file"),
                        "size": a.st_size,
                        "permissions": stat.filemode(a.st_mode) if a.st_mode else "?",
                        "mtime": _dt.datetime.fromtimestamp(
                            a.st_mtime or 0
                        ).strftime("%Y-%m-%d %H:%M")
                    })
                return {"path": path, "items": items}
            finally:
                sftp.close()

    def read_file(self, path: str, max_bytes: int = MAX_FILE_READ) -> dict:
        with self._lock:
            sftp = self._sftp()
            try:
                st = sftp.stat(path)
                total = st.st_size or 0
                with sftp.open(path, "rb") as fh:
                    raw = fh.read(max_bytes + 1)
                truncated = len(raw) > max_bytes
                raw = raw[:max_bytes]
                content = raw.decode("utf-8", errors="replace")
                return {
                    "path": path,
                    "size": total,
                    "truncated": truncated,
                    "content": _truncate(content, max_bytes),
                }
            finally:
                sftp.close()

    def write_file(
        self,
        path: str,
        content: str,
        backup: bool = False,
        confirm: bool = False,
        mode: int | None = None,
    ) -> dict:
        if not confirm:
            return {
                "executed": False,
                "blocked": True,
                "needs": "confirm",
                "message": f"写入远程文件 {path} 需要明确确认。",
            }
        with self._lock:
            sftp = self._sftp()
            try:
                backup_path = None
                if backup:
                    try:
                        with sftp.open(path, "rb") as old:
                            old_data = old.read()
                        ts = _dt.datetime.now().strftime("%Y%m%d%H%M%S")
                        backup_path = f"{path}.bak.{ts}"
                        with sftp.open(backup_path, "wb") as bk:
                            bk.write(old_data)
                    except IOError:
                        backup_path = None  # original did not exist
                with sftp.open(path, "wb") as fh:
                    fh.write(content.encode("utf-8"))
                if mode is not None:
                    sftp.chmod(path, mode)
                audit(self.cfg, "write_file", path, ok=True)
                return {
                    "executed": True,
                    "path": path,
                    "bytes": len(content.encode("utf-8")),
                    "backup": backup_path,
                }
            finally:
                sftp.close()

    def upload_file(self, local: str, remote: str, confirm: bool = False) -> dict:
        if not Path(local).exists():
            return {"executed": False, "error": f"本地文件不存在: {local}"}
        if not confirm:
            return {
                "executed": False,
                "blocked": True,
                "needs": "confirm",
                "message": f"上传并写入远程 {remote} 需要明确确认。",
            }
        with self._lock:
            sftp = self._sftp()
            try:
                sftp.put(local, remote)
                audit(self.cfg, "upload", f"{local} -> {remote}", ok=True)
                return {"executed": True, "local": local, "remote": remote}
            finally:
                sftp.close()

    def download_file(self, remote: str, local: str) -> dict:
        with self._lock:
            sftp = self._sftp()
            try:
                Path(local).parent.mkdir(parents=True, exist_ok=True)
                sftp.get(remote, local)
                return {"executed": True, "remote": remote, "local": local}
            finally:
                sftp.close()

    # -- background jobs --------------------------------------------------- #

    def start_job(
        self,
        command: str,
        confirm: bool = False,
        accept_risk: bool = False,
    ) -> dict:
        """Start a long-running command that keeps running in the background.

        Output (stdout+stderr merged) is streamed to a local log file and a
        bounded in-memory tail; poll with get_job. Same risk gating as run().
        """
        assessment = assess_command(command)
        level = assessment["level"]
        if level == RISK_CAUTION and not confirm:
            return {
                "executed": False, "blocked": True, "needs": "confirm",
                "assessment": assessment,
                "message": "该后台任务属于变更类操作，需要你明确确认后才会启动。",
            }
        if level == RISK_DANGER and not (confirm and accept_risk):
            return {
                "executed": False, "blocked": True,
                "needs": "confirm+accept_risk", "assessment": assessment,
                "message": "该后台任务属于高危操作，需要确认并接受风险后才会启动。",
            }

        client = self._ensure()
        transport = client.get_transport()
        if transport is None:
            raise ConnectionError_("SSH 传输未建立，无法启动后台任务。")
        jobs_dir = DEFAULT_DIR / "jobs"
        jobs_dir.mkdir(parents=True, exist_ok=True)
        job_id = os.urandom(4).hex()
        log_path = jobs_dir / f"{job_id}.log"

        # Wrapper records the remote PID (process-group leader) so stop_job can
        # kill the whole group, then execs the requested command.
        wrapped = (
            "LINUX_OPS_JOB_CMD=" + shlex.quote(command)
            + " bash -c 'printf \"__JOBPID__:%s\\n\" \"$$\" ;"
            + " exec bash -c \"$LINUX_OPS_JOB_CMD\"'"
        )
        chan = transport.open_session()
        chan.set_combine_stderr(True)   # before exec: merge stderr into the log
        chan.exec_command(wrapped)
        audit(self.cfg, "start_job", command, ok=True)
        job = Job(job_id, command, chan, str(log_path))
        self._register_job(job)
        return {"started": True, **job.snapshot()}

    def _register_job(self, job: "Job") -> None:
        with self._lock:
            if not hasattr(self, "jobs"):
                self.jobs: dict[str, "Job"] = {}
            self.jobs[job.id] = job
            if len(self.jobs) > Job.MAX_JOBS:
                done = sorted(
                    (j for j in self.jobs.values() if j.status == "exited"),
                    key=lambda j: j.ended or "",
                )
                for j in done:
                    if len(self.jobs) <= Job.MAX_JOBS:
                        break
                    self.jobs.pop(j.id, None)

    def list_jobs(self) -> dict:
        """List all tracked background jobs (status/pid/exit code, no tail)."""
        with self._lock:
            jobs = list(getattr(self, "jobs", {}).values())
        return {"jobs": [j.snapshot(include_tail=False) for j in jobs]}

    def get_job(self, job_id: str, tail_bytes: int = 16 * 1024) -> dict:
        """Return one job's status and the tail of its streamed output."""
        with self._lock:
            job = getattr(self, "jobs", {}).get(job_id)
        if job is None:
            return {"executed": False, "error": f"找不到后台任务 {job_id}"}
        tail_bytes = max(1, min(int(tail_bytes), Job.MEM_CAP))
        return job.snapshot(tail_bytes=tail_bytes)

    def stop_job(self, job_id: str, confirm: bool = False) -> dict:
        """Terminate a background job's remote process group. Requires confirm."""
        if not confirm:
            return {
                "executed": False, "blocked": True, "needs": "confirm",
                "message": f"停止后台任务 {job_id} 需要明确确认。",
            }
        with self._lock:
            job = getattr(self, "jobs", {}).get(job_id)
        if job is None:
            return {"executed": False, "error": f"找不到后台任务 {job_id}"}
        if job.status == "running":
            pid = job.pid
            if pid:
                kill = (
                    f"kill -TERM -{pid} 2>/dev/null; kill -TERM {pid} 2>/dev/null; "
                    f"sleep 1; kill -KILL -{pid} 2>/dev/null; "
                    f"kill -KILL {pid} 2>/dev/null"
                )
                self.run(kill, confirm=True, accept_risk=True)
            try:
                job.channel.close()
            except Exception:
                pass
        audit(self.cfg, "stop_job", job_id, ok=True)
        job.thread.join(timeout=2)
        return {"stopped": True, **job.snapshot()}

    # -- atomic patching --------------------------------------------------- #

    def patch_file(
        self,
        path: str,
        operations: list,
        backup: bool = True,
        confirm: bool = False,
    ) -> dict:
        """Apply exact find/replace edits to a remote file atomically.

        operations: list of {"find": str, "replace": str,
        "replace_all"?: bool}. The current file is read first; every `find`
        must be present and unique (unless replace_all). On ANY mismatch the
        operation aborts before writing anything. New content is staged to a
        temp file in the same directory (permissions copied), then atomically
        renamed over the target, optionally after a timestamped backup.
        """
        if not confirm:
            return {
                "executed": False, "blocked": True, "needs": "confirm",
                "message": f"补丁修改 {path} 需要明确确认。",
            }
        if not isinstance(operations, list) or not operations:
            return {"executed": False, "error": "operations 必须是非空列表"}

        with self._lock:
            sftp = self._sftp()
            try:
                try:
                    with sftp.open(path, "rb") as fh:
                        original = fh.read().decode("utf-8", errors="replace")
                    fmode = stat.S_IMODE(sftp.stat(path).st_mode or 0o644)
                    exists = True
                except IOError:
                    original, fmode, exists = "", 0o644, False

                content = original
                applied = []
                for i, op in enumerate(operations):
                    find = op.get("find") if isinstance(op, dict) else None
                    repl = op.get("replace", "") if isinstance(op, dict) else ""
                    if not isinstance(find, str):
                        return {"executed": False,
                                "error": f"第 {i + 1} 个操作缺少 find 字符串"}
                    count = content.count(find)
                    if count == 0:
                        return {
                            "executed": False, "blocked": True, "conflict": True,
                            "message": "第 %d 个操作的 find 在文件中不存在（文件可能已被改动），已中止，未做任何修改。" % (i + 1),
                            "find": find[:200],
                        }
                    if not op.get("replace_all") and count > 1:
                        return {
                            "executed": False, "blocked": True, "conflict": True,
                            "message": "第 %d 个操作的 find 出现 %d 次（非唯一），已中止；如需全部替换请设 replace_all。" % (i + 1, count),
                            "find": find[:200],
                        }
                    content = content.replace(
                        find, repl, -1 if op.get("replace_all") else 1
                    )
                    applied.append({
                        "index": i + 1,
                        "replacements": count if op.get("replace_all") else 1,
                    })

                if content == original:
                    return {"executed": False, "noop": True,
                            "message": "改动后内容与原文件一致，无需写入。"}

                tmp = f"{path}.linux-ops.tmp.{os.urandom(3).hex()}"
                with sftp.open(tmp, "wb") as fh:
                    fh.write(content.encode("utf-8"))
                try:
                    sftp.chmod(tmp, fmode)
                except IOError:
                    pass
            finally:
                sftp.close()

        backup_path = None
        steps = []
        if backup and exists:
            ts = _dt.datetime.now().strftime("%Y%m%d%H%M%S")
            backup_path = f"{path}.bak.{ts}"
            steps.append(
                f"cp -a {shlex.quote(path)} {shlex.quote(backup_path)}"
            )
        steps.append(f"mv -f {shlex.quote(tmp)} {shlex.quote(path)}")
        r = self.run(" && ".join(steps), confirm=True)
        audit(self.cfg, "patch_file", path, ok=bool(r.get("executed")))
        if not r.get("executed"):
            return {"executed": False, "error": "原子替换失败", "stage": r}
        return {
            "executed": True, "path": path, "existed": exists,
            "operations": applied, "backup": backup_path,
            "bytes": len(content.encode("utf-8")),
        }


# A long-running remote command with streamed, captured output -------------- #


class Job:
    MEM_CAP = 256 * 1024          # in-memory tail retained per job
    MAX_JOBS = 50

    def __init__(self, job_id: str, command: str, channel, log_path: str):
        self.id = job_id
        self.command = command
        self.channel = channel
        self.log_path = log_path
        self.started = _now()
        self.ended: str | None = None
        self.exit_code: int | None = None
        self.pid: int | None = None
        self.status = "running"
        self._tail = ""
        self._total = 0
        self._lock = threading.Lock()
        self._file = open(log_path, "ab")
        self.thread = threading.Thread(target=self._pump, daemon=True)
        self.thread.start()

    def _pump(self) -> None:
        chan = self.channel
        pre = ""
        try:
            while True:
                data = chan.recv(65536)
                if not data:
                    break
                text = data.decode("utf-8", errors="replace")
                if self.pid is None:
                    pre += text
                    m = re.search(r"__JOBPID__:(\d+)", pre)
                    if m:
                        self.pid = int(m.group(1))
                        rest = pre[: m.start()] + pre[m.end():]
                        if rest.startswith("\n"):
                            rest = rest[1:]
                        pre = ""
                        if rest:
                            self._write(rest)
                    elif len(pre) > 4096:
                        self._write(pre)
                        pre = ""
                else:
                    self._write(text)
            if pre and self.pid is None:
                self._write(pre)
        except Exception:
            import traceback
            self.error = traceback.format_exc()
        finally:
            try:
                self.exit_code = chan.recv_exit_status()
            except Exception:
                self.exit_code = None
            with self._lock:
                self.status = "exited"
                self.ended = _now()
            try:
                self._file.close()
            except Exception:
                pass

    def _write(self, text: str) -> None:
        if not text:
            return
        data = text.encode("utf-8", errors="replace")
        with self._lock:
            try:
                self._file.write(data)
                self._file.flush()
            except Exception:
                pass
            self._tail += text
            self._total += len(data)
            if len(self._tail.encode("utf-8", errors="replace")) > self.MEM_CAP:
                b = self._tail.encode("utf-8", errors="replace")
                self._tail = b[-self.MEM_CAP:].decode("utf-8", errors="replace")

    def snapshot(self, tail_bytes: int = 16 * 1024,
                 include_tail: bool = True) -> dict:
        with self._lock:
            base = {
                "job_id": self.id,
                "command": self.command,
                "status": self.status,
                "pid": self.pid,
                "exit_code": self.exit_code,
                "started": self.started,
                "ended": self.ended,
                "total_log_bytes": self._total,
                "log_file": self.log_path,
                "error": getattr(self, "error", None),
            }
            if include_tail:
                tail = self._tail
                b = tail.encode("utf-8", errors="replace")
                base["tail"] = b[-tail_bytes:].decode("utf-8", errors="replace")
            return base


# Custom exception labels --------------------------------------------------- #


class HostKeyError(Exception):
    pass


class AuthError(Exception):
    pass


class ConnectionError_(Exception):
    pass


# --------------------------------------------------------------------------- #
# Curated, read-only operational views
# --------------------------------------------------------------------------- #


def system_overview(srv: Server) -> dict:
    cmds = {
        "hostname": "hostname; hostnamectl 2>/dev/null | head -5",
        "os": "cat /etc/os-release 2>/dev/null | head -4",
        "kernel": "uname -a",
        "uptime": "uptime",
        "cpu": "nproc; lscpu 2>/dev/null | grep -m1 'Model name'",
        "memory": "free -h",
        "disk": "df -h -x tmpfs -x devtmpfs 2>/dev/null",
        "load": "cat /proc/loadavg",
    }
    out = {}
    for key, cmd in cmds.items():
        r = srv.run(cmd)
        out[key] = r.get("stdout", r.get("error", "")) if r.get("executed") else r
    return {"overview": out}


def check_services(srv: Server) -> dict:
    r = srv.run(
        "systemctl --failed --no-pager 2>/dev/null; "
        "echo '---running---'; "
        "systemctl list-units --type=service --state=running --no-pager "
        "--no-legend 2>/dev/null | head -40"
    )
    return r


def check_logs(srv: Server, service: str | None = None, lines: int = 50) -> dict:
    lines = max(1, min(int(lines), 500))
    if service:
        cmd = f"journalctl -u {shlex.quote(service)} -n {lines} --no-pager 2>/dev/null"
    else:
        cmd = f"journalctl -n {lines} --no-pager -p warning 2>/dev/null"
    return srv.run(cmd)


def security_check(srv: Server) -> dict:
    """Read-only intrusion / exposure triage. No changes are made."""
    checks = {
        "failed_logins": (
            "echo '== lastb (failed logins) =='; lastb -n 15 2>/dev/null; "
            "echo '== auth/secure log failures =='; "
            "grep -iE 'failed|invalid|authentication failure' "
            "/var/log/auth.log /var/log/secure 2>/dev/null | tail -15"
        ),
        "successful_logins": "echo '== last =='; last -n 15 2>/dev/null",
        "logged_in_now": "echo '== who/w =='; who; w",
        "listening_ports": (
            "echo '== listening sockets =='; "
            "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null"
        ),
        "firewall": (
            "echo '== firewall =='; ufw status 2>/dev/null; "
            "firewall-cmd --list-all 2>/dev/null; "
            "iptables -S 2>/dev/null | head -20"
        ),
        "top_processes": "ps aux --sort=-%cpu | head -12",
        "cron_persistence": (
            "echo '== system cron dirs =='; "
            "ls -la /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly "
            "2>/dev/null; "
            "echo '== user crontab spools =='; "
            "tail -n +1 /var/spool/cron/crontabs/* /var/spool/cron/* 2>/dev/null"
        ),
        "ssh_config": (
            "echo '== sshd key settings =='; "
            "grep -iE '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|"
            "PermitEmptyPasswords|Port)' /etc/ssh/sshd_config 2>/dev/null"
        ),
        "fail2ban": "fail2ban-client status 2>/dev/null",
    }
    results = {}
    for key, cmd in checks.items():
        r = srv.run(cmd)
        results[key] = r.get("stdout", "") if r.get("executed") else r
    return {"security_check": results}


# --------------------------------------------------------------------------- #
# Port forwarding — a separate, permission-gated capability
# --------------------------------------------------------------------------- #
# 借鉴 slepp-ssh-mcp：转发独立成工具，客户端可只授予命令执行而不授予转发。
# 默认绑定 127.0.0.1；0.0.0.0 暴露由 MCP 层要求 accept_risk。


def _pump_bytes(src, dst) -> None:
    """双向转发的单向泵：src -> dst，结束后半关闭 dst。"""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


class PortForward:
    def __init__(self, forward_id: str, direction: str, **meta):
        self.id = forward_id
        self.direction = direction
        self.meta = meta
        self.transport = None
        self.local_sock = None          # 本地监听 socket（local 转发）
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.started = _now()

    def snapshot(self) -> dict:
        return {"forward_id": self.id, "direction": self.direction,
                "started": self.started, **self.meta}


class PortForwardManager:
    def __init__(self):
        self.forwards: dict[str, PortForward] = {}

    @staticmethod
    def _new_id() -> str:
        return os.urandom(3).hex()

    def start_local(self, srv: "Server", local_port: int,
                    remote_host: str, remote_port: int,
                    bind_address: str = "127.0.0.1") -> dict:
        """本地转发：本机 bind_address:local_port -> 网关可达的 remote_host:remote_port。"""
        transport = srv._ensure().get_transport()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind_address, int(local_port)))
        listener.listen(16)
        fwd = PortForward(self._new_id(), "local", bind_address=bind_address,
                          local_port=int(local_port), remote_host=remote_host,
                          remote_port=int(remote_port))
        fwd.transport = transport
        fwd.local_sock = listener

        def accept_loop() -> None:
            listener.settimeout(1.0)
            while not fwd.stop_event.is_set():
                try:
                    conn, addr = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    channel = transport.open_channel(
                        "direct-tcpip", (remote_host, int(remote_port)), addr)
                except Exception:
                    conn.close()
                    continue
                t1 = threading.Thread(target=_pump_bytes,
                                      args=(conn, channel), daemon=True)
                t2 = threading.Thread(target=_pump_bytes,
                                      args=(channel, conn), daemon=True)
                t1.start(); t2.start()
                fwd.threads.extend([t1, t2])

        th = threading.Thread(target=accept_loop, daemon=True)
        th.start()
        fwd.threads.append(th)
        self.forwards[fwd.id] = fwd
        return fwd.snapshot()

    def start_remote(self, srv: "Server", remote_port: int,
                     local_host: str, local_port: int,
                     bind_address: str = "127.0.0.1") -> dict:
        """远程转发：网关 bind_address:remote_port -> 本机可达的 local_host:local_port。"""
        transport = srv._ensure().get_transport()
        transport.request_port_forward(bind_address, int(remote_port))
        fwd = PortForward(self._new_id(), "remote", bind_address=bind_address,
                          remote_port=int(remote_port), local_host=local_host,
                          local_port=int(local_port))
        fwd.transport = transport

        def handle_loop() -> None:
            while not fwd.stop_event.is_set():
                chan = transport.accept(timeout=1.0)
                if chan is None:
                    continue
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((local_host, int(local_port)))
                except Exception:
                    try:
                        chan.close()
                    except Exception:
                        pass
                    continue
                t1 = threading.Thread(target=_pump_bytes,
                                      args=(chan, sock), daemon=True)
                t2 = threading.Thread(target=_pump_bytes,
                                      args=(sock, chan), daemon=True)
                t1.start(); t2.start()
                fwd.threads.extend([t1, t2])

        th = threading.Thread(target=handle_loop, daemon=True)
        th.start()
        fwd.threads.append(th)
        self.forwards[fwd.id] = fwd
        return fwd.snapshot()

    def list_forwards(self) -> dict:
        return {"forwards": [f.snapshot() for f in self.forwards.values()]}

    def stop_forward(self, forward_id: str) -> dict:
        fwd = self.forwards.pop(forward_id, None)
        if fwd is None:
            raise ConfigError(f"找不到端口转发 {forward_id!r}")
        fwd.stop_event.set()
        if fwd.local_sock is not None:
            try:
                fwd.local_sock.close()
            except Exception:
                pass
        if fwd.direction == "remote" and fwd.transport is not None:
            try:
                fwd.transport.cancel_port_forward(
                    fwd.meta["bind_address"], fwd.meta["remote_port"])
            except Exception:
                pass
        return {"stopped": True, "forward_id": forward_id}
