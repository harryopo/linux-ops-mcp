#!/usr/bin/env python3
"""
cli.py — Command-line interface to the same secure Linux operations core.

This is the reliable fallback when the MCP server is not registered with a
host, and a convenient way to test. Every command prints a JSON result.

Examples:
    python cli.py test
    python cli.py trust-host
    python cli.py assess "rm -rf /tmp/x"
    python cli.py run "df -h"
    python cli.py run "systemctl restart nginx" --confirm
    python cli.py ls /var/log
    python cli.py read /etc/nginx/nginx.conf
    python cli.py write /var/www/html/index.html --file ./index.html --confirm
    python cli.py upload ./index.html /var/www/html/index.html --confirm
    python cli.py download /var/log/nginx/error.log ./error.log
    python cli.py overview
    python cli.py services
    python cli.py logs --service nginx --lines 100
    python cli.py security

Global options:
  --config <path>  (default ~/.linux-ops/config.json or LINUX_OPS_CONFIG)
  --host <profile> (multi-profile config; pick a specific host profile)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import linux_ops_core as core  # noqa: E402


def _print(obj, code: int = 0) -> int:
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    return code


def _srv(args) -> core.Server:
    cfg = core.load_config(args.config)
    if getattr(args, "host", None):
        return core.Server(core.config_for_host(cfg, args.host))
    return core.Server(cfg)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Secure remote Linux operations CLI")
    p.add_argument("--config", help="path to config JSON")
    p.add_argument("--host", help="host profile name (multi-profile config)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("hosts", help="list configured host profiles")
    sub.add_parser("test", help="test SSH connectivity")
    sub.add_parser("trust-host", help="trust and remember the host key (TOFU)")

    a = sub.add_parser("assess", help="assess command risk without executing")
    a.add_argument("command")

    r = sub.add_parser("run", help="execute a shell command")
    r.add_argument("command")
    r.add_argument("--timeout", type=int, default=30)
    r.add_argument("--confirm", action="store_true")
    r.add_argument("--accept-risk", action="store_true")

    ls = sub.add_parser("ls", help="list a remote directory")
    ls.add_argument("path", nargs="?", default=".")

    rd = sub.add_parser("read", help="read a remote file")
    rd.add_argument("path")

    wr = sub.add_parser("write", help="create/overwrite a remote file")
    wr.add_argument("path")
    g = wr.add_mutually_exclusive_group(required=True)
    g.add_argument("--content", help="text content to write")
    g.add_argument("--file", help="local file whose UTF-8 content is written")
    wr.add_argument("--backup", dest="backup", action="store_true", default=True)
    wr.add_argument("--no-backup", dest="backup", action="store_false")
    wr.add_argument("--confirm", action="store_true")

    up = sub.add_parser("upload", help="upload a local file via SFTP")
    up.add_argument("local")
    up.add_argument("remote")
    up.add_argument("--confirm", action="store_true")

    dl = sub.add_parser("download", help="download a remote file via SFTP")
    dl.add_argument("remote")
    dl.add_argument("local")

    js = sub.add_parser("job-start", help="start a background job")
    js.add_argument("command")
    js.add_argument("--confirm", action="store_true")
    js.add_argument("--accept-risk", action="store_true")

    sub.add_parser("jobs", help="list background jobs")

    jg = sub.add_parser("job-get", help="get a background job's output")
    jg.add_argument("job_id")
    jg.add_argument("--tail", type=int, default=16384)

    jx = sub.add_parser("job-stop", help="stop a background job")
    jx.add_argument("job_id")
    jx.add_argument("--confirm", action="store_true")

    pa = sub.add_parser("patch", help="atomic find/replace patch of a remote file")
    pa.add_argument("path")
    pog = pa.add_mutually_exclusive_group(required=True)
    pog.add_argument("--ops", help="JSON list of {find,replace,replace_all?}")
    pog.add_argument("--ops-file", help="file containing the JSON operations list")
    pa.add_argument("--backup", dest="backup", action="store_true", default=True)
    pa.add_argument("--no-backup", dest="backup", action="store_false")
    pa.add_argument("--confirm", action="store_true")

    sub.add_parser("overview", help="system summary")
    sub.add_parser("services", help="failed/running services")

    lg = sub.add_parser("logs", help="recent journal logs")
    lg.add_argument("--service", default="")
    lg.add_argument("--lines", type=int, default=50)

    sub.add_parser("security", help="read-only intrusion/exposure triage")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        # assess needs no server / credentials; handle it before loading config.
        if args.cmd == "assess":
            return _print(core.assess_command(args.command))

        # hosts: list profiles, no connection needed.
        if args.cmd == "hosts":
            cfg = core.load_config(args.config)
            names = core.host_names(cfg)
            if not names:
                return _print({"hosts": [], "active": None,
                               "note": "单主机配置（无 hosts 字段）",
                               "current": {"host": cfg.get("host")}})
            return _print({"hosts": names, "active": cfg.get("active_host")})

        srv = _srv(args)

        if args.cmd == "test":
            srv.connect()
            r = srv.run("whoami; hostname; uptime")
            return _print({"connected": True, "info": r.get("stdout", "")})

        if args.cmd == "trust-host":
            srv.connect(trust_new=True)
            r = srv.run("whoami; hostname")
            return _print({"trusted": True, "info": r.get("stdout", "")})

        if args.cmd == "run":
            return _print(srv.run(args.command, timeout=args.timeout,
                                  confirm=args.confirm,
                                  accept_risk=args.accept_risk))

        if args.cmd == "ls":
            return _print(srv.list_directory(args.path))

        if args.cmd == "read":
            return _print(srv.read_file(args.path))

        if args.cmd == "write":
            content = args.content
            if args.file:
                content = Path(args.file).read_text(encoding="utf-8")
            return _print(srv.write_file(args.path, content,
                                         backup=args.backup,
                                         confirm=args.confirm))

        if args.cmd == "upload":
            return _print(srv.upload_file(args.local, args.remote,
                                          confirm=args.confirm))

        if args.cmd == "download":
            return _print(srv.download_file(args.remote, args.local))

        if args.cmd == "job-start":
            return _print(srv.start_job(args.command, confirm=args.confirm,
                                        accept_risk=args.accept_risk))

        if args.cmd == "jobs":
            return _print(srv.list_jobs())

        if args.cmd == "job-get":
            return _print(srv.get_job(args.job_id, tail_bytes=args.tail))

        if args.cmd == "job-stop":
            return _print(srv.stop_job(args.job_id, confirm=args.confirm))

        if args.cmd == "patch":
            raw = args.ops
            if args.ops_file:
                raw = Path(args.ops_file).read_text(encoding="utf-8")
            try:
                ops = json.loads(raw)
            except json.JSONDecodeError as exc:
                return _print({"error": f"--ops 不是合法 JSON: {exc}"}, 1)
            return _print(srv.patch_file(args.path, ops, backup=args.backup,
                                         confirm=args.confirm))

        if args.cmd == "overview":
            return _print(core.system_overview(srv))

        if args.cmd == "services":
            return _print(core.check_services(srv))

        if args.cmd == "logs":
            return _print(core.check_logs(srv, args.service or None,
                                         args.lines))

        if args.cmd == "security":
            return _print(core.security_check(srv))

        return _print({"error": f"unknown command {args.cmd}"}, 1)

    except (core.ConfigError, core.HostKeyError, core.AuthError,
            core.ConnectionError_) as exc:
        return _print({"error": str(exc), "type": exc.__class__.__name__}, 1)
    except Exception as exc:  # noqa: BLE001
        return _print({"error": core.redact(str(exc)),
                       "type": exc.__class__.__name__}, 1)


if __name__ == "__main__":
    sys.exit(main())
