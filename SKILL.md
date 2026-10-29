---
name: linux-ops-ssh
description: "Securely connect to and operate a remote Linux server over SSH/SFTP. Use when the user wants to connect to a Linux server/host, run remote shell or bash commands, edit/create/read/patch remote files, upload or download files, run background build/deploy jobs, deploy or update a website/service, inspect logs and errors, check service/process/resource status (CPU/memory/disk), or perform security/intrusion/attack triage (failed logins, listening ports, firewall, suspicious activity). Triggers include phrases like 连接 / 登录 Linux 服务器、远程执行命令、bash/ssh、后台任务、部署网页、看报错 / 日志、服务状态、磁盘 / 内存 / CPU、被攻击 / 入侵排查 / 异常登录、封禁 IP、打补丁. Supports key, password and SSH-agent auth; credentials are never logged; every mutating/high-risk action needs explicit user confirmation. Covers general Linux administration and operations."
---

# Linux Ops

## Overview

在本机（Windows / macOS / Linux）通过 SSH/SFTP 安全地操作远程 Linux 服务器，覆盖通用运维：远程执行命令、文件读写/传输/原子补丁、后台任务、服务/日志/资源查看、网页部署、报错与安全入侵排查。**支持单进程多主机档案（profile）**：一个配置文件可定义多台机器，每个工具都能用可选 `host` 参数显式指定目标，显式指定优先于全局默认，连接按档案缓存互不干扰。本包同时提供标准 **MCP 服务器**（任何兼容 MCP 的 Agent 都能调用）与 **Skill 包装**（支持技能系统的 Agent 使用）。

能力以一个 **MCP 服务器**（`scripts/mcp_server.py`，stdio）暴露；运行时未绑定该 MCP 时，使用等价的 **CLI**（`scripts/cli.py`）。两者共用同一安全核心 `scripts/linux_ops_core.py`。优先用 MCP，MCP 不可用时用 CLI，不要手写 SSH 协议或绕过核心。

## Core Rules（必须遵守）

- **只读操作可直接执行；任何变更/高危操作必须先获得用户明确确认。**
- 变更类（caution）需 `confirm=True`；高危类（danger）需 `confirm=True` 且 `accept_risk=True`。不确定时先调用 `assess_command_risk`。
- “明确确认”指用户在知晓**目标主机、命令、影响范围、回滚方式**后的当轮肯定答复；“你看着办”不算。
- 密码/私钥/口令/令牌不记录、不外泄、不在回复展示；密码默认从环境变量读取。
- 主机密钥默认严格校验：未知密钥先让用户核对指纹，再用 `trust_host`；密钥变更（可能 MITM）拒绝连接。
- 被拒绝或被阻断的操作不自动重试，不换写法绕过确认。
- 多档案下，调用前确认目标档案名；未显式传 `host` 时打到 `active_host`。涉及未在配置中定义的主机/账号需用户另行授权。
- 结果中区分“远程实际返回的事实”与“我的推断”，不臆造执行结果。

## 首次使用（一次性）

**推荐：一键安装器**。它会自动选用已带 paramiko+mcp 的 Python（离线可用），否则建隔离 venv 装依赖；把服务部署到 `~/.linux-ops/server`、由模板生成 `config.json`、自检 stdio 启动，并生成 MCP 注册片段：

- Windows（在本技能根目录的 PowerShell）：
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; .\install.ps1`
- Linux / macOS / Git Bash：`bash install.sh`

然后：
1. 编辑 `~/.linux-ops/config.json`（Windows：`C:\Users\<你>\.linux-ops\config.json`）填写 host/port/username；配置路径可用环境变量 `LINUX_OPS_CONFIG` 覆盖。
2. 选择认证方式 `auth_method`：
   - `key`（默认，推荐 Ed25519）：填 `key_path`；私钥口令走环境变量 `LINUX_OPS_KEY_PASSPHRASE`。
   - `password`：密码走环境变量 `LINUX_OPS_PASSWORD`，不要写进配置或对话。
   - `agent`：使用本机 SSH agent（Windows 用 Pageant，Unix 用 `SSH_AUTH_SOCK`），不经手密钥材料。
3. 在 Doubao「连接器 / MCP」设置中添加本地/自定义 MCP（stdio），粘贴 `~/.linux-ops/mcp-server-snippet.json` 的内容并保存、信任。
4. 首次连接执行 `test_connection`；提示未知主机密钥时，在服务器控制台用 `ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub` 核对指纹，确认无误后执行 `trust_host`（TOFU）。

> 手动安装（不用安装器）：`pip install -r scripts/requirements.txt`，再自行复制脚本、按 `scripts/config.example.json` 建配置。

## 安全模型 / 风险闸门

每条命令先评估，复合命令按 `; && || | & 换行` 拆成子命令逐一检查（引号内容被遮蔽，防止管道/通配符误判）：

| 级别 | 含义 | 执行条件 |
|------|------|----------|
| `safe` | 只读（ls/cat/grep/ps/df/free/ss/查询类 systemctl、journalctl 等） | 直接执行 |
| `caution` | 增删改文件、装/升级依赖、服务 start/stop/restart/reload、kill、改网络、`sh -c` 等 | `confirm=True` |
| `danger` | 删根/家目录、格式化、写块设备、关机重启、清防火墙、杀 PID 1、管道执行网络脚本、反向 shell、改 sudoers/账号、清日志等 | `confirm=True` + `accept_risk=True` |

写文件、上传、补丁、停后台任务同样需要 `confirm`。不满足条件时**不执行**并返回所需确认项。口径与红线见 `references/security.md`。

## 多主机档案（多机切换 · 互不干扰）

**起因**：单例 MCP 被多个会话/项目共享时，任何一次“切机器”都会改动全局唯一配置，影响所有使用者且无版本记录。多档案把“当前默认”和“单次调用目标”分开。

**配置格式（向后兼容）**：一个文件含 `active_host`、`defaults`、`hosts`；老的单主机格式（顶层直接写 `host`）自动识别为单一档案，行为不变。

```json
{
  "active_host": "128",
  "defaults": { "port": 22, "username": "root", "auth_method": "key",
                "command_timeout": 120, "host_key_policy": "strict" },
  "hosts": {
    "128": { "host": "10.0.0.10", "key_path": "~/.ssh/id_ed25519",
             "default_dir": "/opt/app/example", "tags": ["test", "app"] },
    "200": { "host": "10.0.0.20", "key_path": "~/.ssh/id_ed25519",
             "tags": ["other"] }
  }
}
```

**档案管理工具**：

| 工具 | 作用 |
|------|------|
| `list_hosts()` | 列出所有档案：名称、地址、端口、用户、标签、描述、默认目录 |
| `current_host()` | 返回当前默认档案及解析后的实际连接参数 |
| `use_host(name)` | 切换默认档案并原子写回（`.tmp` + `os.replace`），写 `config_switch` 审计；**不断开其他连接**，不影响在跑的后台任务 |

**显式 `host` 参数（关键自研点）**：除 `assess_command_risk`（纯本地分析）外，所有工具都接受可选 `host`。

- 优先级：显式 `host` > `active_host`；不传即走默认。
- 连接按档案名缓存（`_servers: dict[label, Server]`），`Server` 实例不跨档案复用；某档案连接失败不污染其他档案。
- 每个返回体都带 `host`（档案名），便于确认实际打到了哪台。
- 后台任务按档案隔离：`start_job` 与 `get_job/stop_job/list_jobs` 必须在同一档案（必要时显式传同一个 `host`）。

**审计**：每条审计含 `profile`（档案名）与 `host`（实际地址）；`use_host` 额外记录 `config_switch`，“谁切走了配置”可追溯。

**非法档案**：传不存在的 `host` 会返回清晰错误并附可用档案列表，而不是 traceback。

## 复用 ~/.ssh/config 与配置校验

- **ssh_config_host**：档案可设 `ssh_config_host`（别名），用 `paramiko.SSHConfig` 解析 `~/.ssh/config`（可用 `ssh_config_file` 改路径），只补档案未显式定义的 `host/username/port/key_path`，显式值优先。便于复用已有的 `Host` 别名、跳板机命名习惯。
- **配置 schema 校验**：每次加载/解析档案都跑 `validate_config`，必填缺失、端口越界（非 1–65535）、`auth_method`/`host_key_policy` 非法、超时非正整数都会**早失败**并给出可读错误，而不是连到一半才报错。

## 端口转发（独立 · 可单独授权）

转发是与命令执行**分离**的能力，客户端可只授予命令/文件工具而不授予转发。默认绑定回环，避免把端口暴露到全网。

| 工具 | 作用 |
|------|------|
| `start_port_forward(direction, local_port, remote_port, remote_host="127.0.0.1", bind_address="127.0.0.1", confirm, accept_risk, host=None)` | `direction=local`：本机 `local_port` 经网关转发到 `remote_host:remote_port`；`direction=remote`：网关 `remote_port` 反向转发到本机可达的 `remote_host:local_port`。需 `confirm`；`bind_address` 非回环（如 `0.0.0.0`）还需 `accept_risk` |
| `list_port_forwards(host=None)` | 列出进行中的转发（id/方向/绑定/目标） |
| `stop_port_forward(forward_id, confirm, host=None)` | 按 id 停止转发并关闭监听/通道；需 `confirm` |

转发线程均为守护线程，停止时关闭监听并取消网关侧绑定；远程转发调用 `cancel_port_forward`。

## Tools（MCP 工具目录，共 25 个）

多档案
- `list_hosts()` / `current_host()` / `use_host(name)`：见上一节。

连接
- `test_connection(host=None)`：测试连通性，返回 whoami/hostname/uptime。
- `trust_host(host=None)`：核对指纹后信任并保存主机密钥（TOFU）。

命令
- `assess_command_risk(command)`：只评估、不执行，返回 safe/caution/danger 与原因；纯本地分析，无需 host。
- `run_command(command, timeout=None, confirm=False, accept_risk=False, host=None)`：远程执行 shell 命令；省略 timeout 时用配置的 `command_timeout`（默认 120s）。
- `run_script(script_b64, interpreter="bash", timeout=120, confirm=False, accept_risk=False, host=None)`：**长/多行脚本首选**。脚本以 Base64 传输（纯 ASCII），写到远程临时文件后执行并自动清理，彻底避开引号、换行、中文注释导致的「Invalid request parameters」。`interpreter` 仅支持 bash/sh/python3；风险预检与 `run_command` 同级。

文件（SFTP）
- `list_directory(path=".", host=None)`：列目录（名称/类型/大小/权限/时间）。
- `read_file(path, host=None)`：读取远程文本文件（有上限；大/二进制用 download）。
- `write_file(path, content, backup=True, confirm=False, host=None)`：写入文件，默认留时间戳 `.bak`。
- `upload_file(local, remote, confirm=False, host=None)` / `download_file(remote, local, host=None)`：文件传输。

后台任务
- `start_job(command, confirm=False, accept_risk=False, host=None)`：后台运行长命令（构建/部署），返回 `job_id`，stdout+stderr 合并流式落本地日志并保留有界尾缓冲。
- `list_jobs(host=None)`：列出任务的 status/pid/exit code（不含输出）。
- `get_job(job_id, tail_bytes=16384, host=None)`：查看单个任务状态与输出尾部；`error` 字段给出泵异常。
- `stop_job(job_id, confirm=False, host=None)`：终止任务的远程进程组（先 TERM 后 KILL）。

原子补丁
- `patch_file(path, operations, backup=True, confirm=False, host=None)`：对远程文件做精确 find/replace。`operations=[{"find":..., "replace":..., "replace_all"?:bool}]`；先读原文，每个 `find` 必须存在且唯一（除非 `replace_all`），任一不符整体中止、不写任何内容；新内容写同目录临时文件（复制权限）后原子 `rename` 覆盖目标，可选时间戳 `.bak`。

只读运维视图
- `system_overview(host=None)`：OS/内核/运行时长/CPU/内存/磁盘/负载。
- `check_services(host=None)`：失败单元与运行中的服务。
- `check_logs(service="", lines=50, host=None)`：指定服务日志或最近 warning 级日志。
- `security_check(host=None)`：登录记录、在线用户、监听端口、防火墙、高占用进程、cron 持久化、sshd 设置、fail2ban（只读）。

端口转发（独立授权）
- `start_port_forward(...)` / `list_port_forwards(host=None)` / `stop_port_forward(forward_id, confirm, host=None)`：见上一节。

> 多档案下 `list_hosts()` 每个档案还带 `last_connect`（进程内记录的上次连通时间/结果，不主动探活）。

> 后台任务生命周期绑定常驻的 MCP 服务器进程：任务在该进程内持续运行，完整日志落 `~/.linux-ops/jobs/<job_id>.log`；CLI 每次是新进程，任务不跨进程存活。

## CLI 等价用法（MCP 不可用时）

在 `scripts/` 目录下，输出均为 JSON。全局参数 `--host <档案名>` 可指定多档案中的具体机器：

```
python cli.py hosts
python cli.py --host 128 test
python cli.py test
python cli.py trust-host
python cli.py assess "systemctl restart nginx"
python cli.py run "df -h"
python cli.py --host 200 run "hostname"
python cli.py run "systemctl reload nginx" --confirm
python cli.py ls /var/log
python cli.py read /etc/nginx/nginx.conf
python cli.py write /var/www/html/index.html --file ./index.html --confirm
python cli.py upload ./index.html /var/www/html/index.html --confirm
python cli.py download /var/log/nginx/error.log ./error.log
python cli.py job-start "make deploy" --confirm
python cli.py jobs
python cli.py job-get <job_id>
python cli.py job-stop <job_id> --confirm
python cli.py patch /etc/nginx/nginx.conf --ops-file ./ops.json --confirm
python cli.py overview
python cli.py services
python cli.py logs --service nginx --lines 100
python cli.py security
```

## Workflow

1. 明确目标主机、操作意图与范围；需要变更时先向用户说明影响与回滚方式。
2. 只读信息优先：用 `system_overview` / `check_services` / `check_logs` / `read_file` / `list_directory` / `security_check` 收集事实。
3. 需要执行命令时先判断风险（必要时 `assess_command_risk`）；变更/高危操作按规则取得确认并带相应标志执行。
4. 长任务用 `start_job`，再用 `list_jobs`/`get_job` 轮询，必要时 `stop_job`。
5. 执行后核对退出码、stdout/stderr 与服务状态；命令超时先确认远程进程再处理。关键改动保留 `.bak` 直到确认稳定。

## References（按需阅读）

- 安全机制、凭据管理、服务器加固、风险分级口径、入侵处置、行为红线：`references/security.md`（涉及凭据、攻击/入侵、高危操作时必读）。
- 网页部署、报错排查、攻击排查、资源问题、配置编辑的标准步骤：`references/ops-playbooks.md`。

## Failure Handling

- MCP 工具不可用 → 改用 `scripts/cli.py` 同功能子命令；不要手写 SSH 协议或用其他通道替代。
- 认证失败 → 检查用户名/密码/私钥与对应环境变量，不把凭据写入日志。
- 主机密钥未知/变更 → 未知则核对指纹后 `trust_host`；变更可能是 MITM，核实前不继续。
- 命令超时 → 提示可能仍在运行，先 `ps/pgrep` 确认；连接断开会自动重连一次。
- 同一动作失败两次应换通道或排查根因；部分结果或空结果如实标注查询范围，不用记忆补全。
