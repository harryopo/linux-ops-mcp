# 安全规范（linux-ops）

本技能通过 SSH/SFTP 操作远程 Linux，安全是默认前提。下面说明**已强制实现的机制**、**服务器侧加固建议**，以及**怀疑被入侵时的处置流程**。

## 1. 已在代码中强制的安全机制

| 机制 | 行为 |
|------|------|
| 凭据不落日志 | 密码/口令默认从环境变量读取；审计日志与返回结果会对已知密钥做脱敏替换 |
| 主机密钥校验 | 默认 `strict`：未知主机密钥拒绝连接；密钥与记录不一致（可能 MITM）直接报错；仅在用户核对指纹后用 `trust-host` 信任（TOFU） |
| 命令风险分级 | 每条命令先 `assess_command` 评估，复合命令按 `; && || |` 拆分为子命令逐一检查，防止破坏性后缀藏在只读命令后 |
| 变更需确认 | `caution` 级需 `confirm`；`danger` 级需 `confirm + accept_risk`；未满足则**不执行**并返回原因 |
| 输出/读取上限 | 命令输出与文件读取默认截断，避免一次性拉取超大内容 |
| 审计日志 | 连接、执行、写入、上传、信任主机等动作写入本地 `audit.log`（JSON Lines，脱敏） |
| 连接收敛 | 默认 `allow_agent=False`、`look_for_keys=False`，只使用配置指定的凭据，不转发 SSH agent |
| 超时 | 连接与命令均有超时；命令超时后提示先确认进程再决定是否终止，避免误判 |

## 2. 凭据与配置

- 配置文件位于 `~/.linux-ops/config.json`（Windows：`C:\Users\<你>\.linux-ops\config.json`），参考 `scripts/config.example.json`。
- **优先使用 SSH 密钥**（推荐 Ed25519）。密码仅用于临时场景，并通过环境变量传入：
  - PowerShell（当前窗口）：`$env:LINUX_OPS_PASSWORD="你的密码"`
  - 私钥口令：`$env:LINUX_OPS_KEY_PASSPHRASE="口令"`
- 不要把真实密码写进配置文件、聊天记录、截图或任何会被分享/提交的文件。
- 配置目录建议仅当前用户可访问；不要把 `~/.linux-ops` 放进同步盘或公共目录。

生成并安装密钥（本机）：
```powershell
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\id_ed25519
# 把公钥放到服务器（一次性，需输入密码）：
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh user@服务器 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

## 3. 服务器侧加固建议（一次性配置）

建议为运维/部署创建**专用普通用户**，按需授予最小 sudo 权限，而不是直接用 root：

```bash
sudo adduser deploy
sudo mkdir -p /etc/sudoers.d && echo 'deploy ALL=(ALL) /bin/systemctl reload nginx, /bin/systemctl restart nginx' | sudo tee /etc/sudoers.d/deploy
sudo chmod 440 /etc/sudoers.d/deploy
```

SSH 与基础防护（编辑 `/etc/ssh/sshd_config` 后 `sudo systemctl reload sshd`）：
- `PermitRootLogin no`
- `PasswordAuthentication no`（确认密钥可登录后再关闭密码登录）
- `PubkeyAuthentication yes`、`PermitEmptyPasswords no`
- 非必要可改默认端口（注意同步放行防火墙）

其它：
- 启用防火墙，只放行必要端口：`ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw enable`
- 安装并启用 fail2ban 防爆破：`sudo apt install fail2ban -y && sudo systemctl enable --now fail2ban`
- 及时打安全更新：`sudo apt update && sudo apt upgrade`（变更类，需确认窗口）
- Web/数据库等服务不要用 root 运行，数据目录最小权限，密钥与 `.env` 不进版本库。

## 4. 风险分级口径

- **safe（只读）**：ls/cat/grep/ps/df/free/ss/systemctl status/journalctl（查询）等，不改变系统状态，直接执行。
- **caution（变更）**：增删改文件、安装/升级依赖、服务 start/stop/restart/reload、kill 进程、网络配置变更等，**必须用户明确确认**。
- **danger（高危）**：删除根/家目录、格式化、写块设备、关机重启、清空防火墙、终止 PID 1、管道执行网络脚本、反向 shell、改 sudoers/账号、清空日志等，**必须确认 + 显式接受风险**。

判定为"用户明确确认"的标准：用户在清楚知道**目标主机、命令内容、影响范围、回滚方式**后给出的当轮肯定答复；模糊的"你看着办"不算确认。高危操作不复述、不缓存、不自动重试。

## 5. 怀疑被入侵 / 遭遇网络攻击时（只读排查优先）

先用 `security_check`（或 `cli.py security`）做**只读**取证，再决定处置：

1. **评估范围**：失败/成功登录记录（`lastb`、`last`、auth.log/secure）、当前在线用户（`who`/`w`）、来源 IP。
2. **查暴露面**：监听端口（`ss -tulnp`）、异常外联、防火墙状态。
3. **查持久化**：各用户 crontab、`/etc/cron*`、异常 systemd 服务、SSH authorized_keys、`~/.bashrc`。
4. **查运行体**：高占用/异常进程（`ps aux`）、可疑路径、临时目录中的可执行文件、挖矿/反弹 shell 特征。
5. **查 Web 面**：Web 访问/错误日志中的扫描、注入、webshell 痕迹。

处置原则：
- **先保留证据**：把关键命令输出、相关日志下载留存（`download_file`），记录时间线。
- **阻断要谨慎且需确认**：封禁攻击 IP（`ufw deny from <ip>`、fail2ban）、隔离受影响账户/服务，必要时断网或下线——这些都是变更/高危操作，必须用户确认后执行，并评估对业务的影响。
- **不要在被攻破的主机上直接 `rm` 删除可疑文件**，以免破坏证据或触发恶意脚本；优先隔离 + 留证。
- 无法确认清除干净时，最稳妥是**保留磁盘快照后重装系统、轮换全部凭据/密钥、从干净备份恢复**。
- 涉及数据泄露或合规要求时，按所在组织/法规流程上报。

## 6. Agent 行为红线

- 不主动执行任何变更/高危命令；不把"建议执行"当成"已授权执行"。
- 不记录、不外泄密码、私钥、口令、令牌；不在回复中展示这些内容。
- 不自动重试被拒绝的操作，不换写法绕过确认。
- 一次只操作配置指定的那台服务器；涉及额外主机/账号需用户另行授权。
- 结果中区分"远程实际返回的事实"与"我的推断"。
