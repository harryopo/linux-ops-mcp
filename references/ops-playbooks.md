# 运维场景手册（linux-ops）

给出常见场景的**标准操作顺序**。只读步骤可直接执行；标注【需确认】的步骤必须先获得用户明确同意。通用兜底是 `run_command`，但优先用下面的专用工具。

> 约定：`S:` 表示 MCP 工具；CLI 等价写法在括号内给出（`python cli.py ...`）。

## 场景一：部署 / 更新网页（Nginx / Apache）

1. **先看环境**：`S:system_overview`（`overview`）、`S:check_services`（`services`），确认 Web 服务已安装且在运行。
2. **确认站点目录与配置**：
   - `S:read_file /etc/nginx/sites-enabled/default`（Nginx）找 `root` 目录，常见 `/var/www/html`。
   - Apache 常见 `/var/www/html`，配置在 `/etc/apache2/sites-enabled/`。
3. **备份现有版本**【需确认，建议保留】：
   - 打包当前目录：`S:run_command "sudo tar czf /var/www/backup-$(date +%F-%H%M).tgz -C /var/www html" confirm=True`
4. **上传新文件**【需确认】：
   - 单文件：`S:upload_file ./index.html /var/www/html/index.html confirm=True`
   - 多文件：先在本地产物目录打包，上传后在服务器解包（`tar xzf`，【需确认】）。
5. **校正属主/权限**【需确认】：
   - `S:run_command "sudo chown -R www-data:www-data /var/www/html && sudo find /var/www/html -type d -exec chmod 755 {} \; && sudo find /var/www/html -type f -exec chmod 644 {} \;" confirm=True`
6. **校验配置再加载**【需确认】：
   - Nginx：先 `sudo nginx -t`（只读校验），通过后 `sudo systemctl reload nginx`（reload 比 restart 平滑）。
   - Apache：`sudo apachectl configtest`，通过后 `sudo systemctl reload apache2`。
7. **验证**：
   - `S:run_command "curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1/"`
   - `S:check_logs service=nginx lines=30` 看是否有新报错。
8. **异常回滚**【需确认】：用第 3 步备份解包恢复，再 reload；并保留现场日志用于定位。

## 场景二：服务报错 / 网页打不开 / 5xx

按"由近及远、先只读"的顺序定位：

1. **服务状态**：`S:check_services`，或 `S:run_command "systemctl status nginx --no-pager -l"`。
2. **看日志**：
   - 单元日志：`S:check_logs service=nginx lines=100`。
   - Web 错误日志：`S:read_file /var/log/nginx/error.log`（Apache：`/var/log/apache2/error.log`），可配合 `tail`/`grep`。
3. **看端口/进程**：`S:run_command "ss -tulnp | grep -E ':80|:443'; ps aux | grep nginx"`。
4. **看资源**：`S:system_overview`，重点磁盘是否写满（`df -h`）、内存（`free -h`）、负载。
5. **看配置改动**：`nginx -t` / `apachectl configtest`；最近改动的站点文件。
6. **常见原因对照**：
   - 磁盘满 → 日志/缓存占满，清理前先确认对象（删除属【需确认】）。
   - 502/504 → 后端（PHP-FPM/Node/上游）未运行或超时，查对应服务状态与日志。
   - 403 → 目录权限/属主、缺少首页文件、SELinux（`getenforce`）。
   - 配置语法错误 → 改回上一版本，修复后再 reload（【需确认】）。
7. 修复动作（重启服务、改文件、清缓存）全部【需确认】，改完回到第 2、7 步验证。

## 场景三：遭遇网络攻击 / 异常登录排查

只读取证优先，详细处置见 `references/security.md` 第 5 节。

1. **一键只读体检**：`S:security_check`（`security`），覆盖登录记录、在线用户、监听端口、防火墙、高占用进程、cron 持久化、sshd 设置、fail2ban。
2. **聚焦来源**：
   - 失败爆破：`S:run_command "lastb -n 30; grep -iE 'failed|invalid' /var/log/auth.log /var/log/secure 2>/dev/null | tail -30"`
   - 成功登录：`S:run_command "last -n 20; who; w"`，核对是否有非预期时间/地点/用户登录。
3. **查当前威胁**：
   - 异常监听/外联：`ss -tulnp`、`ss -tnp state established`
   - 异常进程：`ps aux --sort=-%cpu | head`，关注挖矿、反弹 shell、`/tmp` 下可执行文件。
   - 持久化：各用户 crontab、`/etc/cron*`、异常 systemd 单元、`authorized_keys`、启动脚本。
4. **Web 攻击**：
   - `grep -E '(\.\./|<script|union.select|/wp-admin|eval\()' /var/log/nginx/access.log | tail`
   - 查最近被改动的 Web 文件（webshell）：`find /var/www -name '*.php' -mtime -7`
5. **留证**：用 `S:download_file` 保存相关日志/可疑文件，记录时间线。
6. **阻断（全部【需确认】，评估业务影响）**：
   - 封 IP：`sudo ufw deny from <IP>` 或 `sudo fail2ban-client set <jail> banip <IP>`
   - 隔离账户/服务、必要时下线；确认无法清除干净则快照后重装并轮换全部凭据。

## 场景四：资源与性能问题

- **磁盘**：`df -h`；定位大目录 `du -xh --max-depth=2 / | sort -rh | head -20`；清理日志/缓存前确认对象（删除【需确认】）。
- **内存**：`free -h`；占内存进程 `ps aux --sort=-%mem | head`。
- **CPU/负载**：`uptime`、`top -b -n1 | head -20`、`ps aux --sort=-%cpu | head`；结合 `iostat`/`vmstat` 判断是否 IO 瓶颈。
- **进程异常**：确认用途后再 `kill`/重启（【需确认】），不要直接 `kill -9` PID 1 或关键系统进程。
- **定时任务**：`crontab -l`、`ls /etc/cron.d`，核对是否有非预期任务。

## 场景五：文件与配置的安全编辑

1. 读取：`S:read_file <path>`；大/二进制文件用 `S:download_file`。
2. 修改：优先 `S:write_file path content backup=True confirm=True`（自动留 `.bak`）。
   - 只改其中几行时，优先 `S:patch_file path operations=[{"find":..., "replace":...}] confirm=True`：带冲突检测、临时文件 + 原子替换，避免整篇重写或覆盖他人改动。
3. 改关键配置（sshd、nginx、sudoers、防火墙）前：先备份、保留可回滚版本；改后用对应 `test/configtest` 校验，再 reload（【需确认】）。
4. 验证服务正常后再结束；保留 `.bak` 直到确认稳定。

## 场景六：高延迟 / 慢链路（VPN、SD-WAN、跨境、EasyTier）

在约 500ms RTT 的隧道上实测：每次调用的**握手 + 认证约占 5 秒**（整轮 7.5–8.1 秒），而服务器端命令执行仅毫秒级。核心思路是**减少调用次数、复用连接**，而不是一味调大超时。

1. **批量合并命令**：一次 `run_command` 携带 5–15 条相关命令，用 `;` / `&&` 连接、`echo '===== 段名 ====='` 分隔，把一次握手摊到多条命令上。例如把磁盘、内存、负载、端口合并成一次只读调用。
2. **超时放大**：非局域网主机把 `timeout` 设为 **90**（默认 30 在链路抖动到 1s+ RTT 时余量不足）；本核心连接的 banner/auth 超时随 connect_timeout 走，必要时在配置里调大 `connect_timeout`。
3. **超 60 秒的任务走后台**：打包、`docker save`、`rsync`、大目录 `du` 等用 `S:start_job` 启动，再用 `S:get_job` 轮询、`S:stop_job` 终止；不要在一次前台调用里长时间阻塞。
4. **复用连接**：本核心默认持久连接、断线自动重连，已天然省去重复握手；避免在脚本外反复新建连接。
5. **不要连续快速重连**：短时间密集探测可能触发网关限流，返回的不是 SSH 横幅而是类似 `Not allowed at this time` 的文本——这并非端口异常，等待约 1 分钟、拉开间隔再试。
6. 实测 `GSSAPIAuthentication=no` 之类的认证项调整对耗时几乎无增益，不必折腾；链路本身过慢时优先就近跳板或更换线路。
