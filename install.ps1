# =============================================================================
# linux-ops 安装脚本 (Windows PowerShell)
#
# 功能:
#   1. 自动选用一个已带 paramiko + mcp 的 Python（优先 Doubao 运行时）；
#      找不到时在 ~/.linux-ops/venv 建隔离环境并安装依赖（需联网）
#   2. 把 MCP 服务脚本部署到稳定位置 ~/.linux-ops/server
#   3. 缺少 config.json 时由模板生成（不覆盖已有配置）
#   4. 自检 MCP 服务器能否以 stdio 启动
#   5. 生成标准 MCP 注册片段 ~/.linux-ops/mcp-server-snippet.json，
#      供在 Doubao「连接器 / MCP 设置」里添加本地（stdio）服务器时粘贴
#
# 用法 (在本技能根目录的 PowerShell 中):
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\install.ps1
# 可选:
#   -UseVenv   强制创建隔离 venv（默认优先复用已带依赖的解释器，离线可用）
#   -Force     重新部署服务脚本
# =============================================================================

[CmdletBinding()]
param(
    [switch]$UseVenv,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Write-Host "==> linux-ops 安装开始"

# ---------------------------------------------------------------------------
# 0. 路径
# ---------------------------------------------------------------------------
$OPS = Join-Path $env:USERPROFILE ".linux-ops"
$SERVER_DIR = Join-Path $OPS "server"
$JOBS_DIR = Join-Path $OPS "jobs"
New-Item -ItemType Directory -Force -Path $OPS, $SERVER_DIR, $JOBS_DIR | Out-Null

$ScriptSrc = Join-Path $PSScriptRoot "scripts"
Write-Host "    运维目录: $OPS"

# ---------------------------------------------------------------------------
# 1. 选择带依赖的 Python
# ---------------------------------------------------------------------------
function Test-Deps {
    param([string]$Py)
    if (-not $Py -or -not (Test-Path $Py)) { return $false }
    try {
        & $Py -c "import sys, paramiko, mcp; sys.exit(0)" 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

$PY = $null

if (-not $UseVenv) {
    $candidates = New-Object System.Collections.Generic.List[string]
    $onPath = (Get-Command python -ErrorAction SilentlyContinue)
    if ($onPath) { $candidates.Add($onPath.Source) }
    # Doubao 托管运行时（路径中的 base 哈希可能随版本变化，动态探测）
    Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA "Doubao\User Data\sandbox_runtime\bases") `
        -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object { $candidates.Add($_.FullName) }
    $py3 = (Get-Command python3 -ErrorAction SilentlyContinue)
    if ($py3) { $candidates.Add($py3.Source) }

    foreach ($c in $candidates) {
        if (Test-Deps $c) { $PY = $c; break }
    }
    if ($PY) { Write-Host "    复用已带依赖的 Python: $PY" }
}

# 2. 找不到则创建 venv（需联网）
if (-not $PY) {
    $base = $null
    foreach ($c in @((Get-Command python -ErrorAction SilentlyContinue).Source,
                     (Get-Command python3 -ErrorAction SilentlyContinue).Source)) {
        if ($c -and (Test-Path $c)) { $base = $c; break }
    }
    if (-not $base) {
        Write-Error "未找到 Python（>=3.10）。请先安装 Python，或在已有 paramiko+mcp 的环境中重跑。"
        exit 1
    }
    $VENV = Join-Path $OPS "venv"
    $VPY = Join-Path $VENV "Scripts\python.exe"
    if (-not (Test-Path $VPY)) {
        Write-Host "    创建隔离虚拟环境: $VENV"
        & $base -m venv $VENV
    }
    Write-Host "    安装依赖 paramiko + mcp（需联网，约 10-30 秒）..."
    & $VPY -m pip install -U pip | Out-Null
    & $VPY -m pip install -r (Join-Path $ScriptSrc "requirements.txt")
    if (-not (Test-Deps $VPY)) {
        Write-Error "依赖安装失败（可能无法访问 PyPI）。可在能联网环境装好后重跑，或手动指定解释器。"
        exit 1
    }
    $PY = $VPY
    Write-Host "    使用 venv Python: $PY"
}

# ---------------------------------------------------------------------------
# 3. 部署服务脚本到稳定位置
# ---------------------------------------------------------------------------
$files = @("linux_ops_core.py", "mcp_server.py", "cli.py")
foreach ($f in $files) {
    $src = Join-Path $ScriptSrc $f
    if (-not (Test-Path $src)) { Write-Error "缺少 $src"; exit 1 }
    Copy-Item $src (Join-Path $SERVER_DIR $f) -Force
}
Write-Host "    已部署服务脚本 -> $SERVER_DIR"

# 3b. 缺少 config.json 时由模板生成（绝不覆盖已有配置）
$cfg = Join-Path $OPS "config.json"
if (-not (Test-Path $cfg)) {
    Copy-Item (Join-Path $ScriptSrc "config.example.json") $cfg
    Write-Host "    已生成配置模板: $cfg（请填写 host/用户名/认证）"
} else {
    Write-Host "    保留已有配置: $cfg"
}

$SRV = Join-Path $SERVER_DIR "mcp_server.py"

# ---------------------------------------------------------------------------
# 4. 自检：以 stdio 启动一次
# ---------------------------------------------------------------------------
Write-Host "    自检 MCP 服务器启动..."
$INIT = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"installer","version":"1.0"}}}'
# 注意：不能用 PowerShell 管道把字符串喂给原生进程——PS 会在 stdin 前加一个
# UTF-8 BOM，导致首条 JSON-RPC 解析失败。改为写临时文件 + cmd 输入重定向，
# 按原始字节喂给服务器。
$initFile = Join-Path $OPS ".selftest-init.json"
[IO.File]::WriteAllText($initFile, $INIT, (New-Object Text.UTF8Encoding($false)))
$cmdLine = '"' + $PY + '" "' + $SRV + '" < "' + $initFile + '"'
$out = cmd /c $cmdLine
Remove-Item $initFile -Force -ErrorAction SilentlyContinue
if (($out | Out-String) -match "linux-ops") {
    Write-Host "    [OK] MCP 服务器可正常启动"
} else {
    Write-Host "    [警告] 自检未捕获到预期输出，请在 Doubao 添加连接器后用 test_connection 验证。"
}

# ---------------------------------------------------------------------------
# 5. 生成标准 MCP 注册片段
# ---------------------------------------------------------------------------
$snippet = [ordered]@{
    mcpServers = [ordered]@{
        "linux-ops" = [ordered]@{
            command = $PY
            args = @($SRV)
        }
    }
}
$snippetPath = Join-Path $OPS "mcp-server-snippet.json"
($snippet | ConvertTo-Json -Depth 6) | Set-Content -Path $snippetPath -Encoding UTF8
Write-Host "    已生成注册片段: $snippetPath"

Write-Host ""
Write-Host "==> 安装完成！接下来："
Write-Host "   1) 编辑 $cfg 填写 host / port / username 与认证方式（密码用环境变量 LINUX_OPS_PASSWORD）。"
Write-Host "   2) 在 Doubao 的「连接器 / MCP」设置中选择添加本地/自定义 MCP（stdio），"
Write-Host "      把 $snippetPath 的内容粘贴进去并保存、信任。"
Write-Host "   3) 首次连接先核对主机密钥指纹，再调用 trust_host；然后用 test_connection 验证。"
Write-Host "   注：Doubao 运行时升级后若解释器路径变化，重跑本脚本即可刷新片段。"
