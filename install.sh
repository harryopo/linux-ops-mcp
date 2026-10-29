#!/usr/bin/env bash
# =============================================================================
# linux-ops 安装脚本 (Linux / macOS / Git Bash)
#
# 功能:
#   1. 自动选用一个已带 paramiko + mcp 的 python3；找不到时在
#      ~/.linux-ops/venv 建隔离环境并安装依赖（需联网）
#   2. 把 MCP 服务脚本部署到 ~/.linux-ops/server
#   3. 缺少 config.json 时由模板生成（不覆盖已有配置）
#   4. 自检 MCP 服务器能否以 stdio 启动
#   5. 生成标准 MCP 注册片段 ~/.linux-ops/mcp-server-snippet.json
#
# 用法 (在本技能根目录):
#   bash install.sh
# 可选环境变量:
#   USE_VENV=1   强制创建隔离 venv
#
set -euo pipefail

echo "==> linux-ops 安装开始"

# 路径
OPS="$HOME/.linux-ops"
SERVER_DIR="$OPS/server"
JOBS_DIR="$OPS/jobs"
SCRIPT_SRC="$(cd "$(dirname "$0")/scripts" && pwd)"
mkdir -p "$OPS" "$SERVER_DIR" "$JOBS_DIR"
echo "    运维目录: $OPS"

# 判断某解释器是否已带依赖
has_deps() {
  [ -x "$1" ] && "$1" -c 'import sys, paramiko, mcp; sys.exit(0)' >/dev/null 2>&1
}

PY=""
if [ "${USE_VENV:-0}" != "1" ]; then
  for c in python3 python; do
    p="$(command -v "$c" 2>/dev/null || true)"
    if [ -n "$p" ] && has_deps "$p"; then PY="$p"; break fi
  done
  [ -n "$PY" ] && echo "    复用已带依赖的 Python: $PY"
fi

# 找不到则建 venv（需联网）
if [ -z "$PY" ]; then
  BASE=""
  for c in python3 python; do
    p="$(command -v "$c" 2>/dev/null || true)"
    if [ -n "$p" ]; then BASE="$p"; break fi
  done
  if [ -z "$BASE" ]; then
    echo "错误: 未找到 python3（>=3.10），请先安装。" >&2
    exit 1
  fi
  VENV="$OPS/venv"
  if [ ! -x "$VENV/bin/python" ]; then
    echo "    创建隔离虚拟环境: $VENV"
    "$BASE" -m venv "$VENV"
  fi
  echo "    安装依赖 paramiko + mcp（需联网）..."
  "$VENV/bin/python" -m pip install -U pip >/dev/null
  "$VENV/bin/python" -m pip install -r "$SCRIPT_SRC/requirements.txt"
  if ! has_deps "$VENV/bin/python"; then
    echo "错误: 依赖安装失败（可能无法访问 PyPI）。" >&2
    exit 1
  fi
  PY="$VENV/bin/python"
  echo "    使用 venv Python: $PY"
fi

# 部署服务脚本
for f in linux_ops_core.py mcp_server.py cli.py; do
  cp -f "$SCRIPT_SRC/$f" "$SERVER_DIR/$f"
done
echo "    已部署服务脚本 -> $SERVER_DIR"

# 缺少 config.json 时由模板生成
if [ ! -f "$OPS/config.json" ]; then
  cp "$SCRIPT_SRC/config.example.json" "$OPS/config.json"
  echo "    已生成配置模板: $OPS/config.json（请填写 host/用户名/认证）"
else
  echo "    保留已有配置: $OPS/config.json"
fi

SRV="$SERVER_DIR/mcp_server.py"

# 自检
echo "    自检 MCP 服务器启动..."
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"installer","version":"1.0"}}}'
if printf '%s\n' "$INIT" | "$PY" "$SRV" 2>/dev/null | grep -q "linux-ops"; then
  echo "    [OK] MCP 服务器可正常启动"
else
  echo "    [警告] 自检未捕获到预期输出，请在 Doubao 添加连接器后用 test_connection 验证。"
fi

# 生成注册片段（用 python 安全编码路径）
"$PY" - "$OPS/mcp-server-snippet.json" "$PY" "$SRV" <<'PYEOF'
import json, sys
out, py, srv = sys.argv[1], sys.argv[2], sys.argv[3]
data = {"mcpServers": {"linux-ops": {"command": py, "args": [srv]}}}
with open(out, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
PYEOF
echo "    已生成注册片段: $OPS/mcp-server-snippet.json"

echo ""
echo "==> 安装完成！接下来："
echo "   1) 编辑 $OPS/config.json 填写 host/port/username 与认证方式（密码用环境变量 LINUX_OPS_PASSWORD）。"
echo "   2) 在 Doubao 的「连接器 / MCP」设置中添加本地/自定义 MCP（stdio），"
echo "      粘贴 $OPS/mcp-server-snippet.json 的内容并保存、信任。"
echo "   3) 首次连接先核对主机密钥指纹，再调用 trust_host；然后用 test_connection 验证。"
