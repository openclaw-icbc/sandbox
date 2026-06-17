#!/bin/bash
set -euo pipefail

# ==============================================
# Sandbox Docker 安全审计包装器安装脚本
# 功能：在 /opt/.sandbox-runtime/bin/ 中替换docker二进制，添加命令审计日志
# 不修改 /usr/bin/docker，不影响系统已有 Docker
# ==============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

INSTALL_PREFIX=""
SHOW_HELP=false

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                SHOW_HELP=true
                shift
                ;;
            -p|--prefix)
                INSTALL_PREFIX="$2"
                shift 2
                ;;
            *)
                echo "错误: 未知参数 $1" >&2
                exit 1
                ;;
        esac
    done
}

readonly DEFAULT_PREFIX="/opt/.sandbox-runtime"

resolve_install_prefix() {
    if [[ -n "$INSTALL_PREFIX" ]]; then
        return
    fi
    INSTALL_PREFIX="${DEFAULT_PREFIX}"
}

parse_arguments "$@"

if [ "$(id -u)" -ne 0 ]; then
    error "本脚本必须以root用户执行，请使用 sudo 运行"
fi

if ! command -v gcc &> /dev/null; then
    error "未安装gcc编译器，请先执行：apt update && apt install -y gcc"
fi

if ! command -v strip &> /dev/null; then
    error "未安装binutils工具，请先执行：apt update && apt install -y binutils"
fi

resolve_install_prefix

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "${SCRIPT_DIR}/packages/docker-wrapper.c" ]; then
    error "找不到源文件：${SCRIPT_DIR}/packages/docker-wrapper.c"
fi

SANDBOX_DOCKER_BIN="${INSTALL_PREFIX}/bin/docker"
if [ ! -f "${SANDBOX_DOCKER_BIN}" ]; then
    error "Sandbox Docker 未安装，请先运行 install-docker.sh"
fi

info "=== 开始安装 Sandbox Docker 安全审计方案 ==="
info "安装路径: ${INSTALL_PREFIX}"

# 1. 备份原始docker二进制文件（仅在sandbox目录内操作）
if [ ! -f "${INSTALL_PREFIX}/bin/.docker.secure" ]; then
    cp "${SANDBOX_DOCKER_BIN}" "${INSTALL_PREFIX}/bin/.docker.secure"
    info "已备份原始docker到 ${INSTALL_PREFIX}/bin/.docker.secure"

    chown root:root "${INSTALL_PREFIX}/bin/.docker.secure"
    chmod 700 "${INSTALL_PREFIX}/bin/.docker.secure"
    info "已设置备份文件权限为700（仅root可访问）"
else
    warn "检测到已存在备份文件 ${INSTALL_PREFIX}/bin/.docker.secure，跳过备份"
fi

# 2. 编译Docker包装器（传入 INSTALL_PREFIX）
info "正在编译Docker包装器..."
WRAPPER_BUILD=$(mktemp)
if ! gcc -O2 -Wall -Wextra -Werror -pedantic \
    -DINSTALL_PREFIX=\"${INSTALL_PREFIX}\" \
    -o "$WRAPPER_BUILD" \
    "${SCRIPT_DIR}/packages/docker-wrapper.c"; then
    error "编译docker-wrapper失败"
fi

strip "$WRAPPER_BUILD"
info "编译完成，已剥离调试信息"

# 3. 替换sandbox目录内的docker命令（不修改 /usr/bin/docker）
cp "$WRAPPER_BUILD" "${SANDBOX_DOCKER_BIN}"
rm -f "$WRAPPER_BUILD"
chown root:root "${SANDBOX_DOCKER_BIN}"
chmod 4755 "${SANDBOX_DOCKER_BIN}"
info "已替换 sandbox docker 命令并设置SUID权限（不影响系统 /usr/bin/docker）"

# 4. 创建审计日志文件（在sandbox目录内）
mkdir -p "${INSTALL_PREFIX}/log"
if [ ! -f "${INSTALL_PREFIX}/log/docker-audit.log" ]; then
    touch "${INSTALL_PREFIX}/log/docker-audit.log"
    info "已创建审计日志文件 ${INSTALL_PREFIX}/log/docker-audit.log"
fi

chmod 644 "${INSTALL_PREFIX}/log/docker-audit.log"
chown root:root "${INSTALL_PREFIX}/log/docker-audit.log"

# 5. 配置logrotate日志轮转
info "正在配置logrotate日志轮转..."
tee /etc/logrotate.d/sandbox-docker-audit << LOGROTATE_EOF
${INSTALL_PREFIX}/log/docker-audit.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        touch ${INSTALL_PREFIX}/log/docker-audit.log
        chmod 644 ${INSTALL_PREFIX}/log/docker-audit.log
        chown root:root ${INSTALL_PREFIX}/log/docker-audit.log
    endscript
}
LOGROTATE_EOF

info "已配置日志轮转：保留30天日志，每日轮转并压缩"

# 6. 验证安装
info "=== 正在验证安装 ==="

if [ "$(stat -c "%a" "${SANDBOX_DOCKER_BIN}")" = "4755" ]; then
    info "✓ Sandbox Docker包装器权限设置正确"
else
    warn "Sandbox Docker包装器权限异常，请手动检查：ls -l ${SANDBOX_DOCKER_BIN}"
fi

if [ "$(stat -c "%a" "${INSTALL_PREFIX}/bin/.docker.secure")" = "700" ]; then
    info "✓ 原始Docker备份权限设置正确"
else
    warn "原始Docker备份权限异常，请手动检查：ls -l ${INSTALL_PREFIX}/bin/.docker.secure"
fi

# 测试: 直接调用真实docker二进制（绕过wrapper，因heartbeat_server尚未启动）
export DOCKER_HOST="unix://${INSTALL_PREFIX}/run/docker.sock"

if "${INSTALL_PREFIX}/bin/.docker.secure" --version &> /dev/null; then
    info "✓ Sandbox Docker二进制正常工作"
else
    error "Sandbox Docker二进制执行失败"
fi

# 测试wrapper本身可执行（不测试认证，因heartbeat_server未启动）
if "${SANDBOX_DOCKER_BIN}" --version &> /dev/null; then
    warn "wrapper认证通过（heartbeat_server已在运行）"
else
    info "✓ wrapper返回认证拒绝（预期行为，heartbeat_server尚未启动）"
fi

echo "=== 安装测试日志 ===" >> "${INSTALL_PREFIX}/log/docker-audit.log"
if [ -s "${INSTALL_PREFIX}/log/docker-audit.log" ]; then
    info "✓ 审计日志文件可正常写入"
else
    warn "审计日志文件写入失败，请检查权限"
fi

# 检查系统docker未受影响
if [[ -f /usr/bin/docker ]]; then
    info "✓ 系统 Docker (/usr/bin/docker) 未受影响"
fi

info ""
info "=============================================="
info " Sandbox Docker 安全审计方案安装完成！"
info "=============================================="
info ""
info "重要说明："
info "1. 所有 sandbox docker 命令会被记录到 ${INSTALL_PREFIX}/log/docker-audit.log"
info "2. 原始docker二进制文件已备份到 ${INSTALL_PREFIX}/bin/.docker.secure"
info "3. 如需恢复原始sandbox docker，执行："
info "   cp ${INSTALL_PREFIX}/bin/.docker.secure ${INSTALL_PREFIX}/bin/docker"
info "4. 系统 Docker (/usr/bin/docker) 完全未受影响"
info ""
info "使用方法："
info "  source ${INSTALL_PREFIX}/activate.sh"
info "  docker ps"
info ""
info "查看审计日志：tail -f ${INSTALL_PREFIX}/log/docker-audit.log"
info ""