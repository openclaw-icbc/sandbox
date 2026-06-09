#!/bin/bash
# OpenClaw Sandbox Docker 一键安装脚本
# 自动完成 Docker 安装、镜像加载和安全配置
# 默认安装到 /opt/.sandbox-runtime/
#
# 用法: sudo bash auto-install.sh [-p|--prefix PATH]
#   不指定路径时默认安装到 /opt/.sandbox-runtime/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step() { echo -e "${BLUE}[STEP]${NC} $1"; }

DEFAULT_PREFIX="/opt/.sandbox-runtime"
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
                echo "未知参数: $1" >&2
                exit 1
                ;;
        esac
    done
}

print_banner() {
    echo "========================================"
    echo "   Sandbox Docker 一键安装脚本"
    echo "========================================"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "此脚本必须以 root 用户运行"
    fi
}

main() {
    parse_arguments "$@"
    check_root

    if $SHOW_HELP; then
        echo "用法: sudo bash auto-install.sh [-p|--prefix PATH]"
        echo ""
        echo "  -p, --prefix  安装路径（默认: /opt/.sandbox-runtime）"
        echo ""
        echo "示例:"
        echo "  sudo bash auto-install.sh                  # 默认路径 /opt/.sandbox-runtime"
        echo "  sudo bash auto-install.sh -p /opt/sandbox  # 自定义路径"
        exit 0
    fi

    if [[ -z "$INSTALL_PREFIX" ]]; then
        INSTALL_PREFIX="${DEFAULT_PREFIX}"
    fi

    print_banner
    info "安装路径: ${INSTALL_PREFIX}"
    echo ""

    step "步骤 1/3: 安装 Sandbox Docker..."
    bash "${SCRIPT_DIR}/install-docker.sh" --force -p "${INSTALL_PREFIX}"
    if [[ $? -ne 0 ]]; then
        error "Docker 安装失败"
    fi
    info "Docker 安装完成"
    echo ""

    step "步骤 2/3: 加载镜像..."
    bash "${SCRIPT_DIR}/load-images.sh" -p "${INSTALL_PREFIX}"
    if [[ $? -ne 0 ]]; then
        error "镜像加载失败"
    fi
    info "镜像加载完成"
    echo ""

    step "步骤 3/3: 配置安全审计..."
    bash "${SCRIPT_DIR}/sec-docker.sh" -p "${INSTALL_PREFIX}"
    if [[ $? -ne 0 ]]; then
        error "安全配置失败"
    fi
    info "安全配置完成"
    echo ""

    echo "========================================"
    info "所有步骤已完成！Sandbox Docker 已安装并配置完毕"
    echo "========================================"
    echo ""
    info "使用方法："
    info "  ${INSTALL_PREFIX}/bin/docker ps"
    echo ""
    info "系统修改（可完整回退）："
    info "  /etc/systemd/system/sandbox-containerd.service"
    info "  /etc/systemd/system/sandbox-docker.service"
    info "  /etc/logrotate.d/sandbox-docker-audit"
    info "  未修改: /usr/bin, /etc/docker, /var/lib/docker"
    echo ""
    info "卸载方法："
    info "  sudo bash ${SCRIPT_DIR}/uninstall.sh -p ${INSTALL_PREFIX}"
    echo ""
}

main "$@"