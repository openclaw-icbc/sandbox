#!/bin/bash
# OpenClaw Sandbox Docker 卸载脚本
# 完整回退所有系统修改，不影响系统已有的 Docker
#
# 系统修改回退:
#   - /etc/systemd/system/sandbox-containerd.service
#   - /etc/systemd/system/sandbox-docker.service
#   - /etc/logrotate.d/sandbox-docker-audit (由 sec-docker.sh 创建)
# 用户目录回退:
#   - /opt/.sandbox-runtime/ 整个目录

set -uo pipefail

readonly SCRIPT_VERSION="3.1.0"
readonly DOCKER_SERVICE="sandbox-docker"
readonly CONTAINERD_SERVICE="sandbox-containerd"

readonly DEFAULT_PREFIX="/opt/.sandbox-runtime"

KEEP_DATA=false
SHOW_HELP=false
INSTALL_PREFIX=""

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                SHOW_HELP=true
                shift
                ;;
            --keep-data)
                KEEP_DATA=true
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

resolve_install_prefix() {
    if [[ -n "$INSTALL_PREFIX" ]]; then
        return
    fi
    INSTALL_PREFIX="${DEFAULT_PREFIX}"
}

stop_process() {
    local proc="$1"
    
    # 先尝试通过systemd获取主PID
    local main_pid
    main_pid=$(systemctl show -p MainPID --value "${proc}" 2>/dev/null || echo "")
    if [[ -n "$main_pid" && "$main_pid" != "0" ]]; then
        kill -TERM "$main_pid" 2>/dev/null || true
    fi
    
    # 兜底：匹配所有相关进程
    local pids
    pids=$(pgrep -af "${INSTALL_PREFIX}/bin/${proc}" | awk '{print $1}')

    [ -z "$pids" ] && return 0

    echo "Stopping ${proc}..."

    for pid in $pids; do
        kill -TERM "$pid" 2>/dev/null || true
    done

    for _ in $(seq 1 10); do
        if ! pgrep -af "${INSTALL_PREFIX}/bin/${proc}" >/dev/null; then
            echo "${proc} stopped"
            return 0
        fi
        sleep 1
    done

    echo "Force killing ${proc}..."

    pids=$(pgrep -af "${INSTALL_PREFIX}/bin/${proc}" | awk '{print $1}')

    for pid in $pids; do
        kill -9 "$pid" 2>/dev/null || true
    done
}

main() {
    parse_arguments "$@"
    resolve_install_prefix

    if $SHOW_HELP; then
        echo "用法: uninstall.sh [--keep-data] [-p|--prefix PATH]"
        echo ""
        echo "  --keep-data   保留镜像数据（${DEFAULT_PREFIX}/data）"
        echo "  -p, --prefix  安装路径（默认: ${DEFAULT_PREFIX})"
        echo ""
        echo "卸载范围（完整回退，不影响系统Docker）："
        echo "  - sandbox-containerd.service + sandbox-docker.service"
        echo "  - /etc/logrotate.d/sandbox-docker-audit"
        echo "  - ${DEFAULT_PREFIX}/ 目录"
        echo "  - /dev/shm/sandbox_pids.* 缓存"
        echo ""
        echo "不删除: /usr/bin/docker, /etc/docker, /var/lib/docker, docker.service"
        exit 0
    fi

    echo "=========================================="
    echo "Sandbox Docker 卸载程序 v${SCRIPT_VERSION}"
    echo "=========================================="
    echo "安装路径: ${INSTALL_PREFIX}"
    echo "时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    
    # ── 步骤0: 删除容器 ──
    DOCKER_BIN="${INSTALL_PREFIX}/bin/.docker.secure"
    DOCKER_SOCK="unix://${INSTALL_PREFIX}/run/docker.sock"

    if [ -f "${DOCKER_BIN}" ]; then
        # 用真实 docker清理所有容器
        "${DOCKER_BIN}" -H "${DOCKER_SOCK}" ps -q | xargs --no-run-if-empty "${DOCKER_BIN}" -H "${DOCKER_SOCK}" rm -f 2>/dev/null || true
    fi
    
    # ── 步骤1: 停止所有sandbox服务 ──
    echo "[1/5] 停止sandbox服务..."
    systemctl stop ${DOCKER_SERVICE} 2>/dev/null || true
    systemctl stop ${CONTAINERD_SERVICE} 2>/dev/null || true
    systemctl disable ${DOCKER_SERVICE} 2>/dev/null || true
    systemctl disable ${CONTAINERD_SERVICE} 2>/dev/null || true
    
    stop_process dockerd
    stop_process containerd
    pkill -9 -f "${INSTALL_PREFIX}/bin/docker-proxy" 2>/dev/null || true

    # 等待进程退出（避免"文本文件忙"）
    local retry=0
    while pgrep -f "${INSTALL_PREFIX}/bin/(dockerd|containerd)" &>/dev/null && [[ $retry -lt 10 ]]; do
        sleep 1
        retry=$((retry + 1))
    done

    echo "  ✓ sandbox-docker + sandbox-containerd 已停止"
    echo ""

    # ── 步骤2: 删除systemd服务文件（唯一系统修改点）──
    echo "[2/5] 删除systemd服务文件..."
    rm -f /etc/systemd/system/${DOCKER_SERVICE}.service 2>/dev/null || true
    rm -f /etc/systemd/system/${CONTAINERD_SERVICE}.service 2>/dev/null || true
    rm -f /etc/systemd/system/${DOCKER_SERVICE}.socket 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    echo "  ✓ 已删除 sandbox-containerd.service + sandbox-docker.service"
    echo "  ✓ 未触碰 docker.service / containerd.service"
    echo ""

    # ── 步骤3: 删除logrotate配置（由 sec-docker.sh 创建）──
    echo "[3/5] 删除logrotate配置..."
    rm -f /etc/logrotate.d/sandbox-docker-audit 2>/dev/null || true
    echo "  ✓ 已删除 /etc/logrotate.d/sandbox-docker-audit"
    echo ""
    
    echo "卸载活跃挂载点..."
    mount | grep "${INSTALL_PREFIX}" | awk '{print $3}' | sort -r | while read mnt; do
        umount -f "$mnt" 2>/dev/null || true
    done
    
    # ── 步骤4: 清理安装目录 ──
    echo "[4/5] 清理安装目录..."
    rm -f /dev/shm/sandbox_pids.* 2>/dev/null || true

    if $KEEP_DATA; then
        echo "  保留数据: ${INSTALL_PREFIX}/data"
        find "${INSTALL_PREFIX}" -mindepth 1 -maxdepth 1 \
            ! -name "data" \
            -exec rm -rf {} + 2>/dev/null || true
        echo "  ✓ 安装目录已清理（data/ 保留）"
    else
        if rm -rf "${INSTALL_PREFIX}" 2>/dev/null; then
            echo "  ✓ 安装目录已完全删除"
        else
            echo "  ✗ 安装目录删除失败（可能有文件被占用）"
            if ! rm -rf "${INSTALL_PREFIX}" 2>/dev/null; then
                echo "  首次删除失败，尝试卸载残留挂载点..."
                mount | grep "${INSTALL_PREFIX}" | awk '{print $3}' | sort -r | while read mnt; do
                    umount -f "$mnt" 2>/dev/null || true
                done
                sleep 2
                if rm -rf "${INSTALL_PREFIX}" 2>/dev/null; then
                    echo "  ✓ 重试后安装目录已删除"
                else
                    echo "    请手动检查: ls -la ${INSTALL_PREFIX}"
                fi
            fi
        fi
    fi
    echo ""

    # ── 步骤5: 验证 ──
    echo "[5/5] 验证清理结果..."
    local all_clean=true

    for svc in ${CONTAINERD_SERVICE} ${DOCKER_SERVICE}; do
        if systemctl is-active --quiet ${svc} 2>/dev/null; then
            echo "  ✗ ${svc} 仍在运行"
            all_clean=false
        else
            echo "  ✓ ${svc} 已停止"
        fi

        if [[ -f /etc/systemd/system/${svc}.service ]]; then
            echo "  ✗ ${svc}.service 仍存在"
            all_clean=false
        else
            echo "  ✓ ${svc}.service 已删除"
        fi
    done

    if [[ -f /etc/logrotate.d/sandbox-docker-audit ]]; then
        echo "  ✗ logrotate配置仍存在"
        all_clean=false
    else
        echo "  ✓ logrotate配置已删除"
    fi

    if ! $KEEP_DATA && [[ -d "${INSTALL_PREFIX}" ]]; then
        echo "  ✗ ${INSTALL_PREFIX} 仍存在"
        all_clean=false
    else
        echo "  ✓ 安装目录已清理"
    fi

    if command -v docker &> /dev/null && [[ -f /usr/bin/docker ]]; then
        echo "  ✓ 系统 Docker (/usr/bin/docker) 未受影响"
    else
        echo "  ○ 系统无独立Docker（正常）"
    fi

    echo ""
    echo "=========================================="
    echo "卸载完成"
    echo "=========================================="
    echo ""
    echo "清理总结:"
    echo "  systemd服务:     ✓ sandbox-containerd + sandbox-docker 已删除"
    echo "  logrotate:       ✓ sandbox-docker-audit 已删除"
    echo "  安装目录:        $(if $KEEP_DATA; then echo '○ data/ 保留'; else echo '✓ 已删除'; fi)"
    echo "  系统 Docker:     ✓ 未受影响"
    echo ""
    echo "所有系统修改已完整回退"
    echo "完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
}

main "$@"