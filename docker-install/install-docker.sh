#!/bin/bash
# OpenClaw Sandbox Docker 离线安装程序
# 安装到 /opt/.sandbox-runtime/（可通过 -p 自定义），与系统 Docker 共存，不污染系统
# 系统修改仅限于: sandbox-containerd.service + sandbox-docker.service（2个systemd文件）
#
# 离线安装流程中的调用方式: sudo bash auto-install.sh
#   auto-install.sh → install-docker.sh → load-images.sh → sec-docker.sh

set -e

readonly SCRIPT_VERSION="3.1.0"
readonly DOCKER_SERVICE="sandbox-docker"
readonly CONTAINERD_SERVICE="sandbox-containerd"

FORCE_INSTALL=false
SHOW_HELP=false
INSTALL_PREFIX=""

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                SHOW_HELP=true
                shift
                ;;
            -f|--force)
                FORCE_INSTALL=true
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

readonly DEFAULT_PREFIX="/opt/.sandbox-runtime"

resolve_install_prefix() {
    if [[ -n "$INSTALL_PREFIX" ]]; then
        return
    fi
    INSTALL_PREFIX="${DEFAULT_PREFIX}"
}

main() {
    parse_arguments "$@"
    resolve_install_prefix

    if $SHOW_HELP; then
        echo "用法: install-docker.sh [-f|--force] [-p|--prefix PATH]"
        echo ""
        echo "  -f, --force    强制重新安装（先完全卸载旧版本）"
        echo "  -p, --prefix   安装路径（默认: ${DEFAULT_PREFIX}）"
        echo ""
        echo "设计原则："
        echo "  - 所有文件安装到指定目录，不写入 /usr/bin 或 /etc/docker"
        echo "  - 独立 containerd + dockerd 服务，与系统 Docker 共存"
        echo "  - 独立 docker.sock，独立 data-root"
        echo "  - 卸载: 停服务 → 删systemd文件 → rm -rf 安装目录"
        echo "  - 系统修改仅: sandbox-containerd.service + sandbox-docker.service"
        exit 0
    fi

    echo "=========================================="
    echo "OpenClaw Sandbox Docker 安装程序 v${SCRIPT_VERSION}"
    echo "=========================================="
    echo "安装路径: ${INSTALL_PREFIX}"

    if [[ $EUID -ne 0 ]]; then
        echo "错误: 需要root权限（配置systemd服务）"
        echo "请使用: sudo ./install-docker.sh"
        exit 1
    fi

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PACKAGE_DIR="${SCRIPT_DIR}/packages/docker"

    # ── 步骤1: 检查安装包 ──
    echo "[1/9] 检查Docker安装包..."
    if [[ ! -d "$PACKAGE_DIR" ]]; then
        echo "错误: 安装包目录不存在: $PACKAGE_DIR"
        exit 1
    fi

    DOCKER_TAR=$(find "$PACKAGE_DIR" -name "*.tgz" -o -name "*.tar.gz" | head -1)
    if [[ -z "$DOCKER_TAR" ]]; then
        echo "错误: 未找到Docker安装包(.tgz)"
        exit 1
    fi
    echo "  安装包: $DOCKER_TAR"

    # ── 步骤2: 强制安装时先完全卸载 ──
    if $FORCE_INSTALL; then
        echo "[2/9] 强制安装模式，完全卸载旧版本..."
        bash "${SCRIPT_DIR}/uninstall.sh" || true
        sleep 2
    else
        echo "[2/9] 跳过（非强制模式）"
    fi

    # ── 步骤3: 创建目录结构 ──
    echo "[3/9] 创建目录结构..."
    mkdir -p "${INSTALL_PREFIX}/bin"
    mkdir -p "${INSTALL_PREFIX}/etc/docker"
    mkdir -p "${INSTALL_PREFIX}/data"
    mkdir -p "${INSTALL_PREFIX}/log"
    mkdir -p "${INSTALL_PREFIX}/run"
    echo "  bin/ etc/ data/ log/ run/"

    # ── 步骤4: 解压并安装二进制 ──
    echo "[4/9] 安装Docker二进制文件..."
    TEMP_DIR=$(mktemp -d)
    tar -xzf "$DOCKER_TAR" -C "$TEMP_DIR"

    if [[ -d "${TEMP_DIR}/docker" ]]; then
        cp "${TEMP_DIR}/docker/"* "${INSTALL_PREFIX}/bin/"
    else
        cp "${TEMP_DIR}/"* "${INSTALL_PREFIX}/bin/"
    fi
    rm -rf "$TEMP_DIR"

    chmod 750 "${INSTALL_PREFIX}/bin/dockerd" 2>/dev/null || true
    chmod 750 "${INSTALL_PREFIX}/bin/docker" 2>/dev/null || true
    chmod 750 "${INSTALL_PREFIX}/bin/containerd" 2>/dev/null || true
    chmod 750 "${INSTALL_PREFIX}/bin/containerd-shim*" 2>/dev/null || true
    chmod 750 "${INSTALL_PREFIX}/bin/runc" 2>/dev/null || true
    chmod 750 "${INSTALL_PREFIX}/bin/ctr" 2>/dev/null || true
    chmod 750 "${INSTALL_PREFIX}/bin/docker-proxy" 2>/dev/null || true
    chmod 750 "${INSTALL_PREFIX}/bin/docker-init" 2>/dev/null || true
    echo "  docker, dockerd, containerd, runc, docker-proxy 等"

    # ── 步骤5: daemon.json（独立数据根+独立socket，不写userns-remap避免污染系统）──
    echo "[5/9] 配置daemon.json..."
    cat > "${INSTALL_PREFIX}/etc/docker/daemon.json" << EOF
{
    "data-root": "${INSTALL_PREFIX}/data",
    "hosts": ["unix://${INSTALL_PREFIX}/run/docker.sock"]
}
EOF

    if true; then
        chown root:root "${INSTALL_PREFIX}/etc/docker/daemon.json"
    fi
    echo "  data-root=${INSTALL_PREFIX}/data"
    echo "  socket=${INSTALL_PREFIX}/run/docker.sock"
    echo "  注意: 未启用userns-remap（需创建dockremap用户，会污染/etc/passwd等）"
    echo "        如需启用，参见 daemon.json 添加 \"userns-remap\": \"default\" 并创建dockremap用户"

    # ── 步骤6: sandbox-containerd.service（独立containerd，与系统containerd共存）──
    echo "[6/9] 配置 systemd 服务..."
    cat > /etc/systemd/system/${CONTAINERD_SERVICE}.service << EOF
[Unit]
Description=Sandbox Containerd Runtime for OpenClaw
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=PATH=${INSTALL_PREFIX}/bin:/usr/bin:/bin:/usr/sbin:/sbin
ExecStart=${INSTALL_PREFIX}/bin/containerd --root ${INSTALL_PREFIX}/data/containerd --address ${INSTALL_PREFIX}/run/containerd.sock
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=on-failure
RestartSec=5
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/${DOCKER_SERVICE}.service << EOF
[Unit]
Description=Sandbox Docker Engine for OpenClaw
After=${CONTAINERD_SERVICE}.service
Requires=${CONTAINERD_SERVICE}.service

[Service]
Type=notify
Environment=PATH=${INSTALL_PREFIX}/bin:/usr/bin:/bin:/usr/sbin:/sbin
ExecStart=${INSTALL_PREFIX}/bin/dockerd --config-file ${INSTALL_PREFIX}/etc/docker/daemon.json --containerd ${INSTALL_PREFIX}/run/containerd.sock
ExecReload=/bin/kill -s HUP \$MAINPID
LimitNOFILE=infinity
LimitNPROC=infinity
TimeoutStartSec=0
Delegate=yes
KillMode=process
Restart=on-failure
StartLimitBurst=3
StartLimitInterval=60s

[Install]
WantedBy=multi-user.target
EOF

    chmod +x /etc/systemd/system/${CONTAINERD_SERVICE}.service
    chmod +x /etc/systemd/system/${DOCKER_SERVICE}.service
    echo "  ${CONTAINERD_SERVICE}.service（独立containerd）"
    echo "  ${DOCKER_SERVICE}.service（依赖sandbox-containerd）"
    echo "  无 Conflicts=docker.service — 与系统Docker共存"

    # ── 步骤7: 启动服务 ──
    echo "[7/9] 重载systemd并启动服务..."
    systemctl daemon-reload

    systemctl enable ${CONTAINERD_SERVICE} --now
    systemctl enable ${DOCKER_SERVICE} --now

    # 轮询等待
    retry=0
    while ! systemctl is-active --quiet ${CONTAINERD_SERVICE} && [[ $retry -lt 8 ]]; do
        sleep 1; retry=$((retry + 1))
    done
    retry=0
    while ! systemctl is-active --quiet ${DOCKER_SERVICE} && [[ $retry -lt 8 ]]; do
        sleep 1; retry=$((retry + 1))
    done

    # ── 步骤8: 验证 ──
    echo "[8/9] 验证安装..."
    local all_ok=true

    if systemctl is-active --quiet ${CONTAINERD_SERVICE}; then
        echo "  ✓ sandbox-containerd 运行正常"
    else
        echo "  ✗ sandbox-containerd 未运行"
        systemctl status ${CONTAINERD_SERVICE} --no-pager
        all_ok=false
    fi

    if systemctl is-active --quiet ${DOCKER_SERVICE}; then
        echo "  ✓ sandbox-docker 运行正常"
    else
        echo "  ✗ sandbox-docker 未运行"
        systemctl status ${DOCKER_SERVICE} --no-pager
        all_ok=false
    fi

    "${INSTALL_PREFIX}/bin/docker" -H "unix://${INSTALL_PREFIX}/run/docker.sock" --version

    if [[ "${all_ok}" != "true" ]]; then
        exit 1
    fi

    # ── 步骤9: 创建激活脚本 ──
    echo "[9/9] 创建激活脚本..."
    cat > "${INSTALL_PREFIX}/activate.sh" << 'ACTIVATE_EOF'
#!/bin/bash
# OpenClaw Sandbox Docker 激活脚本
# 用法: source /opt/.sandbox-runtime/activate.sh
# 退出: deactivate_sandbox_docker
#
# docker-wrapper 已内置 DOCKER_HOST 设置，无需手动配置
# 此脚本主要用于 PATH 优先级，使 sandbox docker 覆盖系统 docker

SANDBOX_RUNTIME_PREFIX="__INSTALL_PREFIX__"
SANDBOX_RUNTIME_DOCKER_HOST="unix://${SANDBOX_RUNTIME_PREFIX}/run/docker.sock"

_sandbox_docker_old_path="$PATH"
_sandbox_docker_old_docker_host="${DOCKER_HOST:-}"

export PATH="${SANDBOX_RUNTIME_PREFIX}/bin:$PATH"
export DOCKER_HOST="${SANDBOX_RUNTIME_DOCKER_HOST}"

echo "Sandbox Docker 已激活"
echo "  docker -> ${SANDBOX_RUNTIME_PREFIX}/bin/docker"
echo "  DOCKER_HOST -> ${SANDBOX_RUNTIME_DOCKER_HOST}"
echo "  使用 'deactivate_sandbox_docker' 退出"

deactivate_sandbox_docker() {
    export PATH="${_sandbox_docker_old_path}"
    if [[ -n "${_sandbox_docker_old_docker_host}" ]]; then
        export DOCKER_HOST="${_sandbox_docker_old_docker_host}"
    else
        unset DOCKER_HOST
    fi
    unset SANDBOX_RUNTIME_PREFIX SANDBOX_RUNTIME_DOCKER_HOST
    unset _sandbox_docker_old_path _sandbox_docker_old_docker_host
    unset -f deactivate_sandbox_docker
    echo "Sandbox Docker 已退出"
}
ACTIVATE_EOF

    sed -i "s|__INSTALL_PREFIX__|${INSTALL_PREFIX}|g" "${INSTALL_PREFIX}/activate.sh"

    chmod +x "${INSTALL_PREFIX}/activate.sh"

    echo ""
    echo "=========================================="
    echo "Sandbox Docker 安装完成！"
    echo ""
    echo "使用方法："
    echo "  source ${INSTALL_PREFIX}/activate.sh   # 激活"
    echo "  docker ps                               # sandbox docker"
    echo "  deactivate_sandbox_docker               # 退出"
    echo ""
    echo "系统修改（可完整回退）："
    echo "  /etc/systemd/system/${CONTAINERD_SERVICE}.service"
    echo "  /etc/systemd/system/${DOCKER_SERVICE}.service"
    echo "  未修改: /usr/bin, /etc/docker, /var/lib/docker, /var/run/docker.sock"
    echo ""
    echo "与系统 Docker 共存："
    echo "  系统Docker: /var/run/docker.sock (docker.service)"
    echo "  Sandbox:    ${INSTALL_PREFIX}/run/docker.sock (${DOCKER_SERVICE})"
    echo ""
    echo "卸载: sudo ${SCRIPT_DIR}/uninstall.sh"
    echo "=========================================="
}

main "$@"