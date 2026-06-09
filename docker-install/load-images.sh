#!/bin/bash
# Sandbox Docker 镶像加载脚本
# 使用 sandbox docker（独立socket）

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_PATH="${SCRIPT_DIR}/images/openclaw-sandbox.tar.gz"

readonly DEFAULT_PREFIX="/opt/.sandbox-runtime"
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

resolve_install_prefix() {
    if [[ -n "$INSTALL_PREFIX" ]]; then
        return
    fi
    INSTALL_PREFIX="${DEFAULT_PREFIX}"
}

parse_arguments "$@"
resolve_install_prefix

DOCKER_BIN="${INSTALL_PREFIX}/bin/docker"
DOCKER_SOCK="unix://${INSTALL_PREFIX}/run/docker.sock"

echo "正在检查 Sandbox Docker 环境..."
echo "安装路径: ${INSTALL_PREFIX}"

if [[ ! -f "${DOCKER_BIN}" ]]; then
    echo "错误: Sandbox Docker 未安装，请先运行 install-docker.sh"
    exit 1
fi

if ! "${DOCKER_BIN}" -H "${DOCKER_SOCK}" info &> /dev/null; then
    echo "警告: Sandbox Docker 服务未启动。"
    echo "请执行: sudo systemctl start sandbox-docker"
    exit 1
fi

echo "Sandbox Docker 已就绪。"

if [ ! -f "$IMAGE_PATH" ]; then
    echo "错误: 找不到文件 '$IMAGE_PATH'，请检查路径是否正确。"
    exit 1
fi

echo "正在加载镜像: $IMAGE_PATH ..."
"${DOCKER_BIN}" -H "${DOCKER_SOCK}" load -i "$IMAGE_PATH"

if [ $? -eq 0 ]; then
    echo "镜像加载成功。"
else
    echo "错误: 加载失败。"
    exit 1
fi