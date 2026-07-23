#!/usr/bin/env bash
# Guided first install. It writes only this host's private router.env, then
# delegates all mutation to the reviewed, backup-first installers.
set -Eeuo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
config=/etc/family-proxy-ui/router.env

[[ $EUID -eq 0 ]] || { echo "请使用 sudo 运行此脚本。" >&2; exit 1; }
[[ -f $config ]] && {
  echo "$config 已存在。为避免覆盖现有凭据和运行配置，引导安装已停止。" >&2
  echo "如需更新现有部署，请使用 scripts/upgrade-server.sh。" >&2
  exit 1
}
command -v docker >/dev/null || { echo "未检测到 Docker；请先安装 Docker Engine 与 Compose 插件。" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "未检测到 Docker Compose 插件；请先安装后重试。" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "当前主机不支持 systemd，无法使用此安装器。" >&2; exit 1; }

ask() {
  local name=$1 prompt=$2 default=${3:-} value
  if [[ -n $default ]]; then
    read -r -p "$prompt [$default]: " value
    value=${value:-$default}
  else
    read -r -p "$prompt: " value
  fi
  [[ -n $value && $value != *$'\n'* && $value != *$'\r'* && $value != *=* ]] || {
    echo "$name 不能为空，且不能包含换行或等号。" >&2
    return 1
  }
  printf -v "$name" '%s' "$value"
}

ask_secret() {
  local name=$1 prompt=$2 value
  read -r -s -p "$prompt: " value
  printf '\n'
  [[ -n $value && $value != *$'\n'* && $value != *$'\r'* ]] || {
    echo "$name 不能为空。" >&2
    return 1
  }
  printf -v "$name" '%s' "$value"
}

derive_prefix() {
  local cidr=$1 network=${1%/*}
  [[ $cidr =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/24$ ]] || return 1
  printf '%s.' "${network%.*}"
}

echo "家庭旁路交互式首次安装"
echo "仅写入本机私密配置，随后调用带备份和验证的安装器。"
echo "不会自动写入 RouterOS、导入机场订阅或接管任何客户端。"
echo
ip -br -4 addr || true
echo

ask FAMILY_LAN_CIDR "家庭 IPv4 网段（当前仅支持 /24）" "192.168.10.0/24"
FAMILY_LAN_PREFIX=$(derive_prefix "$FAMILY_LAN_CIDR") || {
  echo "当前引导仅支持形如 192.168.10.0/24 的网段。" >&2
  exit 1
}
ask FAMILY_PROXY_IP "旁路主机固定 IPv4"
ask FAMILY_ROUTER_IP "RouterOS LAN 地址" "${FAMILY_LAN_PREFIX}1"
ask FAMILY_CAPTURE_INTERFACE "承载 LAN 流量的桥接口" "kvmbr0"
ask FAMILY_DOCKER_ROOT "SSD 持久化目录" "/var/lib/family-proxy/docker"
ask ROUTER_HOST "RouterOS API 地址" "$FAMILY_ROUTER_IP"
ask ROUTER_USER "RouterOS API 用户"
ask_secret ROUTER_PASSWORD "RouterOS API 密码"
ask UI_USERNAME "管理页用户名" "admin"
ask_secret UI_PASSWORD "管理页密码"

install -d -m 700 /etc/family-proxy-ui
umask 077
{
  printf 'FAMILY_LAN_CIDR=%s\n' "$FAMILY_LAN_CIDR"
  printf 'FAMILY_LAN_PREFIX=%s\n' "$FAMILY_LAN_PREFIX"
  printf 'FAMILY_PROXY_IP=%s\n' "$FAMILY_PROXY_IP"
  printf 'FAMILY_ROUTER_IP=%s\n' "$FAMILY_ROUTER_IP"
  printf 'FAMILY_RESERVED_GATEWAY_IP=\n'
  printf 'FAMILY_CAPTURE_INTERFACE=%s\n' "$FAMILY_CAPTURE_INTERFACE"
  printf 'FAMILY_DOCKER_ROOT=%s\n' "$FAMILY_DOCKER_ROOT"
  printf 'BACKUP_ROOT=/var/backups/family-proxy\n'
  printf 'ROUTER_HOST=%s\n' "$ROUTER_HOST"
  printf 'ROUTER_USER=%s\n' "$ROUTER_USER"
  printf 'ROUTER_PASSWORD=%s\n' "$ROUTER_PASSWORD"
  printf 'ROUTER_CN_AUTO_SYNC=true\n'
  printf 'UI_USERNAME=%s\n' "$UI_USERNAME"
  printf 'UI_PASSWORD=%s\n' "$UI_PASSWORD"
  printf 'DNS_UPSTREAM_AUTH_B64=\n'
  printf 'MOSDNS_API_URL=http://127.0.0.1:9099\n'
  printf 'FAMILY_GEODATA_PROXY=http://127.0.0.1:7890\n'
  printf 'MIHOMO_GEODATA_AUTO_UPDATE=false\n'
} >"$config"
chmod 600 "$config"
unset ROUTER_PASSWORD UI_PASSWORD

echo "已写入私密配置：$config"
"$repo_dir/scripts/install-server.sh"
"$repo_dir/scripts/install-mihomo-container.sh"
"$repo_dir/scripts/install-server.sh" --start
"$repo_dir/scripts/verify-server.sh"

echo
echo "基础部署完成。下一步："
echo "1. 审阅并导入 routeros/01-preflight-and-backup.rsc 与 02-prepare-controller.rsc（替换示例 IP）。"
echo "2. 若已有兼容 MosDNS，按 DEPLOYMENT.md 的可选步骤接入管理页。"
echo "3. 从管理页导入订阅、建立候选池，再只接管一台测试设备。"
