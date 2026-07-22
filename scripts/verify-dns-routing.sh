#!/usr/bin/env bash
set -Eeuo pipefail

mode=full
config=/etc/family-proxy-ui/router.env
for argument in "$@"; do
  case "$argument" in
    --quick) mode=quick ;;
    --full) mode=full ;;
    -h|--help)
      echo "usage: $0 [--quick|--full] [router.env]"
      exit 0
      ;;
    *) config=$argument ;;
  esac
done
[[ -r $config ]] || { echo "cannot read $config" >&2; exit 1; }
# shellcheck disable=SC1090
source "$config"

dns_ip=${FAMILY_PROXY_IP:?FAMILY_PROXY_IP is required}
api=${MOSDNS_API_URL:-http://127.0.0.1:9099}
command -v dig >/dev/null || { echo "dig is required" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

domestic=(www.baidu.com www.taobao.com api.m.jd.com www.douyin.com www.qq.com apple.com)
foreign=(www.google.com www.youtube.com api.telegram.org chatgpt.com github.com ssl.gstatic.com)
cache_tags=(cache_all cache_all_noleak cache_cn cache_google cache_google_node cache_node cache_cnmihomo)

if [[ $mode == full ]]; then
  for tag in "${cache_tags[@]}"; do
    curl -fsS "$api/plugins/$tag/flush" >/dev/null
  done
fi
answers=$(mktemp /tmp/family-dns-answers.XXXXXX)
trap 'rm -f "$answers"' EXIT
for domain in "${domestic[@]}" "${foreign[@]}"; do
  result=$(dig +tries=1 +time=4 +short "@$dns_ip" "$domain" A)
  grep -q . <<<"$result" || {
    echo "$domain did not return an IPv4 address" >&2
    exit 1
  }
  found_ipv4=false
  while IFS= read -r address; do
    if [[ $address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      printf '%s=%s\n' "$domain" "$address" >>"$answers"
      found_ipv4=true
    fi
  done <<<"$result"
  $found_ipv4 || { echo "$domain did not return a valid IPv4 address" >&2; exit 1; }
done

python3 - "$answers" <<'PY'
import ipaddress, json, sys
bad = []
for line in open(sys.argv[1], encoding="ascii"):
    domain, raw = line.strip().split("=", 1)
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        bad.append((domain, raw))
        continue
    if (address in ipaddress.ip_network("198.18.0.0/15") or address.is_private
            or address.is_loopback or address.is_link_local or address.is_multicast
            or address.is_unspecified):
        bad.append((domain, str(address)))
if bad:
    raise SystemExit("suspicious DNS answers: " + ", ".join(f"{d}={a}" for d, a in bad[:10]))
PY

if [[ $mode == full ]]; then
  logs=$(curl -fsS "$api/api/v2/audit/logs?limit=500")
  check_direction() {
    local expected=$1 domain=$2 actual
    actual=$(jq -r --arg domain "$domain" '[.logs[] | select(.query_name==$domain and .query_type=="A" and .final_upstream!=null)] | max_by(.query_time) | .final_upstream // ""' <<<"$logs")
    [[ $actual == "$expected" ]] || {
      echo "$domain used '$actual'; expected '$expected'" >&2
      exit 1
    }
    printf '%-28s %s\n' "$domain" "$actual"
  }
  for domain in "${domestic[@]}"; do check_direction domestic "$domain"; done
  for domain in "${foreign[@]}"; do check_direction foreign "$domain"; done
fi

dig +tries=1 +time=4 +comments "@$dns_ip" push.apple.com A | grep -q 'status: NOERROR' || {
  echo "Apple Push probe failed" >&2
  exit 1
}
if [[ $mode == full ]]; then
  echo "DNS routing regression passed (cache flushed and direction verified)"
else
  echo "DNS quick check passed (cache preserved; direction not re-audited)"
fi
