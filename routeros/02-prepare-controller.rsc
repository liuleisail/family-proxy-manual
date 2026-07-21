# Replace only these two values before import. This script creates no active
# per-device policy route and does not redirect any client DNS.
:local lanCidr "192.168.10.0/24"
:local proxyIp "192.168.10.10"

/ip firewall address-list
:if ([:len [find where list="local_lan_ipv4" and address=$lanCidr]] = 0) do={
  add list=local_lan_ipv4 address=$lanCidr comment="family-mihomo local LAN bypass"
}

/ip firewall mangle
:if ([:len [find where comment="family-mihomo-auto anchor"]] = 0) do={
  add chain=prerouting action=accept disabled=yes comment="family-mihomo-auto anchor"
}
/ip firewall nat
:if ([:len [find where comment="family-mihomo-auto DNS anchor"]] = 0) do={
  add chain=dstnat action=accept disabled=yes comment="family-mihomo-auto DNS anchor"
}

# API must be reachable only from the proxy host. Review existing input rules
# first; do not append a broad WAN rule. This line is intentionally disabled.
# /ip firewall filter add chain=input action=accept protocol=tcp dst-port=8728 src-address=$proxyIp comment="family-mihomo RouterOS API"

:put "Controller anchors are ready. Configure /ip service api and firewall source restriction manually."
