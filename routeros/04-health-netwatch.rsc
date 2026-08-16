# Reconcile the legacy RouterOS health monitor with the current unified gateway.
# Replace proxyIp with the Z4Pro address before import. Run after 02-prepare-controller.rsc.
:local proxyIp ""
:if ([:len $proxyIp] = 0) do={ :error "Set proxyIp to the live Z4Pro address before import." }
:local healthName "family-mihomo-tproxy-health"
:local upScript "/ip firewall mangle enable [find where action=mark-connection and new-connection-mark=family_mihomo_conn]\r\n/ip firewall mangle enable [find where action=mark-routing and new-routing-mark=family_mihomo_shared]\r\n/ip firewall nat enable [find where action=dst-nat and to-addresses=$proxyIp and to-ports=\"53\"]\r\n/ip firewall filter enable [find where action=accept and connection-mark=\"family_mihomo_conn\"]\r\n/ipv6 firewall filter enable [find where action=jump and jump-target=\"family_mihomo_auto_v6\"]\r\n/ip firewall connection remove [find where connection-mark=\"family_mihomo_conn\"]"
:local downScript "/ip firewall mangle disable [find where action=mark-connection and new-connection-mark=family_mihomo_conn]\r\n/ip firewall mangle disable [find where action=mark-routing and new-routing-mark=family_mihomo_shared]\r\n/ip firewall nat disable [find where action=dst-nat and to-addresses=$proxyIp and to-ports=\"53\"]\r\n/ip firewall filter disable [find where action=accept and connection-mark=\"family_mihomo_conn\"]\r\n/ipv6 firewall filter disable [find where action=jump and jump-target=\"family_mihomo_auto_v6\"]\r\n/ip firewall connection remove [find where connection-mark=\"family_mihomo_conn\"]"

/tool netwatch
:local monitor [find where name=$healthName]
:if ([:len $monitor] = 0) do={
  add name=$healthName host=$proxyIp type=http-get port=18088 interval=30s timeout=5s up-script=$upScript down-script=$downScript comment="unified gateway health; shared policy fallback"
} else={
  set $monitor host=$proxyIp type=http-get port=18088 interval=30s timeout=5s up-script=$upScript down-script=$downScript comment="unified gateway health; shared policy fallback"
}

:put "Netwatch now probes the unified gateway on port 18088."
