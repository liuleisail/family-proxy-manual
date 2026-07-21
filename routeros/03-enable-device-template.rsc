# Manual alternative to the UI's "加入旁路" button. Do not run it for a device
# already managed by the UI. Replace these values and run 01/02 first.
:local deviceIp "192.168.10.101"
:local deviceMac "AA:BB:CC:DD:EE:FF"
:local proxyIp "192.168.10.10"
:local suffix "101"
:local table ("family_mihomo_auto_" . $suffix)
:local mark ($table . "_conn")
:local tag ("family-mihomo-auto " . $deviceIp)

/routing table
:if ([:len [find where name=$table]] = 0) do={ add name=$table fib=yes }
/ip route add dst-address=0.0.0.0/0 gateway=$proxyIp routing-table=$table check-gateway=ping comment=($tag . " route")

/ip firewall mangle
:local mangleAnchor [find where comment="family-mihomo-auto anchor"]
add chain=prerouting action=accept src-address=$deviceIp dst-address-list=local_lan_ipv4 comment=($tag . " local bypass") place-before=$mangleAnchor
add chain=prerouting action=mark-connection new-connection-mark=$mark passthrough=yes src-address=$deviceIp dst-address-list=!local_lan_ipv4 connection-mark=no-mark comment=($tag . " mark connection") place-before=$mangleAnchor
add chain=prerouting action=mark-routing new-routing-mark=$table passthrough=no src-address=$deviceIp connection-mark=$mark comment=($tag . " route to proxy") place-before=$mangleAnchor

/ip firewall nat
:local natAnchor [find where comment="family-mihomo-auto DNS anchor"]
add chain=dstnat action=dst-nat protocol=tcp src-address=$deviceIp dst-port=53 to-addresses=$proxyIp to-ports=53 comment=($tag . " DNS TCP") place-before=$natAnchor
add chain=dstnat action=dst-nat protocol=udp src-address=$deviceIp dst-port=53 to-addresses=$proxyIp to-ports=53 comment=($tag . " DNS UDP") place-before=$natAnchor

/ip firewall filter
:local fasttrack [find where action=fasttrack-connection]
add chain=forward action=accept connection-mark=$mark comment=($tag . " FastTrack exclude") place-before=$fasttrack

/ipv6 firewall filter
:if ([:len [find where comment="family-mihomo-auto IPv6 drop"]] = 0) do={ add chain=family_mihomo_auto_v6 action=drop comment="family-mihomo-auto IPv6 drop" }
add chain=forward action=jump jump-target=family_mihomo_auto_v6 src-mac-address=$deviceMac comment=($tag . " IPv6 bypass guard")

:put "RouterOS policy created. On the proxy host append deviceIp to managed-ips and run family-mihomo-tproxy-auto sync."
