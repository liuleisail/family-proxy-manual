# Full rollback for one manually managed device. Replace deviceIp before import.
:local deviceIp "192.168.10.101"
:local suffix "101"
:local table ("family_mihomo_auto_" . $suffix)
:local tag ("family-mihomo-auto " . $deviceIp)
/ip firewall mangle remove [find where comment~$tag]
/ip firewall nat remove [find where comment~$tag]
/ip firewall filter remove [find where comment~$tag]
/ipv6 firewall filter remove [find where comment~$tag]
/ip route remove [find where comment~$tag]
/routing table remove [find where name=$table]
/ip firewall connection remove [find where src-address~$deviceIp or reply-dst-address~$deviceIp]
:put "RouterOS rules removed. Remove device IP from /etc/family-proxy-ui/managed-ips and run family-mihomo-tproxy-auto sync on the proxy host."
