# Full rollback for one manually managed device. Replace deviceIp before import.
:local deviceIp "192.168.10.101"
:local tag ("family-mihomo-auto-" . $deviceIp)
/ip firewall address-list remove [find where list="family_mihomo_devices" and address=$deviceIp]
/ipv6 firewall filter remove [find where comment=($tag . " IPv6 bypass guard")]
/ip firewall connection remove [find where src-address~$deviceIp or reply-dst-address~$deviceIp]
:put "Device removed from shared policy. Remove its IP from managed-ips and run family-mihomo-tproxy-auto sync."
