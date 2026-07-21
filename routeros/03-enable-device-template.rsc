# Manual alternative to the UI's "加入旁路" button. Do not run it for a device
# already managed by the UI. Replace these values and run 01/02 first.
:local deviceIp "192.168.10.101"
:local deviceMac "AA:BB:CC:DD:EE:FF"
:local sharedList "family_mihomo_devices"
:local tag ("family-mihomo-auto-" . $deviceIp)

/ip firewall address-list
:if ([:len [find where list=$sharedList and address=$deviceIp]] = 0) do={
  add list=$sharedList address=$deviceIp comment=("family-mihomo-managed " . $deviceIp)
}

/ipv6 firewall filter
:if ([:len [find where comment=($tag . " IPv6 bypass guard")]] = 0) do={
  add chain=forward action=jump jump-target=family_mihomo_auto_v6 src-mac-address=$deviceMac comment=($tag . " IPv6 bypass guard")
}

:put "Device joined the shared RouterOS policy. Append deviceIp to managed-ips and run family-mihomo-tproxy-auto sync."
