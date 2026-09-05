# Replace only these two values before import. Shared rules remain inert until
# an exact client IP is added to family_mihomo_devices.
:local lanCidr "192.168.10.0/24"
:local proxyIp "192.168.10.10"
:local sharedList "family_mihomo_devices"
:local sharedTable "family_mihomo_shared"
:local sharedMark "family_mihomo_conn"
:local cnList "family_cn_ipv4"
:local sharedTag "family-mihomo-shared"

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

/routing table
:if ([:len [find where name=$sharedTable]] = 0) do={ add name=$sharedTable fib=yes }
/ip route
:if ([:len [find where comment=($sharedTag . " route")]] = 0) do={
  add dst-address=0.0.0.0/0 gateway=$proxyIp routing-table=$sharedTable check-gateway=ping comment=($sharedTag . " route")
}

/ip firewall mangle
:local mangleAnchor [find where comment="family-mihomo-auto anchor"]
:if ([:len [find where comment=($sharedTag . " local bypass")]] = 0) do={
  add chain=prerouting action=accept src-address-list=$sharedList dst-address-list=local_lan_ipv4 comment=($sharedTag . " local bypass") place-before=$mangleAnchor
}
:if ([:len [find where comment=($sharedTag . " mark connection")]] = 0) do={
  add chain=prerouting action=mark-connection new-connection-mark=$sharedMark passthrough=yes src-address-list=$sharedList dst-address-list=!local_lan_ipv4 connection-mark=no-mark comment=($sharedTag . " mark connection") place-before=$mangleAnchor
}
:local connectionMarker [find where comment=($sharedTag . " mark connection")]
:local multicastRule [find where comment=($sharedTag . " multicast direct")]
:if ([:len $multicastRule] = 0) do={
  add chain=prerouting action=accept src-address-list=$sharedList dst-address=224.0.0.0/4 comment=($sharedTag . " multicast direct") place-before=$connectionMarker
} else={
  set $multicastRule chain=prerouting action=accept src-address-list=$sharedList dst-address=224.0.0.0/4 comment=($sharedTag . " multicast direct")
  move $multicastRule destination=$connectionMarker
}
:if ([:len [find where comment=($sharedTag . " CN direct")]] = 0) do={
  add chain=prerouting action=accept src-address-list=$sharedList dst-address-list=$cnList comment=($sharedTag . " CN direct") place-before=$connectionMarker
}
# APNs must reach Mihomo so its classical/text rule can select Proxy-Auto.
# Remove the legacy whole-17/8 RouterOS bypass if an older template created it.
:foreach appleDirectRule in=[find where comment=($sharedTag . " Apple APNs direct")] do={
  remove $appleDirectRule
}
:foreach appleDirectEntry in=[/ip firewall address-list find where list="family_apple_direct" and address="17.0.0.0/8"] do={
  /ip firewall address-list remove $appleDirectEntry
}
:if ([:len [find where comment=($sharedTag . " route to z4pro")]] = 0) do={
  add chain=prerouting action=mark-routing new-routing-mark=$sharedTable passthrough=no src-address-list=$sharedList connection-mark=$sharedMark comment=($sharedTag . " route to z4pro") place-before=$mangleAnchor
}

/ip firewall nat
:local natAnchor [find where comment="family-mihomo-auto DNS anchor"]
:if ([:len [find where comment=($sharedTag . " DNS TCP")]] = 0) do={
  add chain=dstnat action=dst-nat protocol=tcp src-address-list=$sharedList dst-port=53 to-addresses=$proxyIp to-ports=53 comment=($sharedTag . " DNS TCP") place-before=$natAnchor
}
:if ([:len [find where comment=($sharedTag . " DNS UDP")]] = 0) do={
  add chain=dstnat action=dst-nat protocol=udp src-address-list=$sharedList dst-port=53 to-addresses=$proxyIp to-ports=53 comment=($sharedTag . " DNS UDP") place-before=$natAnchor
}

/ip firewall filter
:if ([:len [find where comment=($sharedTag . " FastTrack exclude")]] = 0) do={
  :local fasttrack [find where action=fasttrack-connection]
  :if ([:len $fasttrack] > 0) do={
    add chain=forward action=accept connection-mark=$sharedMark comment=($sharedTag . " FastTrack exclude") place-before=[:pick $fasttrack 0]
  } else={
    add chain=forward action=accept connection-mark=$sharedMark comment=($sharedTag . " FastTrack exclude")
  }
}
:local policyAnchor [find where comment=($sharedTag . " FastTrack exclude")]
:if ([:len [find where comment=($sharedTag . " block external DoT TCP")]] = 0) do={
  add chain=forward action=reject reject-with=tcp-reset protocol=tcp src-address-list=$sharedList dst-address-list=!local_lan_ipv4 dst-port=853 comment=($sharedTag . " block external DoT TCP") place-before=$policyAnchor
}
:set policyAnchor [find where comment=($sharedTag . " FastTrack exclude")]
:if ([:len [find where comment=($sharedTag . " block external DoT UDP")]] = 0) do={
  add chain=forward action=drop protocol=udp src-address-list=$sharedList dst-address-list=!local_lan_ipv4 dst-port=853 comment=($sharedTag . " block external DoT UDP") place-before=$policyAnchor
}
:set policyAnchor [find where comment=($sharedTag . " FastTrack exclude")]
:local quicRule [find where comment=($sharedTag . " QUIC fast fallback")]
:if ([:len $quicRule] = 0) do={
  add chain=forward action=reject reject-with=icmp-port-unreachable protocol=udp src-address-list=$sharedList dst-address-list=!local_lan_ipv4 dst-port=443 comment=($sharedTag . " QUIC fast fallback") place-before=$policyAnchor
} else={
  set $quicRule chain=forward action=reject reject-with=icmp-port-unreachable protocol=udp src-address-list=$sharedList dst-address-list=!local_lan_ipv4 dst-port=443
  move $quicRule destination=$policyAnchor
}

/ipv6 firewall filter
:local ipv6Reject [find where comment="family-mihomo-auto IPv6 drop"]
:if ([:len $ipv6Reject] = 0) do={
  add chain=family_mihomo_auto_v6 action=reject reject-with=icmp-admin-prohibited comment="family-mihomo-auto IPv6 drop"
} else={
  set $ipv6Reject action=reject reject-with=icmp-admin-prohibited
}

# API must be reachable only from the proxy host. Review existing input rules
# first; do not append a broad WAN rule. This line is intentionally disabled.
# /ip firewall filter add chain=input action=accept protocol=tcp dst-port=8728 src-address=$proxyIp comment="family-mihomo RouterOS API"

:put "Shared policy is ready but has no clients. Configure RouterOS API source restriction, then add one device."
