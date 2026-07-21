# Read-only preflight plus rollback artifacts. Replace the prefix if desired.
:local stamp ([:pick [/system clock get date] 7 11] . "-" . [:pick [/system clock get time] 0 2] . [:pick [/system clock get time] 3 5])
/export hide-sensitive file=("family-proxy-prechange-" . $stamp)
/system backup save name=("family-proxy-prechange-" . $stamp)
/system resource print
/system package update print
/ip service print where name=api
/ip route print detail where active
/ip firewall mangle print detail where comment~"family-mihomo"
/ip firewall nat print detail where comment~"family-mihomo"
/ip firewall filter print detail where action=fasttrack-connection
/ipv6 firewall filter print detail where comment~"family-mihomo"
:put "Preflight complete. Download both backup files before continuing."
