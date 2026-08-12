# Replace healthHost before import. This repairs the existing Family Proxy
# Netwatch contract without replacing its enable/disable scripts.
:local healthName "family-mihomo-tproxy-health"
:local healthHost "192.168.10.10"
:local health [/tool netwatch find where name=$healthName]
:if ([:len $health] = 0) do={
  :error ("Missing existing Netwatch entry: " . $healthName . "; create it from the management UI first")
}
/tool netwatch set $health host=$healthHost type=http-get port=18088 interval=30s timeout=5s
:put ("Netwatch unified health contract applied: " . $healthHost . ":18088/")
