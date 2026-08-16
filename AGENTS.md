# 家庭旁路系统运维交接

本文件是家庭旁路代理系统的 agent 交接手册。它描述现有架构、已完成工作、诊断证据、日常操作和运维账户使用方式。它不是实时状态数据库：每次处理线上故障或变更前，都要重新连接设备并采集当前状态。

## 0. 最高优先级规则

1. 这是“按设备选择性旁路”，不是全网透明代理。未加入旁路的设备必须保持原有网关和访问行为。
2. 默认先只读诊断。不要因为 SSH/API 能连接就重启服务、改路由、改防火墙、改 DNS、改代理、改用户权限或清理状态。
3. 一次只处理一个故障域或一个变更目标。先写出假设、影响范围、预期指标、备份位置和回滚动作，再执行。
4. RouterOS 变更前必须保存文本导出和二进制备份；Z4Pro 状态变更前必须保存相关配置、服务状态、运行文件和数据库/卷备份（如涉及）。
5. 只有用户明确授权后才能做线上变更。优先使用 *-change SSH 入口，但入口权限不是变更授权；codexops 运维账号仍应按最小权限使用。
6. 变更后必须从受影响的实际路径验证：RouterOS 状态、Z4Pro 状态、nft/路由计数、Netwatch、日志和真实客户端业务。命令返回成功不等于系统恢复。
7. 严禁在此文件、代码、提交、日志、记忆或最终报告中写入或回显密码、私钥、token、cookie、订阅链接、节点原文、RouterOS 完整敏感导出或抓包内容。
8. 任何历史地址、端口、镜像、容器路径和设备 IP 都只是线索；线上操作前必须重新发现，不能盲信历史记录。
9. 每次对代码、配置、部署或文档的修改（含 UI 变更、版本发布、脚本与配置调整）落地后，必须同步修订本文件：记录变更内容、版本号、部署方式与交接注意事项，确保任意时刻更换模型都能凭本文件接管继续工作。

## 1. 系统目标与流量模型

家庭网络通过 RB5009 作为主路由，Z4Pro 作为旁路代理主机。只有 RouterOS 地址表 family_mihomo_devices 中的设备被纳管。

### 正常路径

- 未纳管设备：继续按 RB5009 原有默认路由访问。
- 纳管设备访问局域网：RouterOS 的 local_lan_ipv4 规则放行，避免绕到旁路主机。
- 纳管设备访问中国 IPv4：RouterOS 在连接打标前命中 family_cn_ipv4，直接走 WAN；Z4Pro 侧 nft 也有中国地址兜底直转/SNAT。
- 纳管设备访问国外 TCP/UDP：RouterOS 使用连接标记 family_mihomo_conn 和路由表 family_mihomo_shared 将流量送到 Z4Pro；Z4Pro nft 将 TCP/UDP TPROXY 到 Mihomo 7893，并用 mark 0x2000 配合本机策略路由回送。
- 纳管设备普通 DNS 53：RouterOS dst-nat 到 Z4Pro 的 53 端口。
- 纳管设备 IPv6：当前设计通过 family_mihomo_auto_v6 防漏链阻断纳管设备 IPv6，避免 IPv6 绕过 IPv4 旁路策略；不要擅自改成全网 IPv6 劫持。
- 外部 DoT 853：纳管设备的 TCP 853 被 reject/reset、UDP 853 被 drop；DoH/HTTPDNS/应用内置解析需另按 DNS 规则诊断。

### 关键边界

- RouterOS 前置中国 IPv4 直连必须保留；不能把所有流量都送到 Z4Pro，否则会产生 RouterOS -> Z4Pro -> RouterOS 额外往返甚至递归。
- Mihomo 7890 是 mixed HTTP 代理；7893 是 TPROXY 监听，不能拿 7893 当 HTTP 代理测试。
- TG-Auto 是用户 Telegram 流量的业务策略；TG-Notify 是系统通知/推送路径。两者必须保持独立，修一个不能顺手改另一个。
- 管理页面的“已加入”只表示部分状态，不能证明生效。必须同时核对 RouterOS、Z4Pro 状态文件、nft 集合、TPROXY 计数和实际包路径。

## 2. 实际设备与代码位置

以下是已知交接信息，线上操作时仍需重新确认：

| 组件 | 当前已知入口/位置 | 作用 |
| --- | --- | --- |
| RB5009 | 192.168.2.1:2222，SSH 别名 rb5009 | 主路由、策略路由、mangle、NAT、地址表、IPv6 防漏、Netwatch |
| Z4Pro | 192.168.2.156:14623，SSH 别名 z4pro | Docker/NAS、Mihomo、旁路转发、控制平面、DNS/MosDNS |
| 家庭旁路代码仓库 | /Volumes/NAS/File/codex/projects/family-proxy-manual | 部署脚本、RouterOS 模板、运行时、测试和文档 |
| Z4Pro 控制配置 | /etc/family-proxy-ui/router.env | 生产配置，禁止提交/回显 |
| Z4Pro 纳管状态 | /etc/family-proxy-ui/managed-ips | 每行一个纳管 IPv4，权限敏感，修改后必须同步 TPROXY |
| Z4Pro nft 表 | inet family_mihomo_direct | managed4、cn4、TPROXY 与中国 IPv4 SNAT |
| Z4Pro 同步命令 | /usr/local/sbin/family-mihomo-tproxy-auto sync | 根据 managed-ips 生成并应用 nft/策略路由 |
| Z4Pro TPROXY 服务 | family-mihomo-tproxy-auto | systemd oneshot，依赖 Docker/Mihomo |
| Mihomo | host network；混合端口 7890，TPROXY 7893，控制器通常 127.0.0.1:9091 | 节点、fallback、业务分流 |
| 统一管理入口 | http://192.168.2.156:18088/（实际地址变更前重查） | 登录后的设备、规则、机场与候选池管理 |
| RouterOS 健康探针 | http://192.168.2.156:18088/ | family-mihomo-tproxy-health Netwatch 目标；18087 是历史旧端口 |
| 控制平面本地后端 | 127.0.0.1:18093 | 设备、健康、抓包等内部 API，不应直接暴露 |
| 机场后端 | 127.0.0.1:18090 | 订阅与候选池管理 |
| MosDNS 管理后端 | 127.0.0.1:18102 | DNS 上游、规则和回归状态 |
| 抓包目录 | /run/family-proxy-captures | 内存目录；单文件 50 MB、总量 200 MB、最长保留 24 小时 |
| 典型抓包接口 | kvmbr0 | Z4Pro 承载受管设备流量的 LAN 桥；必须现场确认 |

仓库中优先阅读：

- README.md：系统边界、设备接入、订阅/候选池、DNS、健康检查和回退。
- DEPLOYMENT.md：部署、升级、备份和恢复。
- routeros/README.md：RouterOS 脚本顺序和限制。
- routeros/01-preflight-and-backup.rsc：RouterOS 变更前检查与备份。
- routeros/02-prepare-controller.rsc：共享策略、路由表、mangle、DNS NAT、FastTrack 排除、IPv6 防漏。
- routeros/03-enable-device-template.rsc 和 routeros/99-remove-device-template.rsc：仅在管理页面不可用时使用的单设备手工接入/回退模板。
- routeros/04-health-netwatch.rsc：统一健康探针和故障时共享策略启停。
- scripts/family-mihomo-tproxy-auto：Z4Pro nft、策略路由和 TPROXY 同步的实际实现。
- runtime/family-proxy-ui.py：设备管理、RouterOS API、配置对账、审计和回退事务。
- runtime/family-proxy-gateway.py：统一登录网关和内部后端路由。
- tests/test_routeros_health_netwatch.py、tests/test_family_proxy_ui.py：回归测试。

## 3. 运维账户如何使用

### 本机 SSH 别名

本机 ~/.ssh/config 已配置以下别名。别名背后的主机、端口、用户名和密钥路径由 SSH 配置管理，本文件不复制这些凭据：

~~~sh
ssh -o BatchMode=yes z4pro
ssh -o BatchMode=yes rb5009
ssh -o BatchMode=yes z4pro-change
ssh -o BatchMode=yes rb5009-change
~~~

- z4pro：Z4Pro Linux shell 的 codexops 运维入口。
- rb5009：RB5009 RouterOS CLI 的 codexops 运维入口。
- z4pro-change：Z4Pro 变更入口，仅在用户明确授权后使用。
- rb5009-change：RB5009 变更入口，仅在用户明确授权后使用。

另一个 agent 只有在同一台 Mac、同一用户环境、同一 SSH agent/钥匙串可用时，才能直接复用这些入口。远程 agent、云端 agent、容器或不同用户不会自动获得本机局域网、密钥或权限。不要把私钥文件复制到工作区，也不要把密码写入 prompt 或 router.env 的版本库副本。

### 连接与身份自检

以下命令是只读连接自检；输出中可以报告主机名、用户名、RouterOS 版本和资源摘要，但不要报告密钥指纹以外的秘密材料：

~~~sh
ssh -o BatchMode=yes -o ConnectTimeout=8 z4pro 'hostname; id -un; printf "ready=z4pro\\n"'
ssh -o BatchMode=yes -o ConnectTimeout=8 rb5009 '/system identity print; /system resource print'
~~~

如果失败，按层定位并停止：

1. 本机密钥/SSH agent/钥匙串。
2. 到 192.168.2.156:14623 或 192.168.2.1:2222 的网络可达性。
3. 远端 SSH 服务和 host key。
4. 登录用户是否正确。
5. 登录后命令权限是否足够。

不要为了绕过权限错误而删除规则、改防火墙或扩大用户组权限。

### 账户权限边界

- codexops 的运维权限和 family-proxy-ui 的 RouterOS API 权限是两条不同路径。页面使用 API 账号，不要把 SSH 运维账号密码填进 /etc/family-proxy-ui/router.env。
- codexops 在历史验证中保持 RouterOS read 权限；即使临时获准加权限，也必须先备份、只加一个必要权限、完成后恢复负权限策略并复核最终组权限。
- 曾验证过：给 RouterOS 组临时加入 sensitive，以及尝试把 !write 调整为 write，通过 SSH/API 执行根级 /export 仍返回 not enough permissions (9)。这不是继续扩大权限的理由。
- RouterOS 文本导出权限不足时，仍可使用现有特权管理路径生成 /system backup save 二进制备份；不能声称已经生成文本导出。
- 不使用 sudo -S、命令行明文密码、shell history、临时环境变量或日志传递密码。Z4Pro 需要特权操作时，登录后按现场确认的 sudo 策略执行，并避免把密码写进命令。

## 4. 只读诊断基线

每次线上任务先记录时间、目标症状、影响设备、当前分支/提交和以下基线。命令要窄，避免一次输出超大配置导致截断。

### Z4Pro 基线

~~~sh
ssh z4pro 'hostname; id; uptime; ip -br addr; ip -br link'
ssh z4pro 'systemctl --no-pager --plain status family-proxy-ui family-proxy-gateway family-mihomo-tproxy-auto family-mihomo-sub-import --lines=30'
ssh z4pro 'ss -lntup | grep -E ":(53|7890|7893|9091|18088|18090|18093|18102)\\b" || true'
ssh z4pro 'sudo nl -ba /etc/family-proxy-ui/managed-ips; sudo nft list set inet family_mihomo_direct managed4; sudo nft list chain inet family_mihomo_direct prerouting; sudo nft list chain inet family_mihomo_direct postrouting'
ssh z4pro 'ip -br rule; ip route show table family_mihomo_shared; sudo systemctl --no-pager --plain status family-mihomo-tproxy-auto --lines=30'
ssh z4pro 'sudo journalctl -u family-proxy-ui -u family-proxy-gateway -u family-mihomo-tproxy-auto --since "30 min ago" --no-pager'
~~~

Z4Pro 没有保证安装 rg；远端搜索使用 grep/sed。不要把 /etc/family-proxy-ui/router.env、gateway.secret、订阅文件或节点配置直接输出到聊天。

### RB5009 基线

~~~sh
ssh rb5009 '/system resource print; /system package update print'
ssh rb5009 '/ip service print where name=api; /tool netwatch print detail where name="family-mihomo-tproxy-health"'
ssh rb5009 '/ip route print detail where routing-table="family_mihomo_shared" or dst-address="0.0.0.0/0"'
ssh rb5009 '/ip firewall address-list print detail where list="family_mihomo_devices" or list="family_cn_ipv4"'
ssh rb5009 '/ip firewall mangle print stats detail where comment~"family-mihomo"'
ssh rb5009 '/ip firewall nat print stats detail where comment~"family-mihomo"'
ssh rb5009 '/ip firewall filter print stats detail where comment~"family-mihomo"'
ssh rb5009 '/ipv6 firewall filter print stats detail where comment~"family-mihomo"'
ssh rb5009 '/ip firewall connection print count-only; /log print where topics~"error|warning|critical"'
~~~

不要未经请求执行 /export、/system backup save、/ip firewall ... remove、/system reboot 或用户权限修改；备份是变更前步骤，不是随意收集完整敏感配置。

### 页面/API 健康

从 Z4Pro 本机验证内部服务时，优先使用项目自带脚本：

~~~sh
ssh z4pro 'sudo /usr/local/sbin/verify-server'
~~~

实际安装路径可能不同，先用 command -v verify-server 或检查仓库脚本，再执行。需要确认的关键结果：

- family-proxy-ui、family-proxy-gateway、family-mihomo-sub-import active。
- Mihomo 控制接口可用，Proxy-Auto 有当前节点和候选列表。
- DNS 53 可解析，国内/国外方向按当前规则工作。
- RouterOS API 可连通且没有认证/权限错误。
- Netwatch 状态为 up，健康 URL 使用 18088。
- 配置对账 drift=[] 或页面显示无漂移。

若脚本不存在，按仓库 scripts/verify-server.sh 中的检查逻辑逐项执行，不要因为路径差异直接重装。

## 5. 如何判断设备是否真正生效

对目标设备 IP X.X.X.X，至少对照以下四层：

1. RB5009：family_mihomo_devices 包含目标 IP；DHCP lease/ARP 的 MAC 和 IP 对应正确；共享 mangle、DNS NAT、IPv6 防漏规则存在并有计数。
2. Z4Pro：/etc/family-proxy-ui/managed-ips 包含同一 IP。
3. Z4Pro nft：inet family_mihomo_direct 的 managed4 包含同一 IP；prerouting TPROXY、中国直连、局域网 return 规则和 postrouting SNAT 计数符合预期。
4. 实际流量：重新连接 Wi-Fi 或重新打开应用后，RouterOS shared mangle/DNS NAT 计数、Z4Pro nft/TPROXY 计数和 Mihomo 日志/策略计数增长；国内业务直连，外网业务进入正确业务策略。

健康状态应接近：managed=true、effective=true、drift=[]、netwatch=up。effective=false 可能只是没有新连接，不能立即判定失败；先清理旧连接/让客户端产生新流量，再看计数。

### 典型根因：RouterOS/Z4Pro 状态不同步

历史上 iPhone 192.168.2.189 的页面显示已加入但无法访问外网。证据是：

- RB5009 已将 .189 放入 family_mihomo_devices，并把外部连接通过 family_mihomo_conn/family_mihomo_shared 送往 192.168.2.156。
- Z4Pro /etc/family-proxy-ui/managed-ips 和 nft managed4 缺少 .189。
- kvmbr0 抓到重复 SYN，TTL 从 63 变 62，8 秒内有 3,649 个过滤包，证明是 RouterOS 到 Z4Pro 的转发递归，不是先归因于上游节点。
- UI 审计显示设备加入事务出现 no such item (4) 回滚/部分写入迹象，导致两端状态不一致。

遇到类似问题，先比对四层状态，不能只点“重新加入”或重启 Mihomo。

针对单台设备的只读抓包示例（目标地址和端口按现场替换）：

~~~sh
ssh z4pro 'sudo timeout 8 tcpdump -ni kvmbr0 -c 80 -vv "host X.X.X.X and (tcp port 80 or tcp port 443 or tcp port 5222)"'
~~~

重复相同 SYN 且 TTL 变化，优先查 RouterOS 到 Z4Pro 的递归/状态不同步；连接无包、计数不增长，再区分 DHCP、客户端、DNS、Mihomo、上游节点或防火墙。

## 6. 已完成工作与可复用结论

### 6.1 iPhone 旁路不同步问题

- 已完成根因定位并恢复到有效状态。
- 根因是 UI/RouterOS 地址表与 Z4Pro managed-ips/nft managed4 不一致，形成转发递归。
- 后续必须把设备加入视为事务：检查健康和冲突 -> RouterOS 写入 -> 保存 Z4Pro 状态 -> family-mihomo-tproxy-auto sync -> 校验 -> 清理旧连接；任一步失败要回滚已创建部分。
- 页面状态、RouterOS 状态、Z4Pro 状态和 nft 状态必须一起验证。

### 6.2 旧 Netwatch 健康监控

- 已修复并合并到家庭旁路仓库主线历史：旧监控探测 18087，当前统一网关为 18088；旧脚本还引用了历史设备和旧 auto 规则。
- 当前模板 routeros/04-health-netwatch.rsc 只维护一个 family-mihomo-tproxy-health，探测 18088，故障时只停用当前共享策略：family_mihomo_conn、family_mihomo_shared、DNS NAT 到 Z4Pro:53、FastTrack 排除和 family_mihomo_auto_v6。
- 已验证过 Netwatch status=up、管理 API ready=true、netwatch=up、drift=[] 和共享计数持续增加。
- 任何重新导入前，仍应读取当前脚本和在线 Netwatch，确认没有端口/地址漂移。

### 6.3 RouterOS 权限和导出

- 已创建过变更前二进制备份，并尝试临时最小权限提升。
- sensitive 和 write 的试验均已回滚；codexops 最终仍保持受限状态。
- /export 在测试路径仍返回 not enough permissions (9)；不能说有完整文本导出。
- 结论：不要为了导出继续扩大权限；若需要恢复证据，优先使用可用的二进制 backup，并明确其与文本导出的差异。

### 6.4 Telegram TPROXY checkpoint

- TG-Auto 和 TG-Notify 必须分离。
- 之前只验证过 Telegram 健康 URL、TPROXY 同步和监听器防护，实际图片/消息投递没有完整验证。
- 若继续该任务，先读 ip rule、ip route get 149.154.166.110 mark 0x2000、TPROXY/input 计数、唯一源端口的 Mac curl、RouterOS sniffer，再执行实际投递测试；此前 RouterOS 未因该 checkpoint 发生变更。

### 6.5 Z4Pro Docker/NAS 服务

- Z4Pro 上 Docker/NAS 服务的真实 Compose 路径必须由 docker inspect <container> 重新发现，不要假设历史路径仍存在。
- 历史 sub2api 维护使用过 docker inspect sub2api、Compose、.env、容器 inspect JSON、pg_dumpall 和校验和备份；重建后需要 /health 和关键数据库计数验证。
- Z4Pro NAS SSH 登录名的历史修正为 18053615760 的 NAS 账户，特权操作通过 sudo；不要把相关密码写入记忆或本文件。
- 观察到的 OAuth 代理拒绝曾是外部代理故障，不等于容器升级失败；服务健康和上游代理健康必须分开判断。

## 7. 日常操作流程

### 7.1 加入一台设备

优先使用管理页面的“加入旁路”，因为它实现了健康检查、冲突检查、事务回滚、RouterOS 写入、Z4Pro 状态保存、TPROXY 同步和旧连接清理。

加入前：

1. 管理页显示 Z4Pro、RB5009、DNS、Mihomo、策略组和自动回退正常。
2. 目标 IP 有 DHCP lease，MAC 对应正确；Apple 设备不要只依赖可能变化的 IP。
3. 确认设备没有被其它策略路由、主代理或另一套旁路代理接管。
4. 确认当前纳管状态无 drift。

加入后：

1. 检查 RouterOS 地址表、共享 mangle/NAT、IPv6 防漏。
2. 检查 /etc/family-proxy-ui/managed-ips 和 nft managed4。
3. 检查 family-mihomo-tproxy-auto 状态和 ip rule/family_mihomo_shared。
4. 让设备重新连 Wi-Fi/重新打开应用，验证一个国内业务、一个局域网服务和一个外网业务。

页面不可用时才使用手工模板：

1. 先执行 routeros/01-preflight-and-backup.rsc 和 routeros/02-prepare-controller.rsc 的当前版本。
2. 按现场 DHCP lease 填写 routeros/03-enable-device-template.rsc 的 IP/MAC。
3. 在 Z4Pro 把同一 IP 写入 managed-ips，执行 sudo /usr/local/sbin/family-mihomo-tproxy-auto sync。
4. 全部四层状态验证通过后才让用户继续使用。
5. 不要让同一设备同时由管理页面和手工模板管理。

### 7.2 撤出一台设备

优先使用管理页面“恢复直连”。它应移除共享地址表成员、IPv6 防漏、单设备旧规则/表、状态文件成员、TPROXY 状态和旧连接。完成后重新连 Wi-Fi，验证国内、局域网和外网均回到原有直连行为。

页面不可用时，使用 routeros/99-remove-device-template.rsc 只清理目标设备，再从 Z4Pro managed-ips 删除同一 IP 并运行 TPROXY sync。不要直接删除全部 mangle/NAT 或重写默认路由。

### 7.3 订阅、候选池和规则

- 订阅必须从本地网络直连导入，不经代理、Fake-IP、第三方转换站；不要在日志中打印订阅链接。
- 运行时使用人工筛选的候选池和 fallback，不把整份订阅直接暴露给业务策略。
- AI 候选池不使用香港节点；HK-视频、TG、Proxy 按业务范围使用。
- 修改规则/候选池一次只改一个业务类别，先验证再改下一个；失败优先回退上一版。
- 不因为单一网站失败就全网改 DNS；先判断是 DNS、分流规则、节点、MTU、客户端或路径问题。

### 7.4 升级和恢复

升级前：

1. 记录运行容器、镜像、卷挂载、重启策略和当前服务状态。
2. 备份 Z4Pro Compose、.env、inspect JSON、数据库导出、候选池、Mihomo 配置和 systemd 文件。
3. RouterOS 保存文本导出（若权限允许）和二进制 backup；权限不足要明确记录。
4. 确认备份介质、空间和恢复路径。

升级后：

1. 先做语法/加载检查，再只重启相关服务。
2. 检查健康接口、日志、Mihomo 控制接口、DNS、Netwatch 和配置漂移。
3. 验证真实客户端路径，不以 systemd active 或容器 running 作为唯一成功标准。
4. 失败时使用本次变更前备份恢复，不混合多个历史版本手工拼接。

代码仓库的标准升级入口是：

~~~sh
cd /Volumes/NAS/File/codex/projects/family-proxy-manual
git status --short --branch
git pull --ff-only
sudo ./scripts/upgrade-server.sh
sudo ./scripts/verify-server.sh
~~~

若工作区有他人未提交修改，先保护现场，不要 reset、checkout 或覆盖；需要合并时使用临时干净 worktree。

## 8. 故障排查决策树

### A. 单台纳管设备不能上网

按顺序检查：

1. DHCP lease、ARP、IP/MAC 是否正确。
2. RouterOS 是否仍在 family_mihomo_devices，mangle/NAT/FastTrack 排除计数是否增长。
3. Z4Pro managed-ips 与 nft managed4 是否同一集合。
4. 7893 是否监听，TPROXY 计数是否增长，ip rule/本地路由表是否存在。
5. Mihomo 策略组是否有有效当前节点，DNS 是否可解析。
6. 抓包判断是无包、重传、递归还是上游连接失败。

先恢复直连通常比重启全套服务更安全；但恢复前仍要保存证据并确认目标设备。

### B. 国内 App 慢/图片迟到

优先查 DNS、family_cn_ipv4 地址表、RouterOS CN direct 计数、Z4Pro nft cn4 计数、旧连接和是否误进入 Mihomo。不要先全局改代理或禁用 FastTrack。

### C. 外网/AI/Telegram 失败

先查具体业务策略和当前叶子节点，再查 Mihomo 日志、DNS 方向、TPROXY/input 计数和实际目标地址路径。Telegram 用户流量与通知路径分开检查。

### D. 页面显示已加入但实际不通

直接按第 5 节四层对账；页面状态不是证据。若出现重复 SYN、TTL 变化，优先判定 RouterOS/Z4Pro 状态不同步或转发递归。

### E. Netwatch down

1. 从 Z4Pro 只读检查统一网关 18088 和 /api/health。
2. 从 RB5009 检查 Netwatch 目标、状态、上/下脚本和当前共享规则启停状态。
3. 检查 Z4Pro 服务、Mihomo listener、DNS 和本地 API。
4. 只有确认健康接口和端口现状后，才考虑重新导入 routeros/04-health-netwatch.rsc。
5. 不要恢复历史 18087，不要把旧设备 .105/.107 或旧 auto 规则重新写回。

### F. CPU 高或网络循环

先做 RouterOS /tool profile、连接计数、Z4Pro top/ss、nft 计数和窄范围 tcpdump。重复 SYN/TTL 变化优先查路径递归；不要先重启健康服务或全局关闭 FastTrack。

## 9. 变更审批、备份、回滚和报告模板

在执行任何线上变更前，向用户明确：

~~~text
目标：
现象与证据：
根因假设及置信度：
影响范围：
将使用的入口/账号类型：
变更前备份：
精确变更：
回滚动作：
验证指标：
预计用户可见影响：
~~~

完成后按同一指标报告：

~~~text
Before：路由、计数、CPU、服务健康、目标设备状态
Change：实际执行的非敏感命令/脚本和备份标识
After：同一组指标、客户端实际验证结果
Decision：保留、继续调整或已回滚
Residual risk：未验证的路径、权限、节点或真实业务
~~~

RouterOS 变更要求：

~~~routeros
/export hide-sensitive file=family-proxy-prechange-<timestamp>
/system backup save name=family-proxy-prechange-<timestamp>
/system resource print
/system package update print
~~~

如果 /export 因权限失败，记录失败，不要扩大权限；确认二进制 backup 是否成功，并明确恢复能力边界。

## 10. 不应做的事情

- 不执行 git reset --hard、git checkout -- 覆盖工作区修改。
- 不把 auth.json、SSH 私钥、RouterOS 密码、API 密码、订阅链接、节点原文、.env、数据库备份或抓包提交到 Git。
- 不全局禁用 FastTrack、重写默认路由、全网 DNS 劫持、删除全部 mangle/NAT/filter、重启 RB5009 或清空 nft 表来“试试看”。
- 不使用历史端口 18087 代替当前统一健康端口 18088。
- 不用 7893 做 HTTP 代理测试；HTTP 测试使用 7890，TPROXY 用实际流量和计数验证。
- 不只看 UI 的 joined/healthy 字样；必须对账和走真实客户端路径。
- 不把临时权限提升留在设备上；失败也要回滚并复核最终权限。
- 不声称“已修复/已验证”而实际上只做了本机命令、服务进程检查或单次网络探针。

## 11. 交接时的第一轮动作

另一个 agent 接手家庭旁路系统时，第一轮只做以下工作：

1. 阅读本文件以及家庭旁路仓库的 README.md、DEPLOYMENT.md、routeros/README.md。
2. git -C /Volumes/NAS/File/codex/projects/family-proxy-manual status --short --branch，识别未提交修改，不覆盖。
3. 使用 ssh z4pro 和 ssh rb5009 做身份/可达性自检。
4. 采集第 4 节基线，确认实际端口、服务、路径、RouterOS 版本和当前纳管设备集合。
5. 将实时观察与本文件的历史记录分开记录；若有冲突，以最新只读证据为准，并更新项目文档/用户报告，而不是悄悄改配置。
6. 只有用户给出明确变更目标和授权后，才进入备份、最小变更、验证和回滚流程。

## 12. 2026-08-13 维护审计与落地记录

以下为一次完整维护审计及已批准变更的落地结果，作为后续交接的最新基线。

### 仓库与版本基线

- 本地仓库已切换到 `main` 分支，HEAD = `829bc98`（Release v0.11.10），与 origin/main 对齐；旧分支 `agent/fix-netwatch-health-probe` 保留未删。
- 本仓库位于 NAS 挂载（/Volumes/NAS/...），挂载层不保留文件执行位（git 索引 644 的文件在文件系统上显示为 700/755）。已设置 `git config core.fileMode false`，git status 不再把这种元数据漂移当作修改；提交时脚本执行位以 git 索引为准，不要用 chmod 在挂载层反复纠正。
- 生产 Z4Pro 控制平面已从 0.11.9 升级到 0.11.10（upgrade-server.sh），备份在 `/var/backups/family-proxy/20260813-122556/`；升级前快照在 `/var/backups/family-proxy/pre-upgrade-20260813-122437/`。
- 生产 `router.env` 补齐了 v0.11.10 必填键 `ROUTER_MODE=routeros`（按键名最小追加，未改动其它行）。
- Z4Pro 运维副本在 `/home/codexops/family-proxy-manual/`（由仓库 rsync 同步，非 git 仓库），是 `deploy-family-proxy-ui` 的 `SOURCE_DIR` 且与生产 `/opt` 哈希一致；`/home/codexops/family-proxy-manual-main/` 是一次性陈旧副本（`rules.html` 哈希与生产不一致），勿再当作部署源。

### 端口与组件澄清

- 18087 不是残留：当前 gateway 按 `LEGACY_HEALTH_PORT=18087` 同时兼容监听，返回 403 属鉴权响应；Netwatch 仍只探测 18088，不得改回 18087。
- 18091 是 docker-proxy 把 mosdns-ui 容器（172.31.53.3:9099）发布到 LAN 的端口，供 gateway 遗留 DNS 路由（/api/v1/、/api/v2/、/plugins/）转发，属设计内。
- 2900/3001 规则不是遗留：`homekit-direct-routes.timer`（每分钟）按 RouterOS DHCP lease 维护 Z4Pro→HomeKit 设备的直连规则；删除会被自动恢复，勿清理。
- family-mihomo-listener-guard 已移除历史 192.168.2.105/.107 放行项；7893 仅放行 RouterOS 192.168.2.1 与当前 managed-ips；备份为 `/var/backups/family-proxy/family-mihomo-listener-guard.20260813-122435`。

### verify-server 与指纹口径

- 以仓库 main 版 scripts/verify-server.sh 为准（含 18087/18088 端口探测与 build 指纹校验）。
- build-info.json 的 id 由 install-server 对渲染后的 ui/gateway + VERSION + frontend/dist/index.html 四个 sha256 拼接再哈希（前 12 位）生成；指纹不匹配时用 upgrade/install 重新生成，不要手工改校验逻辑或扩权。
- 2026-08-13 因旧部署流程生成的 build id 与现行算法不一致，已重建 build-info（备份 `/var/backups/family-proxy/build-info-20260813-085015.json`），随后升级到 0.11.10 时由安装器再次生成并校验通过。

### 遗留与边界

- RouterOS 二进制备份因 codexops 权限不足失败（`not enough permissions (9)`），已记录，未扩权；升级不涉及 RouterOS，RouterOS 侧未做任何变更。
- Telegram 实际消息投递仍由用户用自己的会话验证；DNS 方向全量回归（--full）已通过。
- 未接管设备的直连行为与真实客户端业务验证需由用户在受管设备上实测。

### RouterOS 变更与备份授权（2026-08-13 用户明确授权）

- 用户授权原则：以后任何 RouterOS 修改，必须先备份、后修改；为生成备份，用户预先批准临时提升 codexops 权限，完成后必须恢复并复核。
- 当前 RouterOS 权限基线（只读实测）：
  - codexops 用户组 = `read`（策略含 read/test/sniff/sensitive/api/ssh，无 write/policy）。
  - 已存在的专用组：`router-backup`（ssh/ftp/reboot/read/write/policy/test/password/sniff/sensitive/romon，无 api/winbox/web，历史二进制备份路径）、`codex-change`（ssh/read/write/test，无 policy/sensitive，历史临时变更组）、`family-proxy-ui`（API 账号组）。
- 未来标准流程（仅在用户发起 RouterOS 变更时执行）：
  1. 记录当前用户组与策略；尝试 `/export hide-sensitive file=family-proxy-prechange-<ts>` 与 `/system backup save name=family-proxy-prechange-<ts>`。
  2. 若权限不足，按用户预先批准临时将 codexops 切换到 `router-backup`（或最小权限方案），只生成二进制备份（必要时再试文本导出），成功或失败都要记录。
  3. 立即恢复 codexops 到 `read`，复核最终用户组策略。
  4. 再执行精确变更，变更后从 RouterOS 状态、计数、Netwatch、日志和真实客户端路径验证；失败用本次备份回滚。
- 该授权只覆盖“变更前备份所需的临时提权”，不构成对任意 RouterOS 修改的预授权；每次具体修改仍需用户明确目标。

## 13. 2026-08-13 UI 变更与发布记录（v0.11.11 / v0.11.12）

以下为同一维护周期内完成的新版控制台 UI 变更与发布信息，作为后续模型接管的补充上下文。

### 发布版本

- v0.11.11：tag 与 GitHub Release 已发布（含设备图标选择、DNS 内容过滤与更新反馈、各页排版优化、系统维护卡片合并等）。
- v0.11.12：tag 与 GitHub Release 已发布（含总览页重构、KPI 调整、悬停交互）。
- 升级方式：`git pull --ff-only && sudo ./scripts/upgrade-server.sh`；DNS 数据管理页升级后点击“重新载入”。

### 主要 UI 变更（均在新版控制台 frontend/src/App.vue + frontend/src/styles.css）

- 设备管理：点击设备左侧图标可打开选择面板（26 种样式），选中保存只提交 `{mac, icon}`；“编辑设备”弹窗只保留改名；流量观察“设备活动”卡片的图标同样可点击更换，保存后即时刷新。
- DNS 管理：
  - 解析路径卡片版式（上游标签居中、地址逐行、无多余装饰），全页字号排版优化；
  - “精简内容过滤”更名为“内容过滤”，关闭/观察/拦截改为独立按钮，切换即时反馈（切换中/成功/失败），不再依赖刷新；
  - “立即检查并更新”轮询 `/rules/status`（最长约 60 秒）并显示更新中/成功/失败与最近结果时间；
  - “规则数据”卡片紧凑化。
- 流量观察：字号与排版协调优化。
- 系统维护：“平台更新状态”并入“核心组件与设备”卡片并补齐 Mihomo/Z4Pro/MosDNS/RB5009 版本号，卡底显示上次检查时间；“异地回家”卡片补 13px 下间距。
- 总览页：KPI 改为已接管设备/活动连接/当前出口/DNS 平均处理（可点击跳转，悬停有小手与上浮效果，当前出口数值字号 17px）；异常时状态头显示“N 项需检查”；运行状态卡新增配置漂移提示；进入总览自动加载 DNS 统计。
- 旧版设备页（runtime/family-proxy-ui.py）：警告徽标配色与 tooltip 遮挡修复。
- 机场候选池：候选池页在“筛选节点名称”下方新增测速/应用进度条与状态行（每秒轮询后端 `/api/test-status`，显示 completed/total、GitHub 专项阶段、完成/失败结果）；覆盖“三次稳定性测速”“复测并生效”“校验并应用”“回退上一版”。后端进度接口本就存在（旧版机场页在用），新版控制台此前未接入。
- 机场候选池（订阅来源卡片重构）：去掉“来源/地址/操作”三列表头；每个来源改为独立小卡片（`.source-row` 圆角内衬）：左上是序号+机场名+导入状态+最后更新，右侧为操作按钮，整行下方放订阅链接输入框（`.source-url`）。删除冗余的“当前生效来源/备用来源”小字（原会被挤压遮挡）；备用机场的删除图标移到操作组最左侧，保证两行的“直连导入或替换/清空”按钮纵向对齐。桌面端双列（名称+按钮 / 输入框整行），移动端单列堆叠。
- 机场候选池（切换状态页）：当前出口保持**每个出口组一张卡片**的原始样式（`surface-card runtime-card` + `runtime-facts` 2×2 信息块，`runtime-grid` 双列）；曾尝试改为紧凑表格行（23:09/23:11/23:15 三次迭代），用户反馈不如原样式，已整体回退到原始卡片布局，`.runtime-row/.runtime-columns/.runtime-phase` 相关样式不再使用。
- 机场候选池（流程修复）：全量测速完成后自动把 `suggestions.pools` 载入候选池草稿，再点“复测并生效”才会复测建议节点。此前新版控制台从未使用 suggestions，导致“复测并生效”一直复测旧池（例如 US-AI 池旧节点未通过 3/3 时被清空并报“必须是 1 至 5 个不重复节点”）。
- DNS 概览版面优化：常用域名与活跃设备下移到竞速区下方；概览内容用纵向容器统一 18px 间距；上游地址单行（省略号）、竞速小字允许换行不截断；**解析路径拆为“国内解析/国外解析”两张独立卡片**（不再有大卡片套小卡片，`.route-cards` 双列网格，移动端单列）；每张卡片内问号图标以**居中弹窗**展示该组竞速数据（原固定竞速卡片与卡片内联面板均已移除），铅笔图标**只编辑对应一侧上游地址**（弹窗仅显示该侧输入框，未编辑侧沿用当前配置提交，后端 `/upstreams` 契约不变）。弹窗容器 `.dns-race-modal`：宽 `min(760px, calc(100% - 28px))`、最大高 `min(720px, calc(100vh - 40px))`、内容可滚动，列表沿用 `.dns-race-columns/.dns-race-row` 四列网格；移动端沿用现有 760px 断点折叠布局。弹窗遮罩 `.dns-race-backdrop` 限定在右侧内容区（`left: var(--sidebar-w)`，跟随 244/214/0px 断点），不遮挡左侧固定菜单栏。

### 2026-08-13 22:42 追加部署（DNS 竞速居中弹窗，未发 release）

- 变更：DNS 概览“国内上游/国外上游”竞速面板从卡片内联改为居中弹窗（点击解析路径卡片内问号图标触发，点遮罩或关闭按钮退出），避免面板内嵌挤压卡片与弹层。
- 版本：仍为 v0.11.12，未 bump；本次仅 UI 微调，尚未打 tag / 发布 release。
- 部署：rsync frontend → Z4Pro `/home/codexops/family-proxy-manual-main/frontend` → `sudo ./scripts/install-server.sh --start`；`verify-server.sh` 通过（control-plane local checks passed）。
- 产物：`/opt/family-proxy-ui/frontend/` 现引用 `index-CFdnphLq.css`、`index-YMJshlph.js`；build-info.json id `c6e8e581d479`（deployed_at `20260813-224213`）。
- 22:45 跟进：遮罩加 `.dns-race-backdrop`（`left: var(--sidebar-w)`），弹窗限定在右侧内容区居中，不再盖到左侧菜单栏；弹窗宽度改相对内容区 `calc(100% - 28px)`。重部署后产物为 `index-CwqdwV8N.css`、`index-CQ6vsR65.js`，build id `5298c89b570e`（deployed_at `20260813-224554`），verify-server 通过。
- 22:51 跟进：解析路径从单张“解析路径”大卡片拆为“国内解析/国外解析”两张独立卡片（`.route-cards` 双列网格）；移除大卡片标题旁铅笔；每张卡片铅笔只编辑对应一侧上游地址（新增 `dnsUpstreamEditSide`，弹窗只显示该侧输入框，未编辑侧按当前配置补齐后提交）。重部署后产物为 `index-D0MZBRGB.css`、`index-68Coq4ra.js`，build id `d7f098838568`（deployed_at `20260813-225155`），verify-server 通过（刚重启后 18087/18088 偶发短时不可达，稍等重跑即可）。
- 22:57 跟进：`npm run typecheck` 清零（此前 5 个历史报错）：移除未使用的 `Robot` 导入；新增 `SummaryPayload` 类型并让 `summary` computed 使用它（覆盖 ready/mode/netwatch/router/drift/version/build_id/proxy_ip/checks/detail/router_resource）；机场测速状态里的建议候选池显式按 `Record<string, string[]>` 读取。纯类型/死代码修复，产物哈希不变（仍为 `index-D0MZBRGB.css`、`index-68Coq4ra.js`，与线上逐字节一致），未重启服务；后续维护可直接 `npm run typecheck` 作为前置校验。
- 23:05 跟进：订阅来源卡片重构落地（去三列表头、每来源独立小卡片、操作按钮对齐、去掉会被遮挡的小字）。产物 `index-DwPkCwR3.css`、`index-BP97lxcf.js`，build id `8d3d270c51fe`（deployed_at `20260813-230527`），verify-server 通过。
- 23:09 跟进：切换状态页“当前出口”下方改为紧凑表格行（`.runtime-row`），压缩纵向空间。产物 `index-D9Vp-Biv.css`、`index-Be2Cqkah.js`，build id `8bc3d780159a`（deployed_at `20260813-230943`），verify-server 通过。
- 23:11 跟进：修正“当前出口”表格风格，包进 `surface-card failsafe-card` 卡片（卡头含标题/说明/刷新按钮，表格嵌卡内），与页面其余卡片一致；CSS 未变，JS 产物 `index-BhxrnPjL.js`、build id `d6a32d140d1b`（deployed_at `20260813-231141`），verify-server 通过。
- 23:15 跟进：去噪“当前出口”表格：桌面端单元格只显示值（小标签隐藏，避免与表头重复），行高放宽到 64px、状态加圆点标识、最近探测长文本截断并带悬停提示；移动端才显示单元格小标签。产物 `index-tcLQVMcU.css`、`index-BFAVqfiV.js`，build id `76357ad7e54a`（deployed_at `20260813-231507`），verify-server 通过。
- 23:18 回退：切换状态页“当前出口”整体回退到 7f3b1e6 的原始卡片样式（每个出口组一张卡片 + 2×2 信息块）；`App.vue`/`styles.css` 与 7f3b1e6 逐字一致，产物回到 `index-DwPkCwR3.css`、`index-BP97lxcf.js`，build id `8d3d270c51fe`（deployed_at `20260813-231805`），verify-server 通过。后续若再改此页，先与用户确认参考样式，避免反复试错。
- 交接注意：后续发布 release 时，本弹窗改动与上一批 DNS 概览改动（commit `cac4a12`、`08da8f7`）一并进入版本号与发布说明；GitHub push 曾连续 Internal Server Error，推送失败时重试即可，本地 main 已领先 origin。

### 交接注意（构建与部署）

- 仓库在 NAS 挂载上不保留执行位，已设 `core.fileMode false`；不要用 chmod 反复纠正。
- 本机 NAS 上直接 `npm ci` 会因 esbuild postinstall 失败；构建流程：把 frontend 同步到本地临时目录（如 /tmp/fb.xxx，排除 node_modules/dist）→ `npm ci && npm run build` → 把 dist 拷回仓库 `frontend/dist`。
- 部署：rsync frontend 到 Z4Pro `/home/codexops/family-proxy-manual-main/frontend`（排除 node_modules），再 `sudo ./scripts/install-server.sh --start`；改 VERSION 或 runtime/family-proxy-ui.py 时要同步到仓库副本对应路径。
- 旧版 DNS 仪表盘（/dns/）：源文件 `runtime/mosdns/dashboard.html`，部署时备份后复制到 Z4Pro `/tmp/zfsv3/nvme13/18053615760/data/docker/family-mosdns-t/web/index.html`。
- 发布流程：bump `VERSION`、`frontend/package.json`、`runtime/family-proxy-ui.py` 的 BUILD_VERSION、`App.vue` 侧边栏回退版本 → 构建 → 部署 → commit → `git tag -a vX.Y.Z` → push main 与 tag → `gh release create vX.Y.Z`。
- GitHub push 偶发 `Connection reset by peer`，重试即可。

## 14. 2026-08-13 16:20 定期维护审计与修复记录

### 审计结论

- 总体：警告（系统运行健康，四层一致、流量正常；发现 1 项已修复的发布一致性问题 + 1 项待用户确认的容器事件 + 1 项观察项）。
- 基线：main @ `910f0a8`，v0.11.12，工作区干净；审计全程只读，无生产变更；修复均在人工批准后执行。

### 发现与处理

1. **已修复（发布一致性）**：`tests/test_first_run_setup.py` 此前硬编码断言 `BUILD_VERSION = "0.11.10"`，随版本升级（0.11.11/0.11.12）导致 46 项测试中 1 项失败。已改为从仓库 `VERSION` 文件读取并断言 `BUILD_VERSION` 与之一致（并校验格式），本地与 Z4Pro 全量 46 项测试通过。
2. **已澄清（容器事件，属预期行为）**：2026-08-13 12:26 family-mihomo-fallback 的停止/启动来自升级链路 `family-mihomo-sub-import.py --apply-current` 应用候选池后自动执行 `restart_mihomo()`（`docker restart family-mihomo-fallback`），属预期自动重启（约 1–2 秒），非外部手动操作、非异常。docker 事件中的 `hasBeenManuallyStopped=true` 是 `docker restart` 停止阶段的 API 标记；容器 ID 在事件前后一致（同一容器重启，非重建），无 OOM/错误。后续审计遇到相同事件可直接归因于升级/应用候选池流程，无需再报异常。`family-mihomo-docker-health.timer` 仍只检查镜像仓库可达性，不负责容器运行态；如未来需要自愈保护再另行评估。
3. **观察项**：Z4Pro 负载约 1.6、iowait 16.9%（smbd 活跃），服务与接口正常，暂不处理。

### 交接要点

- 发布流程新增注意：bump 版本时检查是否还有硬编码旧版本号的测试断言（当前已改为动态比较 VERSION）。
- mihomo 容器若再次出现“手动停止”事件且无人工操作，按 AGENTS.md 第 8 节决策树排查并考虑加 watchdog。

### 风险验证结果（2026-08-13 16:35）

- DNS 方向：`verify-dns-routing.sh --full` 通过（国内 6 域名全部 domestic、国外 6 域名全部 foreign；执行时清了一次 MosDNS 缓存）。
- Telegram 路径：`ip route get 149.154.166.110 mark 0x2000` 正确落到 family_mihomo_shared；经 Mihomo 本机代理唯一源端口访问 api.telegram.org 返回 302；config 中 TG-Auto/TG-Notify 规则在位。**实际消息投递仍需用户用自己的 Telegram 会话验证（不代持凭据）**。
- 真实客户端业务：RouterOS 标记连接 48 条，其中 .189 活跃 21 条，证明受管设备真实业务流量在走旁路路径；应用级功能（国内/局域网/外网）仍需用户在设备上实测。
- Z4Pro 负载：iowait 已回落至 0% wa、load 约 1.35（早前 16.9% wa 为瞬时 SMB 活动）；24h 内无 OOM 杀进程。另观察到极空间外部组件 `zfrpc.service` 01:26 单次失败（非本系统，仅记录）。

### TG 推送故障排查（2026-08-13 16:38）

- 现象：用户在局域网报告 Telegram 推送失败；经查当前推送路径正常。
- 结论：不是规则问题。证据：`/api/alerts/test` 返回“测试消息已发送”；mihomo 日志确认 127.0.0.1→api.telegram.org 命中 `AND((SrcIPCIDR,127.0.0.1/32)&&(Domain,api.telegram.org))→TG-Notify`；TG-Notify（Fallback，3 候选）对 api.telegram.org 探测 3/3 可达；TG-Auto（URLTest，5 候选）5/5 健康，客户端 MTProto（149.154.x/91.108.x）连接活跃。
- 已记录的两条排查经验：① `/group/*/delay` 用默认 gstatic 探测 URL 可能误报（TG-Notify 默认探测 0/1，换成 api.telegram.org 后 3/3），判断 Telegram 可达性应使用 Telegram 真实端点；② 系统告警推送路径 = family-proxy-ui.py `send_alert_test()` / 更新提醒，经 `curl --proxy http://127.0.0.1:7890` 到 api.telegram.org，命中 TG-Notify 规则。
- 待用户补充：失败发生的时间点、具体是“系统告警测试/更新提醒”还是“手机 App 通知”、当时的报错文本；若再次失败，抓取当时 mihomo 日志与 `/api/alerts/test` 返回值定位。

### TG 推送故障二次排查结论（2026-08-13 16:55，iPhone .189 在局域网）

- 用户反馈：iPhone（192.168.2.189）在局域网完全收不到 Telegram 弹窗通知；5G 下正常。
- 系统侧已排除：RouterOS 连接表显示 .189 存在**活跃且直连的 APNs 会话** `17.188.171.133:5223`（TCP established，orig 4,015 包 / 3.08 MB，repl 2,891 包收包正常，回复目的地为公网 WAN IP，未进旁路/代理）；另有 Apple 中国节点 101.226.142.171:443 与 NTP 17.253.68.251:123 连接。APNs 通道在正常收发，Apple→iPhone 推送链路未发现阻断。.189 当前无 Telegram DC（149.154.x/91.108.x）连接，IPv6 guard 计数增长极缓（+10/20min）。
- 结论：网络/旁路系统未阻断推送，指向 iOS/Telegram 客户端侧（通知权限、专注模式、APNs 令牌或 App 后台状态）。下一步验证：用户触发测试消息时观察 .189 的 APNs 会话 repl 计数是否增长（增长=Apple 在投递，问题在显示侧；不增长=令牌/Telegram 服务端未下发）。

### TG 推送根因确认（2026-08-13 17:05，iPhone .189）

- 现象：iPhone .189 在局域网完全收不到 Telegram 弹窗；5G 下正常；手机侧通知设置/重启 TG/专注模式均已排除。
- 根因：**TG-Auto 代理节点无法承载 Telegram MTProto 会话**。RouterOS 双采样显示 .189→149.154.175.50:443 的连接带 `connection-mark=family_mihomo_conn`（正确走 TG-Auto），但每次只交换约 389B 发送 / 305B 接收即停滞并断开重连（新连接号持续出现）；APNs 会话（17.188.171.133:5223）保持空闲且下行不增长。即 App 无法经代理维持 Telegram 后台连接 → 推送依赖的连接不可用。
- 旁证：mihomo 对 Telegram DC IP 的 SNI 嗅探报 `may not have any sent data` 属 Telegram MTProto 非标准握手导致，路由已回退 IPCIDR 命中 TG-Auto，非故障原因；TG-Auto 对 DC 的简单 delay 探测 5/5 通过（探测不敏感，无法发现 MTProto 停滞）。
- 修复方向（待用户操作/授权）：在管理页把 TG 策略组当前节点（主力 HK）切换为其它候选（或复测并生效），iPhone 杀掉 Telegram 重开后验证；若所有 TG 候选都失败，说明该批节点被 Telegram 对 MTProto 封禁/限速，需更换机场节点。切换后复查 .189 的 MTProto 连接 orig/repl 计数是否持续增长。

### TG 推送根因最终确认（2026-08-13 17:20）

- 用户已切换 TG 节点并实测，仍收不到推送；字节级观测与握手探针最终确认根因：**TG-Auto 机场节点无法中继 Telegram MTProto 会话**（TCP 可建连，MTProto 握手数据不流动）。
- 探针结论：经 `127.0.0.1:7890`（命中 IPCIDR→TG-Auto）向 149.154.175.50 / 91.108.56.149:443 发送规范 MTProto 混淆头（64B、首字节 0xEF），两个 DC 均无响应（超时）；Z4Pro 直连（不经代理）同样超时，说明国内 WAN 直连 Telegram DC 被阻断，只能依赖节点，而当前节点（切换前后）均不通。
- 可复用诊断方法：给 TG 池更换节点后，先用该握手探针验证节点是否真的能承载 MTProto（期望收到 64B 响应），再让用户测试，避免反复试错。简单 delay 探测（/group/delay）对 MTProto 不敏感，不能用它判断。
- 修复：换用能承载 Telegram MTProto 的节点/机场（优先试备用机场 2 的节点）；若全部候选都不通，需更换机场供应商。

### TG 节点自动切换与验证结果（2026-08-13 17:30）

- 已按用户授权对 TG-Auto 全部 5 个候选节点逐个执行 `PUT /proxies/TG-Auto` 选择（均返回 204）并做 MTProto 握手探针：**5/5 全部无响应（0 字节）**。当前机场（主力）的 TG 线路整体无法承载 Telegram MTProto，已排除“单个节点坏”的可能。
- 结论与建议：需在 TG 候选池加入其它线路的节点（优先备用机场 2，或新机场），加入生效后可用同一探针脚本复验；若备用机场 2 也失败则需更换机场。
- 备选方案（需用户批准，涉及规则/配置）：TG-Notify 组节点对 api.telegram.org 可达（系统 Bot 推送成功），可评估把 Telegram 客户端流量临时改走 TG-Notify 组或并入其节点；但 TG-Notify 组节点是否能跑 MTProto 尚未验证。
- 诊断脚本要点：探针 = 经 127.0.0.1:7890 SOCKS5 CONNECT 到 DC IP:443，发送首字节 0xEF 的 64B MTProto 混淆头，期望收到 64B 响应；`/group/*/delay` 探测对 MTProto 不敏感，不能用于判断。

### 修正：前台可用，问题在后台推送（2026-08-13 17:40）

- 用户实测：**Telegram 前台（App 打开）消息正常收发；后台（退出/挂起）收不到推送**；5G 下后台推送正常。
- 更正此前结论：MTProto 代理路径是通的（前台可用），之前 64B 握手探针 0 响应属**假阴性**（Telegram DC 对不完整握手不回应），不能作为“节点无法承载 MTProto”的依据；5 节点全部失败的同探针结论一并作废。
- 现状事实：.189 后台无推送，APNs 会话（17.188.171.133:5223）在且直连但下行不增长；前台 MTProto 正常。
- 候选根因（均为局域网受管设备特有、5G 无）：A) iOS APNs 走 IPv6 被防漏链拒绝（.189 IPv6 尝试量低，证据弱）；B) iOS 17+ 推送可能使用 QUIC/UDP 443，被“family-mihomo-shared QUIC fast fallback”reject 规则阻断（未验证）。
- 待办：经用户批准后，做受控 RouterOS 测试（先备份）：① 放行 .189 的 UDP 443 测 QUIC 假设；② 若无效，放行 .189 IPv6 测 IPv6 假设；找到生效项后收敛为最小规则（如仅 Apple 推送目的），无效即回滚。

### 备用节点方案评估（2026-08-13 17:50）

- 备用机场 2 已导入 170 节点，但 TG-Notify 组里仅 2 个备用节点，且其中只有 1 个符合 TG 池地域规则（POOLS["TG"] 关键词），无法把 TG 池整体替换为备用节点；机场 API 受 CSRF 保护，修改候选池需经管理页操作。
- 结论修正：前台 MTProto 正常说明代理节点非瓶颈；后台推送失败更可能是 iOS 推送通道（APNs）在受管局域网被影响——候选根因仍为 A) IPv6 被防漏链拒绝、B) UDP 443 被 QUIC 规则拒绝（5G 均不经过这些规则）。
- 待办（需用户批准 + 先 RouterOS 备份）：受控试验 ① 放行 .189 UDP 443；② 放行 .189 IPv6；确认生效项后收敛为最小规则并固化，无效即回滚。

### 2026-08-14 规则集合手动来源类型回填修复

- 现象：在规则集合卡片中手动输入 HTTPS 地址，再选择“复合规则”和“文本”并保存到草稿后，卡片及再次编辑仍显示 `domain · mrs`。
- 根因：旧版 `/rules` 页面在地址输入时先用默认值创建来源对象；后续下拉框只更新界面，没有更新这个已创建对象。保存时对象中的默认 `behavior/format` 被保留。新版控制台也会把 URL 作为集合来源重新生成，存在同类覆盖风险。
- 修复：`runtime/rules.html` 和 `frontend/src/App.vue` 对已保存来源按 URL 区分内置预设与手动来源；非预设 URL 继续视为手动来源，编辑时行为类型/文件格式会回写该来源，预设来源保持自身类型。`manual` 仅为前端编辑态字段，不会提交到规则集持久化数据。
- 验证：旧版内嵌脚本 `node --check`、46 项 Python 回归、前端 `npm run typecheck` 和 `npm run build` 全部通过；Playwright 模拟已有 `domain · mrs` 手动来源编辑为“复合规则/文本”，来源详情、草稿卡片、校验应用后的卡片及再次编辑均显示 `复合规则 · TEXT` / `classical · text`。
- 生产部署（2026-08-14）：已按备份流程部署到 Z4Pro，备份为 `/var/backups/family-proxy/20260814-101552`；生产 `rules.html` 与本地修复源码哈希一致，`scripts/verify-server.sh` 通过。浏览器访问生产 `/rules` 已正常进入统一登录页，未使用或记录登录凭据，因此未声称完成登录后的页面交互复验。
- 部署链路修复：`scripts/deploy-family-proxy-ui` 现在会备份并安装旧版 `rules.html`，并将旧版页面与 QR 运行时纳入 `build-info` 指纹；`scripts/sync-z4pro-source` 将 `verify-server.sh` 纳入关键文件校验，避免旧版核验脚本残留。
- 最新生产部署（2026-08-14）：二次修复已部署，构建 ID 为 `a222bd633fee`，备份为 `/var/backups/family-proxy/20260814-104311`，`scripts/verify-server.sh` 通过。同步脚本现在按内容直接同步完整 `frontend/dist`，并将 `runtime/rules.html` 纳入关键文件校验，避免新哈希资源或旧版页面变更漏传。

### 2026-08-14 总览活动连接卡片跳转修复

- 变更：总览页“活动连接”KPI 卡片补齐与“已接管设备/当前出口/DNS 平均处理”一致的交互；支持点击或 Enter 键跳转到 `traffic` 流量观察视图，并显示统一的悬停箭头反馈。
- 版本：仍为 `v0.11.12`，本次未 bump 版本号。
- 本地验证：临时构建目录中的 `npm run typecheck` 与 `npm run build` 通过；46 项 Python 回归通过；生成前端资源为 `index-DVmGmsAE.css`、`index-DROpo0xI.js`。
- 生产状态：已于 2026-08-15 部署，build ID `66e114efc14c`（`deployed_at 20260815-092052`），备份 `/var/backups/family-proxy/20260815-092052`，`verify-server.sh` 通过。部署入口已恢复（`codexops` 的 `sudo -n` 可用），但 `90-codexops-nopasswd` 授予 `(ALL : ALL) NOPASSWD: ALL` 的宽泛权限，超出 `deploy-family-proxy-ui` 最小授权，建议后续收窄并复核最终 sudoers。

## 15. 2026-08-15 全方位审计与优化（历史基线）

以下为一次全面审计、代码优化与线上部署的历史交接基线。相关改动已部署到 Z4Pro 生产（build `66e114efc14c`）进行验证；当前有效规则和 APNs 处理以第 17 节为准。

### 审计结论

- 仓库 `main` = `origin/main`（HEAD `35ec047`），工作区干净，无冲突标记，无已提交密钥。
- 版本一致：`VERSION`=0.11.12 == `BUILD_VERSION` == `frontend/package.json`；46 项 Python 回归通过；前端 `typecheck`+`build` 通过。
- 前端↔后端 `/api/*` 契约无孤儿端点；界面未发现新的功能性 bug。

### 已部署到 Z4Pro 的改动（来自 PR #87，生产已生效）

- 部署了已提交未部署的「总览活动连接卡片→流量观察」跳转修复（生产 build `a222bd633fee` → `66e114efc14c`，前端 `index-DROpo0xI.js`/`index-DVmGmsAE.css`）。
- 同步了代码仓库优化（历史 PR #87）：异常静默改日志、NO_PROXY/接口硬编码改配置、nanoid 升级；APNs 直连模板方案已由第 17 节的 Mihomo 代理方案取代。

### 历史 PR #87 内容

- A1 的整段 `family_apple_direct` + `Apple APNs direct` 方案已作废；当前模板清理该旧对象，详见第 17 节。
- A2 `frontend/package-lock.json` 根版本对齐 0.11.12。
- A3 `runtime/family-mihomo-sub-import.py` 两处 `except Exception: pass` 改为记录 stderr。
- A4 `runtime/mosdns/updater.py` NO_PROXY 改读 `FAMILY_MOSDNS_LAN_CIDR`。
- A4b `scripts/family-mihomo-tproxy-auto` `oifname kvmbr0` 改读 `FAMILY_CAPTURE_INTERFACE`。
- nanoid 3.3.17→3.3.18（修复高危 GHSA-2v37-7h3g-55p8，`dist` 不变）。

### 已清理

- 本地分支 `codex/rule-set-source-type-fix` + 远程 8 个未合并陈旧分支（`agent/apple-apns-direct`、`agent/apple-ui-release-011`、`agent/auto-failover-warning`、`agent/dns-race-overview`、`agent/legacy-wireguard-maintenance`、`agent/release-0.11.10`、`codex/rule-set-source-type-fix`、`fix/network-overview-pulse`）。

### 遗留观察项（待处理）

- `/usr/local/sbin/deploy-family-proxy-ui` 仍是旧版（缺 rules.html 备份/安装逻辑）；本次用源目录 `/home/codexops/family-proxy-manual/scripts/deploy-family-proxy-ui` 完成部署。后续应把当前版同步到 `/usr/local/sbin/`。
- `90-codexops-nopasswd` 的 `NOPASSWD: ALL` 过宽，建议收窄为最小 `deploy-family-proxy-ui` 入口并复核 sudoers。
- `FAMILY_MOSDNS_LAN_CIDR` 目前仅 `updater.py` 内部可覆盖，未接 systemd/安装脚本渲染。

### 当前状态

- 本次授权后的 APNs 规则、RouterOS 模板、UI 预设和交接记录已在当前提交合并到 `main`；历史 PR 分支不再作为 APNs 方案来源。

## 16. 2026-08-15 MosDNS-T 更新源修正（已部署）

- 现象：维护页将运行中的第三方 `jasonxtt/mosdns-t:latest`（核心版本可能显示 `0.7.1`）与官方 `IrineSistiana/mosdns` 的 `5.x` Release 混在同一版本信息中，造成错误的跨项目更新提示。
- 修复：`runtime/mosdns/updater.py` 改读 `jasonxtt/mosdns` Tags（只接受 `vX.Y.Z` 主项目标签）；实际是否可升级仍只由第三方 Docker 镜像 digest 比对决定。维护页和 release 弹窗均标记为 MosDNS-T 第三方项目，并链接其 Tags。
- 版本边界：MosDNS-T 版本不得与官方 MosDNS 版本比较；第三方 Tags、`jasonxtt/mosdns-t:latest` digest 和运行时健康检查是三类不同证据。
- 生产部署：Family Proxy 控制平面 build `ff6c82982fd9`（`deployed_at 20260815-110916`），备份目录为 `/var/backups/family-proxy/20260815-110916`；独立 MosDNS 管理服务最后一次备份为 `/var/backups/family-proxy/20260815-111257/mosdns-management`。
- 部署验证：本地 52 项 Python 测试、编译和 `git diff --check` 通过；Z4Pro `verify-server.sh` 通过；MosDNS 管理 API、维护页面、`family-mosdns-updater`、Family Proxy 两个服务和 `mosdns-t`/管理 UI 容器均已核验。`mosdns-t` 核心未重建，RouterOS、DHCP DNS、53 端口和当前上游配置未修改。

## 17. 2026-08-15 Telegram 后台推送 APNs 旁路修复（已授权落地）

本节是当前 APNs/TG 推送路径的有效基线，覆盖第 15 节中“整段 `17.0.0.0/8` Apple APNs 直连模板”的历史描述；后续不得按旧模板重新添加该 RouterOS 直连绕过。

### 现象与根因证据

- 受管 iPhone `192.168.2.189` 在局域网后台收不到 Telegram 推送，5G 正常；Telegram 前台收发正常。`TG-Auto` 用户流量与 `TG-Notify` 系统通知流量必须继续分离。
- Surge 配置 `/Users/liulei/Library/Mobile Documents/iCloud~com~nssurge~inc/Documents/iPhone-Flowr-Ponte.conf` 将 `push.apple.com` 和 `Apple_APNs.list` 送入代理；旁路运行时此前却有 RouterOS `family-mihomo-shared Apple APNs direct` 规则，目标表为整个 `17.0.0.0/8`，因此 Mihomo APNs 规则命中为 0。
- 生产 APNs 来源已确认是 `behavior=classical`、`format=text`，包含 `push.apple.com`、APNs IPv4/IPv6 fallback；问题不是 MRS 格式，而是 RouterOS 前置直连与运行时错误策略 `AI-Auto`。

### 备份与实际变更

- RouterOS 通过现有受限 API 成功生成二进制备份 `family-proxy-prechange-20260815-0324.backup`（约 1.7 MB）；`/export hide-sensitive` 仍返回 `not enough permissions (9)`，没有声称存在文本导出。
- Z4Pro 规则状态、Mihomo 配置和 APNs 来源备份在 `/var/backups/family-proxy/20260815-0324-telegram-apns/`，未包含在仓库。
- 将 `/etc/family-proxy-ui/rule-sets.json` 的 `apple-push` 出口从 `AI-Auto` 改为 `Proxy-Auto`，使用现有 `--apply-current` 重生成并重启校验 Mihomo。
- 删除 RouterOS 的旧 `family-mihomo-shared Apple APNs direct` 规则、`family_apple_direct` 的 `17.0.0.0/8` 条目和本次 A/B 临时地址表；`192.168.2.189` 仍保留在 `family_mihomo_devices`。
- 代码新增 Apple APNs 预设（`classical + text + Proxy-Auto`），RouterOS `02-prepare-controller.rsc` 会清理旧整段 `17/8` 直连对象，TG-Auto/TG-Notify 规则未改动。

### 验证结果

- RouterOS：APNs 直连规则数量 `0`、`family_apple_direct` 的 `17/8` 条目数量 `0`、`.189` 纳管成员仍为 `1`。
- Mihomo：`.189 -> 17.188.178.173:5223` 命中 `family-apple-push-apple-apns-1`，出口为 `Proxy-Auto`；采样时下行/上行计数持续增长，APNs RuleSet 命中数从 `0` 增长到 `4`。
- 同时观察到 `.189` 的 Telegram DC 连接继续命中 `TG-Auto`；`TG-Notify` 没有被并入用户 Telegram 路径。`family-mihomo-tproxy-auto` 和 `family-mihomo-sub-import` 均为 active。
- 本地隔离 Python 环境完整回归 `54 tests OK`；Python 编译、旧版规则页 JavaScript 语法和 `git diff --check` 通过。前端在临时本机依赖目录完成 `vue-tsc` 与 Vite build；NAS 挂载下的 `npm ci` 曾出现 `TAR_ENTRY_ERROR EIO`，未将其当作代码失败。
- 尚未取得用户对“后台实际弹出一条 Telegram 通知”的最终可见确认；APNs 网络/策略路径已证实，显示层仍需用户用另一账号在 Telegram 后台时发送新消息复测。

### 回滚

- RouterOS 即时回滚：恢复 `family_apple_direct` 的 `17.0.0.0/8` 地址条目，并恢复 `family-mihomo-shared Apple APNs direct` 规则的 `src-address-list=family_mihomo_devices`、`dst-address-list=family_apple_direct`；必要时使用本次二进制备份恢复。
- Z4Pro 规则回滚：恢复 `/var/backups/family-proxy/20260815-0324-telegram-apns/rule-sets.json`，再执行 `sudo /usr/bin/python3 /opt/family-proxy-ui/family-mihomo-sub-import.py --apply-current`。
- 回滚后必须重新核对 RouterOS 规则、Mihomo RuleSet 命中、TPROXY 计数和真实 iPhone 后台通知，不以服务 active 代替业务验证。

## 18. 2026-08-15 v0.11.13 发布记录

- 版本统一为 `0.11.13`：`VERSION`、`frontend/package.json`、`frontend/package-lock.json` 根包、`BUILD_VERSION` 和新版侧栏回退值保持一致。
- 本版本包含 Apple APNs `classical + text + Proxy-Auto` 预设、RouterOS 旧 APNs 直连对象清理、网关登录会话修复和对应回归测试。
- Z4Pro 已部署并验证：无 Cookie 的 RouterOS 请求仍返回健康探针；带登录会话的同一来源返回管理 HTML。部署备份为 `/var/backups/family-proxy/20260815-120828`，四个控制面服务均 active。
- 本地隔离依赖环境完整回归为 `55 tests OK`；前端发布前需完成 `vue-tsc`、Vite build 和 `scripts/verify-release.sh`。
- GitHub Release 地址：`https://github.com/liuleisail/family-proxy-manual/releases/tag/v0.11.13`。

## 19. 2026-08-16 MosDNS 升级失败修复与当前部署状态

### 当前生产状态（2026-08-16 部署后）

- 控制平面 build：`6b772844bd64`（v0.11.13，`deployed_at 20260816-133525`），备份 `/var/backups/family-proxy/20260816-133525`；`family-proxy-ui`/`family-proxy-gateway`/`family-mosdns-updater`/`family-mihomo-sub-import` 均 active。
- MosDNS updater 已部署修复版（备份 `/var/backups/family-proxy/mosdns-updater-20260816-133533`，`py_compile` 通过，服务 active）。
- MosDNS 核心仍运行旧 digest `3ac037…`（v0.7.1），`phase=available`，新镜像 digest `26d792…`（v0.7.3）待受控升级验证；**未自动重试真实升级**。

### 升级失败根因与修复（代码在 PR #88，分支 agent/fix-mosdns-upgrade）

- 根因：镜像拉取在现有代理下超过 updater 原 600s 超时 → 自动回退；失败细节被后续自动检查覆盖。
- 修复：拉取超时 1800s（`FAMILY_MOSDNS_IMAGE_PULL_TIMEOUT`）＋重试 2 次；`set_status` 保留 `last_failure`；DNS 验证 UDP→TCP 退避；`wait_healthy` 180s；旧版维护页与新控制台均显示 `last_failure` 并延长轮询（新版 `applyMosdns` 每 5s 最长 35 分钟）。
- 57 项 Python 回归通过；`vue-tsc`+`vite build` 通过。
- **已部署到 Z4Pro，但代码尚未合并 main**（PR #88 OPEN）；同时 PR #87（全方位审计优化，分支 agent/audit-and-optimization）也仍 OPEN 未合并。合并前以各自分支/PR 为准。

### 待办

- 用户确认代理拉取链路正常后，发起一次受控 MosDNS 升级验证（页面应显示进度与结果；失败会保留 `last_failure` 原因）。成功后再合并 PR #88 与 #87。
- 若再次失败：读 `/opt/family-mosdns-updater` 的 status.json（`last_failure`）、`journalctl -u family-mosdns-updater`、Docker 事件与拉取进度；判断是否仍是代理下载阻塞，必要时提高 `FAMILY_MOSDNS_IMAGE_PULL_TIMEOUT`。
