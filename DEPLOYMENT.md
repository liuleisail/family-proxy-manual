# 服务器部署、升级与恢复

本项目提供的是可重复部署的**家庭旁路控制平面**。它不会在安装时自动添加任何 RouterOS 策略路由、DNS 劫持、订阅链接或接管设备。完成服务健康检查后，才在网页或 RouterOS 模板中选择单个设备。

## 0. 前置条件

- Debian/Ubuntu 或兼容 `systemd` 的主机，已安装 Docker Engine 与 Docker Compose 插件。Debian/Ubuntu 安装器会按需补齐 `python3-yaml`、`lm-sensors`、`tcpdump` 和 `util-linux`；其它发行版需自行安装。缺少 `lm-sensors` 时仅温度卡片不可用，缺少后两项则不能使用设备抓包诊断。
- 旁路主机有固定 IPv4 地址，并接入家庭 LAN。若选择 RouterOS 集成，RouterOS API 只应向旁路主机开放，不得暴露到 WAN。
- 旁路主机的 SSD 路径可用于 `/var/lib/family-proxy/docker`，或在配置中改成另一个持久目录。
- 先确认当前家庭没有让同一设备同时进入 Surge 和 Mihomo 两套代理平面。

## 1. 获取项目与填写私密配置

### 交互式首次安装（推荐）

对于满足前置条件、尚未部署本项目的新服务器，最短流程如下：

```bash
git clone https://github.com/liuleisail/family-proxy-manual.git
cd family-proxy-manual
sudo ./scripts/bootstrap-interactive.sh
```

引导脚本会询问 LAN、旁路主机 IP、LAN 桥接口、SSD 数据目录、路由集成模式、可选 RouterOS API 与管理页凭据，生成仅本机可读的 `router.env`，然后执行控制平面安装、基础 Mihomo 容器创建、服务启动及 `verify-server.sh`。自动模式会在凭据齐全时验证 RouterOS API；没有 RouterOS 时应选择独立旁路。它拒绝覆盖已有 `router.env` 或同名 Mihomo 容器；已有部署请使用升级流程。

如果希望像系统初始设置一样在浏览器中填写敏感配置，可使用一键安装入口：

```bash
sudo ./scripts/install-one-click.sh
```

它先在终端收集 LAN、旁路 IP、接口和持久化目录，随后安装基础服务并打印一次性向导地址。向导只允许 LAN 客户端访问，令牌完成一次提交后立即失效；选择 RouterOS 集成时会先验证 API 登录，选择独立旁路时不会保存或调用 RouterOS 凭据。管理页密码直接转换为 PBKDF2 哈希。完成页面向导后运行 `sudo ./scripts/verify-server.sh` 做完整核查。旧的 `bootstrap-interactive.sh` 仍保留为全量终端安装方式。

该脚本不会自动写 RouterOS、占用 53 端口、覆盖已有 MosDNS、导入订阅或接管客户端。独立旁路安装完成后，维护页只展示本机 Linux、Mihomo 和 MosDNS；设备通过 `7890` HTTP/SOCKS5 手动代理，或由家庭网关将指定流量送入 `7893`。RouterOS 集成模式才需要按本文第 4 节审阅 RouterOS 模板。

### 手工填写配置

```bash
git clone https://github.com/liuleisail/family-proxy-manual.git
cd family-proxy-manual
sudo install -d -m 700 /etc/family-proxy-ui
sudo install -m 600 config/router.env.example /etc/family-proxy-ui/router.env
sudoedit /etc/family-proxy-ui/router.env
```

只填写 `router.env` 内的 LAN、旁路主机、RouterOS API 用户/密码及管理页用户名/密码。`FAMILY_CAPTURE_INTERFACE` 与 `FAMILY_HOMEKIT_ROUTE_INTERFACE` 应填写承载 LAN 流量的桥接口，Z4Pro 通常为 `kvmbr0`；其它主机先用 `ip -br link` 核实。后者仅用于已在设备页明确选择的 HomeKit 本地视频直连设备，不改客户端默认网关或 DNS。首次运行安装器会把 `UI_PASSWORD` 转为 PBKDF2 哈希并从文件中删除。该文件、网关会话密钥和节点/订阅文件均不在 Git 中。

现有 DNS 仪表盘若启用了 Basic Auth，再把 `username:password` 的 Base64 结果填入 `DNS_UPSTREAM_AUTH_B64`：

```bash
printf '%s' 'dns_username:dns_password' | base64
```

该值只保存在权限为 `600` 的 `router.env` 中。统一入口通过 `/dns/` 代为认证，浏览器不会再出现第二套认证框。

若 MosDNS 审计 API 位于 Docker 网桥而非本机 `127.0.0.1:9099`，把 `MOSDNS_API_URL` 改为实际只在服务器可达的地址；该项仅供命令行完整 DNS 回归读取审计和清理路由缓存，不改变 DNS 查询路径。

## 2. 安装控制平面

```bash
sudo ./scripts/install-server.sh
```

首次安装不会启动服务。脚本会保存旧版文件到 `/var/backups/family-proxy/<时间戳>/`，渲染运行程序、检查 Python 语法、安装 systemd 单元并启用开机启动。`FAMILY_DOCKER_ROOT` 必须指向服务器可持续访问的数据目录；Z4Pro 状态页会以该目录统计 Docker 盘容量。

systemd 会为设备诊断创建 `/run/family-proxy-captures` 内存运行目录。抓包单文件限制 50 MB、总量限制 200 MB、保留 24 小时，重启后自动清空，因此不会持续写入 Docker 数据盘或 M.2。

安装器还会使用本地直连从 APNIC 官方数据源生成 `/etc/family-proxy-ui/cn-ipv4.txt`，并启用每周更新计时器。该列表用于让受管设备的中国 IPv4 流量在旁路主机直接转发和 SNAT；只有列表外流量进入 Mihomo TPROXY。手动更新命令为：

```bash
sudo /usr/local/sbin/refresh-family-cn-ipv4
```

`ROUTER_CN_AUTO_SYNC=true` 会在本地集合成功更新后，同步 RouterOS 中唯一的 `family_cn_ipv4` 地址表。首次启用前先做只读比较：

```bash
sudo /usr/local/sbin/sync-routeros-cn-ipv4 --check
```

脚本拒绝异常数量和超过 20% 的差异，备份位于 `/var/backups/family-proxy/routeros-cn/`，更新过程先加后删并最终对账，失败反向回滚；不操作现有 mangle、NAT、路由表或设备名单。

## 3. 创建 Mihomo 容器

确认当前没有名为 `family-mihomo-fallback` 的容器后执行：

```bash
sudo ./scripts/install-mihomo-container.sh
sudo ./scripts/install-server.sh --start
sudo ./scripts/verify-server.sh
```

安装器不会替换同名容器，也不会覆盖已有的 `config.yaml`、规则或策略状态。首次启动的 Mihomo 只有直连基线配置；在管理页导入一个原生订阅地址后，系统会按节点名称自动生成启动候选池和业务 fallback 策略，导入完成即可使用。后续全量稳定性测速用于优化候选顺序，不是首次使用的前置步骤。

安装器会安装 Mihomo 地理数据库周更新单元，但默认不启用计时器。首次先执行无变更验证：

```bash
sudo /usr/local/sbin/refresh-mihomo-geodata --check
```

它先直连下载 MetaCubeX 官方资产和校验和；国内网络直连失败时仅公开 GEO 文件回退到 `FAMILY_GEODATA_PROXY` 的本机代理，机场订阅仍保持强制直连。在临时目录用当前 Mihomo 内核验证，应用前备份到 `FAMILY_DOCKER_ROOT/family-mihomo-fallback/geodata-backups/`，最多保留三版。只在文件确有变化时重启 Mihomo，失败自动恢复旧文件。检查稳定通过后才设置 `MIHOMO_GEODATA_AUTO_UPDATE=true` 并重新运行安装器；否则保持默认关闭，不影响现有 GEO 文件。

DNS 必须由本机现有的 MosDNS/DNS 服务监听旁路主机的 `53` 端口。该项目不自动覆盖 DNS 容器，因为错误地占用 `53` 端口会影响全屋解析。完成 DNS 对接后，管理页的 DNS 健康项才会变为正常。

### 可选：安装 MosDNS 管理页面

已有兼容的 `family-mosdns-t` compose 目录时，可以部署上游编辑、规则/软件维护与仪表盘：

```bash
sudo scripts/install-mosdns-management.sh \
  --compose-dir /你的持久化目录/family-mosdns-t \
  --dns-server 旁路主机的局域网IP \
  --core-api http://MosDNS容器地址:9099 \
  --socks5 Mihomo容器地址:7890
```

安装器还会部署 `deploy/mosdns-compose.override.yml`，将 `MOSDNS_AUTO_INIT` 设为 `false`。MosDNS-T 的镜像启动时不再远程改写持久化配置；配置变更仍由本项目的管理页面和规则任务负责。该 override 会在安装前随其它 MosDNS 管理文件备份。

脚本先备份仪表盘、维护服务和 `upstream_overrides.json`，然后只重启维护服务并重建 `ui` 服务，以修复 Docker 单文件 bind mount 更换 inode 后可能出现的 `Stale file handle`。它不重启 MosDNS 核心、不改端口 `53`、不修改现有上游、不写 RouterOS，也不增加 DNS 重定向。

打开统一入口的“DNS - 概览 - 解析路径”后，可通过国内或国外卡片右上角的编辑图标编辑服务器。保存时使用 MosDNS-T 热重载，并用国内外固定域名校验实际分流；失败自动恢复旧上游。未主动使用 MosDNS 的设备不受这些设置影响。

## 4. RouterOS 操作

在 RouterOS 终端依次导入：

```routeros
/import file-name=01-preflight-and-backup.rsc
/import file-name=02-prepare-controller.rsc
```

文件位于本项目的 `routeros/` 目录。导入前替换其中的示例 IP。然后配置 API 用户和来源限制，并在管理页完成设备加入；RouterOS 手工接管模板仅用于管理页不可用时。详细顺序见 [routeros/README.md](routeros/README.md)。

## 5. 订阅与候选池

1. 在局域网管理页导入主力/备用机场的原生 HTTPS 订阅；需要更多来源时，点击订阅来源标题右侧的 `+` 按需增加备用机场。
   备用机场可在卡片中删除；若仍被当前候选池引用，先完成候选池切换再删除。
2. 在需要更换来源的业务池中选择机场并点击“锁定机场范围”；这一步只保存待测范围，不改变当前出口。未锁定的业务池保持当前候选，尤其是 YouTube 使用的 `HK-视频` 池。
3. 执行“全量稳定性测速”；系统只对已锁定范围内、符合业务地域规则的节点测速，并为每个池生成连续三次成功的待生效建议。
4. 点击“复测并生效”；系统只复测待生效建议，配置校验和运行验证通过后才更新 fallback。随后检查当前节点和切换历史。
5. 最后才加入一个测试设备。国内 App、局域网服务和外网服务均通过后，再加入下一台。

候选池页面的每个业务池卡片提供“锁定机场范围”：选择已导入的机场后，系统只保存该池的来源约束，不会立即替换候选或重启 Mihomo。全量测速完成后，待生效候选仍需通过“复测并生效”才会提交；没有锁定机场范围的池不会被本次测速改动。

订阅拉取保持直连，不经代理、Fake-IP 或第三方转换器；链接不会持久保存在页面中。

## 6. 升级与回退

升级：

```bash
git pull --ff-only
sudo ./scripts/upgrade-server.sh
```

升级脚本会先建立时间戳备份，然后更新并重启 `family-proxy-ui`、`family-mihomo-sub-import` 和 `family-proxy-gateway`。它不会重启 Mihomo/MosDNS 容器、启动历史停用容器或写入 RouterOS。新版网关兼容 Safari 缓存的旧 DNS 页面，升级后无需清空 DNS 数据。

从开发机发布到 Z4Pro 时，先在仓库根目录执行内容校验和同步，再在 Z4Pro 执行部署。`sync-z4pro-source` 不使用 `--delete`，并会在同步后核对网关源码哈希；部署脚本随后创建时间戳备份、重启控制面并验证 gated health：

```bash
./scripts/sync-z4pro-source
ssh z4pro 'sudo /home/codexops/family-proxy-manual/scripts/deploy-family-proxy-ui'
```

如 SSH 别名或部署源目录不同，可设置 `Z4PRO_SSH_TARGET` 和 `Z4PRO_SOURCE_DIR`。同步完成后应记录部署脚本输出的 `Backup` 路径和 `build-info.json` 的版本/ID，并在浏览器依次打开机场、维护页面验证导航和页面加载。

Mihomo 镜像维护通过管理页“维护”按需执行，不属于上述控制平面升级。检查仓库只读；实际升级会备份当前配置并保留旧镜像标签，且只允许重建 `family-mihomo-fallback`。若配置校验、控制接口或 `Proxy-Auto` 验证失败，脚本会自动回退旧镜像。不要为该功能设置自动计时器。

安装器还会启用 `family-platform-update-check.timer`：每天约 09:15 查询 RouterOS 当前官方通道、Z4Pro 自带极空间升级服务，并对 Mihomo、MosDNS-T 执行只读镜像检查。MosDNS-T 是第三方整合项目，版本信息读取其自身 Tags，不与官方 MosDNS 5.x 版本比较；实际升级仍以 `jasonxtt/mosdns-t:latest` 的镜像 digest 变化为准。该任务只写入维护页状态；Mihomo 的 Alpha、Beta、RC 等预发布镜像不会触发 Telegram，只有正式发布版本才可能推送。它不会升级 RouterOS、ZOS、`apt` 软件包、Docker 镜像或重启设备。

极空间把持久化数据挂载在 `/tmp/zfsv3/...` 时，`family-mihomo-sub-import` 必须保持 `PrivateTmp=false`，否则 systemd 的私有 `/tmp` 会遮住机场文件并让候选池显示为 `0/5`。安装包已内置该设置；`verify-server.sh` 也会比较磁盘候选池与 API 返回数量，发现路径不可见时立即报错。

失败时停止相关服务，从本次时间戳备份恢复 `/opt/family-proxy-ui/`、服务单元和本地配置，再执行：

```bash
sudo systemctl daemon-reload
sudo systemctl restart family-proxy-ui family-mihomo-sub-import family-proxy-gateway
sudo ./scripts/verify-server.sh
```

对单个接管设备的 RouterOS 回滚，使用 `routeros/99-remove-device-template.rsc` 从共享名单撤出，并在旁路主机中删除同一 IP 后同步：

```bash
sudoedit /etc/family-proxy-ui/managed-ips
sudo /usr/local/sbin/family-mihomo-tproxy-auto sync
```

## 7. 验收标准

- 三个控制平面服务均为 `active`，`verify-server.sh` 通过内部网关密钥验证健康、Z4Pro 系统状态和机场状态接口。
- 设备页能显示 CPU、内存、温度、Docker 数据盘、运行/总容器数和系统运行时间；已停止容器保持原状态。
- Mihomo 控制接口可访问，候选池配置可校验并加载。
- DNS 服务确实监听旁路主机 53 端口，国内和代理域名按预期解析。
- DNS“概览”和“数据管理”的重新载入均成功；上游编辑能读取当前配置、拒绝国外明文 DNS；来自旧 DNS 页面的无前缀 API 也能经统一入口兼容转发。
- DNS 快速检查在不清缓存时通过；配置或规则变更后的完整回归能核对国内/国外实际 `final_upstream`。
- `sync-routeros-cn-ipv4 --check` 没有异常数量或大比例漂移；Mihomo GEO 文件通过官方校验和及内核加载验证。
- 接管测试设备在国内 App、局域网服务和外网业务上都通过；未接管设备保持原样。
- RouterOS 文本导出、二进制备份和本次服务器备份均可定位。
- RouterOS 的 `family-mihomo-tproxy-health` 使用统一入口 `18088`；
  必须从 RB5009 执行 `/tool fetch url="http://旁路主机IP:18088/" mode=http output=none`，
  再确认 Netwatch 为 `up`。普通局域网或 WireGuard 客户端打开 `18088` 首页仍应进入登录页，
  不应把浏览器的 `303` 误判为探针失败。
- 统一入口探针使用连续两次成功/失败门槛；gateway、UI、前端构建和 `build-info.json`
  由同一个部署脚本安装，脚本会在服务重启后验证 gated health。
- `build-info.json` 的 ID 是 UI、gateway、前端入口和版本文件的内容指纹，不使用可能带有未提交修改的 Git HEAD 冒充版本。
- 每次 UI 部署会备份 `/opt/family-proxy-ui` 的旧 Python、前端资源、build-info 和运维 helper；失败时保留本次时间戳目录，可恢复后再重启两个控制面服务。

RouterOS 的命令设计遵循其 [Packet Flow](https://help.mikrotik.com/docs/spaces/ROS/pages/328227/Packet+Flow+in+RouterOS)、[Connection Tracking](https://help.mikrotik.com/docs/spaces/ROS/pages/130220087/Connection+tracking) 与 [Netwatch](https://help.mikrotik.com/docs/spaces/ROS/pages/8323208/Netwatch) 文档：IPv4 策略路由、DNS 和 FastTrack 排除使用共享地址列表，设备增减仍保持单设备事务与独立 IPv6 防漏。
