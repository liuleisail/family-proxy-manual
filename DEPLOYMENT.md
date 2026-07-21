# 服务器部署、升级与恢复

本项目提供的是可重复部署的**家庭旁路控制平面**。它不会在安装时自动添加任何 RouterOS 策略路由、DNS 劫持、订阅链接或接管设备。完成服务健康检查后，才在网页或 RouterOS 模板中选择单个设备。

## 0. 前置条件

- Debian/Ubuntu 或兼容 `systemd` 的主机，已安装 Docker Engine 与 Docker Compose 插件。Debian/Ubuntu 安装器会按需补齐 `python3-yaml` 和 `lm-sensors`；其它发行版需自行安装，缺少 `lm-sensors` 时仅温度卡片不可用。
- 旁路主机有固定 IPv4 地址，并与 RouterOS 位于同一 LAN。
- RouterOS API 已仅向旁路主机开放；不得把 API 暴露到 WAN。
- 旁路主机的 SSD 路径可用于 `/var/lib/family-proxy/docker`，或在配置中改成另一个持久目录。
- 先确认当前家庭没有让同一设备同时进入 Surge 和 Mihomo 两套代理平面。

## 1. 获取项目与填写私密配置

```bash
git clone https://github.com/liuleisail/family-proxy-manual.git
cd family-proxy-manual
sudo install -d -m 700 /etc/family-proxy-ui
sudo install -m 600 config/router.env.example /etc/family-proxy-ui/router.env
sudoedit /etc/family-proxy-ui/router.env
```

只填写 `router.env` 内的 LAN、旁路主机、RouterOS API 用户/密码及管理页用户名/密码。首次运行安装器会把 `UI_PASSWORD` 转为 PBKDF2 哈希并从文件中删除。该文件、网关会话密钥和节点/订阅文件均不在 Git 中。

现有 DNS 仪表盘若启用了 Basic Auth，再把 `username:password` 的 Base64 结果填入 `DNS_UPSTREAM_AUTH_B64`：

```bash
printf '%s' 'dns_username:dns_password' | base64
```

该值只保存在权限为 `600` 的 `router.env` 中。统一入口通过 `/dns/` 代为认证，浏览器不会再出现第二套认证框。

## 2. 安装控制平面

```bash
sudo ./scripts/install-server.sh
```

首次安装不会启动服务。脚本会保存旧版文件到 `/var/backups/family-proxy/<时间戳>/`，渲染运行程序、检查 Python 语法、安装 systemd 单元并启用开机启动。`FAMILY_DOCKER_ROOT` 必须指向服务器可持续访问的数据目录；Z4Pro 状态页会以该目录统计 Docker 盘容量。

安装器还会使用本地直连从 APNIC 官方数据源生成 `/etc/family-proxy-ui/cn-ipv4.txt`，并启用每周更新计时器。该列表用于让受管设备的中国 IPv4 流量在旁路主机直接转发和 SNAT；只有列表外流量进入 Mihomo TPROXY。手动更新命令为：

```bash
sudo /usr/local/sbin/refresh-family-cn-ipv4
```

## 3. 创建 Mihomo 容器

确认当前没有名为 `family-mihomo-fallback` 的容器后执行：

```bash
sudo ./scripts/install-mihomo-container.sh
sudo ./scripts/install-server.sh --start
sudo ./scripts/verify-server.sh
```

安装器不会替换同名容器。首次启动的 Mihomo 只有直连基线配置；在管理页导入至少一个原生订阅后，系统才会生成候选池和业务 fallback 策略。

DNS 必须由本机现有的 MosDNS/DNS 服务监听旁路主机的 `53` 端口。该项目不自动覆盖 DNS 容器，因为错误地占用 `53` 端口会影响全屋解析。完成 DNS 对接后，管理页的 DNS 健康项才会变为正常。

## 4. RouterOS 操作

在 RouterOS 终端依次导入：

```routeros
/import file-name=01-preflight-and-backup.rsc
/import file-name=02-prepare-controller.rsc
```

文件位于本项目的 `routeros/` 目录。导入前替换其中的示例 IP。然后配置 API 用户和来源限制，并在管理页完成设备加入；RouterOS 手工接管模板仅用于管理页不可用时。详细顺序见 [routeros/README.md](routeros/README.md)。

## 5. 订阅与候选池

1. 在局域网管理页导入主力/备用机场的原生 HTTPS 订阅。
2. 手工执行一次“全量稳定性测速”，让系统生成待生效建议。
3. 建议仅保留连续三次成功的节点；每池 4 至 5 个，主力优先、备用后置。AI 使用 JP/SG/US 与“其他-AI”池，后者收录台湾、韩国等非港节点。
4. 点击“复测并生效”；系统只复测建议节点，配置校验和运行验证通过后才更新 fallback。随后检查当前节点和切换历史。
5. 最后才加入一个测试设备。国内 App、局域网服务和外网服务均通过后，再加入下一台。

订阅拉取保持直连，不经代理、Fake-IP 或第三方转换器；链接不会持久保存在页面中。

## 6. 升级与回退

升级：

```bash
git pull --ff-only
sudo ./scripts/upgrade-server.sh
```

升级脚本会先建立时间戳备份，然后更新并重启 `family-proxy-ui`、`family-mihomo-sub-import` 和 `family-proxy-gateway`。它不会重启 Mihomo/MosDNS 容器、启动历史停用容器或写入 RouterOS。新版网关兼容 Safari 缓存的旧 DNS 页面，升级后无需清空 DNS 数据。

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
- DNS“概览”和“数据管理”的重新载入均成功；来自旧 DNS 页面的无前缀 API 也能经统一入口兼容转发。
- 接管测试设备在国内 App、局域网服务和外网业务上都通过；未接管设备保持原样。
- RouterOS 文本导出、二进制备份和本次服务器备份均可定位。

RouterOS 的命令设计遵循其 [Packet Flow](https://help.mikrotik.com/docs/spaces/ROS/pages/328227/Packet+Flow+in+RouterOS)、[Connection Tracking](https://help.mikrotik.com/docs/spaces/ROS/pages/130220087/Connection+tracking) 与 [Netwatch](https://help.mikrotik.com/docs/spaces/ROS/pages/8323208/Netwatch) 文档：IPv4 策略路由、DNS 和 FastTrack 排除使用共享地址列表，设备增减仍保持单设备事务与独立 IPv6 防漏。
