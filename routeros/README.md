# RouterOS 手工操作

这些脚本对应控制器的共享 IPv4 策略和每设备 IPv6 防漏对象。每次变更只能选择一种方式：管理页面，或本目录的手工模板。不要对同一设备混用两种方式。

执行顺序：

1. 导入 `01-preflight-and-backup.rsc`，下载文本导出和二进制备份。
2. 在旁路主机生成 RouterOS 中国 IPv4 地址表并导入路由器：

```bash
python3 scripts/render-routeros-cn-list.py /etc/family-proxy-ui/cn-ipv4.txt family-cn-ipv4.rsc
scp family-cn-ipv4.rsc <router-user>@<router-ip>:
```

然后在 RouterOS 执行 `/import file-name=family-cn-ipv4.rsc`，确认 `/ip firewall address-list print count-only where list="family_cn_ipv4"` 大于 1000。地址表只需在列表更新后重新生成和导入，不包含任何账号或订阅信息。

3. 在 `02-prepare-controller.rsc` 填写 LAN 网段和旁路主机 IP，导入脚本。脚本会在连接打标前依次加入局域网、IPv4 多播、Apple Push `17.0.0.0/8` 和国内目的地址直连规则。国内流量因此不会经过 `RouterOS -> Z4Pro -> RouterOS` 的额外往返；mDNS/IGMP 等 HomeKit 发现流量不会被送进 Mihomo；Apple Push 也不再依赖 Z4Pro、Mihomo 或机场节点。Telegram 消息正文仍由 Telegram 策略组代理，只有 iPhone/iPad 的 APNs 推送通道直连。
4. 在 RouterOS 中确认 API 服务只允许旁路主机访问。创建最小权限 API 用户前，先检查当前用户组策略和输入链顺序。
   如果已经存在名为 `family-mihomo-tproxy-health` 的 Netwatch，
   将其 HTTP 探针端口设为专用健康端口，避免把经 WireGuard
   SNAT 后的远程管理访问误判成路由器探针：

```routeros
/tool netwatch set [find where name="family-mihomo-tproxy-health"] port=18087
```

   `18088` 只用于交互式管理页面，`18087` 只用于 RouterOS 健康探针。
5. 用管理页面加入设备；仅当页面不可用时，才填写并导入 `03-enable-device-template.rsc`。
6. 在旁路主机将同一 IP 写入 `/etc/family-proxy-ui/managed-ips` 后运行：

```bash
sudo /usr/local/sbin/family-mihomo-tproxy-auto sync
sudo systemctl status family-mihomo-tproxy-auto
```

7. 验证国内应用、局域网服务和外网策略。异常时先运行 `99-remove-device-template.rsc`，再在旁路主机删除对应 IP 并重新同步 TPROXY。

共享策略会把接管设备的普通 TCP/UDP 53 重定向到旁路 DNS，并在 FastTrack 排除规则之前阻断这些设备访问局域网以外的 TCP/UDP 853。TCP 使用 reset 促使客户端快速回退，UDP 使用 drop；HTTPS 443 不做全局封锁，避免误伤正常网站。DoH、HTTPDNS 和应用内置解析仍需在 DNS 服务侧用经过验证的小型规则处理。

Apple Push 规则使用 `family_apple_direct` 地址表，默认仅包含 Apple 官方公布的 `17.0.0.0/8`。它只匹配 `family_mihomo_devices` 中的接管设备，并且必须位于连接打标规则之前。手工回滚：

```routeros
/ip firewall mangle remove [find where comment="family-mihomo-shared Apple APNs direct"]
/ip firewall address-list remove [find where list="family_apple_direct" and address="17.0.0.0/8"]
```

HomeKit 的 IPv4 多播例外只匹配接管设备发往 `224.0.0.0/4` 的流量，主要覆盖 mDNS 和 IGMP，不会放行普通公网流量。手工回滚：

```routeros
/ip firewall mangle remove [find where comment="family-mihomo-shared multicast direct"]
```

不要执行会全局禁用 FastTrack、重写默认路由、全网 DNS 劫持或直接删除全部 mangle/NAT 的命令。共享规则只匹配 `family_mihomo_devices`，单设备撤出只删除它的地址列表成员和 IPv6 防漏项。
