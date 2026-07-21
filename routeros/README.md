# RouterOS 手工操作

这些脚本对应控制器的共享 IPv4 策略和每设备 IPv6 防漏对象。每次变更只能选择一种方式：管理页面，或本目录的手工模板。不要对同一设备混用两种方式。

执行顺序：

1. 导入 `01-preflight-and-backup.rsc`，下载文本导出和二进制备份。
2. 在 `02-prepare-controller.rsc` 填写 LAN 网段和旁路主机 IP，导入脚本。
3. 在 RouterOS 中确认 API 服务只允许旁路主机访问。创建最小权限 API 用户前，先检查当前用户组策略和输入链顺序。
4. 用管理页面加入设备；仅当页面不可用时，才填写并导入 `03-enable-device-template.rsc`。
5. 在旁路主机将同一 IP 写入 `/etc/family-proxy-ui/managed-ips` 后运行：

```bash
sudo /usr/local/sbin/family-mihomo-tproxy-auto sync
sudo systemctl status family-mihomo-tproxy-auto
```

6. 验证国内应用、局域网服务和外网策略。异常时先运行 `99-remove-device-template.rsc`，再在旁路主机删除对应 IP 并重新同步 TPROXY。

不要执行会全局禁用 FastTrack、重写默认路由、全网 DNS 劫持或直接删除全部 mangle/NAT 的命令。共享规则只匹配 `family_mihomo_devices`，单设备撤出只删除它的地址列表成员和 IPv6 防漏项。
