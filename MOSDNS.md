# MosDNS-T 分流加固

本页适用于 RealIP/Redir-Host 模式的选择性旁路网络。目标是：国内域名交给国内上游，国外域名交给经代理访问的加密上游，同时尽量减少缓存、HTTPDNS 和规则更新造成的错误分流。

## 1. 缓存边界

- 关闭位于分流判断之前的全量缓存（MosDNS-T 中通常是“过期缓存 2”或 `switch13=B`）。
- 保留国内、国外和节点域名各自的独立缓存（通常是“过期缓存 1”或 `switch4=A`）。
- DDNS、Apple Push、OCSP 等更新频繁的域名不要使用长期乐观缓存。
- 规则更新成功后清空所有 DNS 缓存，再运行方向回归；更新失败时恢复规则备份。

这样仍可获得热查询缓存收益，但不会让一个域名在改为另一条解析路径后继续复用旧路径的共享答案。

## 2. 规则优先级

建议保持以下逻辑顺序：

1. 本地强制代理与强制直连规则。
2. 业务专属规则。
3. 在线国内/国外规则。
4. GeoIP 响应校验。
5. 自动学习的直连/代理记录。

不要使用 `keyword:akamai`、`keyword:akadns` 这类覆盖范围过宽的直连规则。Apple 中国服务应使用明确域名；Google、YouTube、OpenAI、Telegram、GitHub 等核心国外服务也应保留少量明确规则。大规则集自动更新时，本地规则不得被覆盖。

## 3. 上游和规则下载

- 国内解析使用本地可达的国内上游。
- 国外解析使用两个独立 DoH 上游，并经 Mihomo/SOCKS 访问；不要在失败时退回国内明文 DNS。
- 机场订阅始终使用本地网络直连拉取，不经过代理、FakeIP 或第三方转换。
- 官方域名/IP 规则使用原始项目的 HTTPS 地址。若代理节点无法访问 GitHub，可本地直连 `raw.githubusercontent.com`，但不得改用来源不明的镜像站。
- 自动更新至少校验规则数量下限、与上一版的数量比例、固定域名的实际标签、实际国内/国外上游和异常/FakeIP 地址；任一项失败即回滚。

### 在管理页编辑上游

安装可选 DNS 管理组件后，“DNS - 概览 - 解析上游”可以分别编辑国内和国外服务器。每行一个地址；需要固定连接 IP 时，在竖线后填写 IP：

```text
udp://223.5.5.5
https://dns.alidns.com/dns-query | 223.5.5.5
h3://dns.alidns.com/dns-query | 223.6.6.6
tls://dns.alidns.com | 223.5.5.5
quic://dns.alidns.com | 223.6.6.6
```

`h3://` 是页面的简写，保存时会转换为 HTTPS 并开启 HTTP/3。DoT、DoH3 和 DoQ 应优先填写证书对应的域名，再用竖线指定连接 IP；直接填写 `tls://223.5.5.5` 等 IP 地址可能因证书名称不匹配而失败。

国外组只接受 DoT、DoH、DoH3 和 DoQ，并强制沿用 Mihomo SOCKS 出口；不会退回明文 UDP/TCP。保存时先备份现有上游，调用 MosDNS-T 热重载，再检查固定国内外域名的实际 `final_upstream`。任一探针失败会恢复旧配置，无需重启 MosDNS 核心。

该编辑器只影响主动使用 Z4Pro MosDNS 的查询，不会修改 RouterOS、DHCP DNS、设备接管名单或增加 DNS 重定向。当前网络若已验证国内应用使用公共 DNS 更稳定，应继续保持这一边界。

## 4. HTTPDNS 和 DoT

MosDNS 无法控制应用直接访问的 HTTPDNS、DoH 或 DoT。推荐分层处理：

- 只有经过单设备验证确有需要时，才对接管设备重定向 TCP/UDP 53；已验证公共 DNS 更稳定的网络不要启用该项。
- 只对接管设备阻断局域网以外的 TCP/UDP 853，并把规则放在该策略的 FastTrack 排除规则之前。
- 不全局封锁 443。
- HTTPDNS 使用本地维护的小型清单，先覆盖实际使用的购物、短视频和通信应用；不要直接启用同时混有 PCDN、广告和遥测域名的大型清单。
- 启用后必须验证淘宝、京东、拼多多、抖音、微信及未接管设备；出现兼容问题时先停用 HTTPDNS 清单，不动基础分流规则。

仓库提供了一个不含账户信息的起始清单：[config/httpdns.rules.example](config/httpdns.rules.example)。把它复制到 MosDNS 的持久化目录，通过仅容器网络可访问的本地 HTTP 地址交给 AdGuard 规则插件加载，关闭在线自动更新；不要把临时外部订阅地址直接写入运行配置。

## 5. 验证和回滚

每次修改前保存 MosDNS 目录、容器检查结果、审计日志，以及 RouterOS 文本导出和二进制备份。至少验证：

```bash
sudo scripts/verify-dns-routing.sh /etc/family-proxy-ui/router.env
```

预期结果：国内探针的 `final_upstream` 为 `domestic`，国外探针为 `foreign`，返回地址不在 `198.18.0.0/15`、私网、回环或链路本地网段。若失败，恢复本次 MosDNS 备份并删除 RouterOS 中本次新增且带明确注释的规则。
