# Case: VpnConfig.routes 在 API 23 上不生效

## 环境

- SDK: HarmonyOS 6.1.0 (API 23)
- 设备: Mate 70 Pro (6.1.0.170)
- 场景: VpnExtensionAbility（`:vpn` 子进程）
- 项目: WireGuard VPN 客户端开源项目 (GitHub: wan0791/harmonyos-wg-client)

## 核心问题

### 问题 1: VpnConfig.routes 完全不生效

7 种配置组合穷举（含 `trustedApplications` 空数组/具体包名/不设），`/proc/net/route` 始终只有 VPN 子网路由。`fileIo.read(tunFd)` 永远返回 EAGAIN。

### 问题 2: trustedApplications 与 routes 的正确协作方式

AI 答复称两者必须配合才生效。实测填入 `['com.huawei.hmos.browser']` + `routes: [0.0.0.0/0]`，路由表无变化，浏览器流量不走 TUN。

### 问题 3: IP 层完全不通

不仅外网不通，**VPN 子网（10.8.0.0/24）也不通**。手机浏览器无法访问 `10.8.0.1:9090`。WG Transport 层正常（keepalive 双向），但 TUN 层不工作——`fileIo.read` 永远返回 EAGAIN。

### 问题 4: 官方推荐产品形态

AI 建议 Per-App VPN + 用户授权模式。但 WireGuard 的设计是全隧道代理——每个 App 都需走隧道。请问 HarmonyOS 上对此类应用的正确实现路径是什么？

## 已排除的原因（完整列表）

- ❌ DNS 冲突
- ❌ IPv6 冲突
- ❌ trustedApplications 缺失
- ❌ interface 命名（`vpn-tun` vs 空字符串）
- ❌ 路由格式（`0.0.0.0/0` vs `0.0.0.0/1 + 128.0.0.0/1`）
- ❌ 连接状态
- ❌ 系统日志（hilog 无 NETMGR 相关错误）

## 已放弃的替代方案

- ❌ DNS 劫持 + 透明代理（TUN 读不到数据，TCP 连接无法建立）
- ❌ SOCKS5 代理（VPN 子网 IP 无法建立 TCP 连接）
- ❌ 参考 IKE VPN（使用 XFRM，不是 TUN 体系）

## 期望

1. `fileIo.read` 在 TUN fd 上的正确使用方式——为何永远 EAGAIN？
2. `VpnConfig.routes` 在 API 23 的实现状态确认
