# 鸿蒙 WireGuard VPN 客户端 — 开发进度 & 问题报告

**日期**: 2026-06-12
**SDK**: HarmonyOS 6.1.0 (API 23)
**设备**: Mate 70 Pro (6.1.0.170)
**版本**: v0.1.1

---

## 一、已验证可工作的部分 ✅

| 模块 | 状态 | 验证方式 |
|------|------|---------|
| Noise IKpsk2 握手 | ✅ | 服务器 dmesg 确认 `handshake response sent` |
| Transport 加解密 | ✅ | Keepalive 双向流通，服务器 WG transfer 持续增长 |
| NAPI 原生 UDP socket | ✅ | 主进程 pthread + TSFN 收包，UdpRelay 转发正常 |
| Loopback 中继 | ✅ | VpnExt ↔ relay ↔ NAPI ↔ WG 服务器，无 socat/TCPSocket |
| SNAT（源 IP 重写） | ✅ | dmesg 确认无 `unallowed src IP` 错误 |
| IPv6 过滤 | ✅ | dmesg 确认无 `unallowed src IP (::)` 错误 |
| Transport 反重放 | ✅ | v0.1.1 已加入 counter window 检查 |
| CSPRNG 密钥生成 | ✅ | v0.1.1 已替换 Math.random() |
| 相机扫码 | ✅ | @kit.ScanKit startScanForResult 系统原生界面 |
| 配置持久化 | ✅ | Preferences，App 重启后配置保留 |
| 诊断面板 | ✅ | 实时 NAPI fd + Relay Tx/Rx 字节数 |

## 二、已验证不可工作的部分 ❌

### 核心阻塞: IP 层通信完全不工作

**现象**:
1. `VpnConfig.routes` 在 API 23 完全无效——7 种配置组合穷举全部失败
2. `fileIo.read(tunFd)` 永远返回 EAGAIN，即使有流量被路由到 TUN 也读不到
3. 手机浏览器无法访问 VPN 子网（如 `10.8.0.1:9090`），TCP SYN 未到达服务器 wg0
4. WG Transport 层正常（keepalive 双向），但 IP 层不工作

**这意味着**: 不仅是外网不通，**VPN 子网也不通**。之前观察到的"双向通信"仅限于 WG 协议层的 Transport 消息（keepalive 和手动发送的测试包），不包含真实的 TCP/IP 通信。

### `VpnConfig.routes` 穷举记录（7 种组合全失败）

| # | routes | trustedApplications | dnsAddresses | isIPv6Accepted | 结果 |
|---|--------|---------------------|-------------|----------------|------|
| 1 | `0.0.0.0/0` | 未设置 | 114.114.114.114 | 未设置 | ❌ |
| 2 | `0.0.0.0/1 + 128.0.0.0/1` | 未设置 | 114.114.114.114 | 未设置 | ❌ |
| 3 | `0.0.0.0/0` | `[]`（空） | 114.114.114.114 | 未设置 | ❌ |
| 4 | `0.0.0.0/0` | `[]`（空） | 未设置 | 未设置 | ❌ |
| 5 | `0.0.0.0/0` | `[]`（空） | 114.114.114.114 | `false` | ❌ |
| 6 | `0.0.0.0/0` | `['com.huawei.hmos.browser']` | 114.114.114.114 | 未设置 | ❌ |
| 7 | 不设 routes | 未设置 | 114.114.114.114 | 未设置 | ✅ 仅 VPN 子网条目 |

> 路由表始终只有 `10.8.0.0/24 → vpn-tun`，从未出现全局路由。

### `trustedApplications` 测试

AI 说 `trustedApplications` 必须与 `routes` 配合才生效。填入浏览器包名 `com.huawei.hmos.browser` 测试——无效。`/proc/net/route` 仍只有 VPN 子网。

## 三、已放弃的替代方案

### 方案 1: DNS 劫持 + 透明代理
让 `dnsAddresses` 指向 `10.8.0.1`，DNS 解析全部返回 VPN 网关 IP，浏览器连 `10.8.0.1` 走 TUN。但由于 TUN 读不到数据，TCP 连接无法建立——不可行。

### 方案 2: 服务器 SOCKS5 代理
Clash 在服务器监听 `10.8.0.1:7891`（SOCKS5）、`7890`（HTTP）。通过系统 WiFi 代理设置或浏览器直接访问，但由于 TUN 不工作，VPN 子网 IP 无法建立 TCP 连接——不可行。

### 方案 3: 参考系统 IKE VPN
Mate 70 Pro 内置 IKE VPN 使用 `xfrm-vpn1` 接口（IPsec/XFRM 内核框架），与我们的 TUN 体系不同——无法参考。

## 四、conntrack 关键发现

在手动发送 Transport 层测试包时，服务器 conntrack 出现了一次 `10.8.0.9` 的记录：
```
tcp src=10.8.0.9 → dst=49.4.38.205:30859 [UNREPLIED]
```
这证明 **WG 加解密 + SNAT + NAT 整条链路是通的**。问题仅在于 `fileIo.read` 读不到 TUN 数据，导致正常 TCP 流量永远无法进入 WG 隧道。

## 五、当前结论

整个 WG 协议栈（握手 → 加解密 → Transport → SNAT）已在 API 23 上完整验证可工作。唯一阻塞是 HarmonyOS 平台层的 `VpnConfig.routes` 不生效 + `fileIo.read` 在 TUN fd 上永远返回 EAGAIN。

**等待华为 Case 回复或新 API 版本。**
