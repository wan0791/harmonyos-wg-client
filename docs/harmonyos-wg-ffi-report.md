# 鸿蒙 WireGuard VPN 客户端 — 开发进度 & 问题报告

**日期**: 2026-06-11
**SDK**: HarmonyOS API 23 (6.1.0.170)
**设备**: Mate 60 / 6.1.0

---

## 一、架构

```
┌─ VPN 进程 (:vpn) ─────────────────────────────────┐
│  TUN read → encrypt → 127.0.0.1:relay → loopback    │
│  TUN write ← decrypt ← 127.0.0.1:vpnExt ← loopback  │
└──────────────────────────────────────────────────────┘
         loopback UDP (不受 TUN 影响)
┌─ 主进程 (EntryAbility) ─────────────────────────────┐
│  UdpRelay → NAPI C socket → WG 服务器 (公网)        │
│  UdpRelay ← pthread + TSFN 收包 ← WG 服务器         │
└──────────────────────────────────────────────────────┘
```

**为什么用主进程 NAPI socket**：
- `protectProcessNet()` 在 API 23 不生效
- `requireNapi` 在 `:vpn` 进程中报 error 2147483647
- 主进程不受 TUN 路由影响 → NAPI socket 天然绕过 VPN

## 二、已完成 ✅

| 模块 | 状态 | 说明 |
|------|------|------|
| Noise IKpsk2 握手 | ✅ | HMAC-BLAKE2s KDF, BLAKE2s-128 MAC1, 服务器握手成功 |
| Transport 加解密 | ✅ | ChaCha20Poly1305, counter/nonce 格式与 wireguard-go 一致 |
| NAPI 原生 UDP socket | ✅ | CMake 编译, 主进程 pthread 收包 + TSFN 回调 |
| Loopback 中继 | ✅ | UdpRelay 转发 VPN ↔ NAPI socket（无 TCPSocket/socat） |
| Keepalive | ✅ | 每 10 秒发送, 双向 Transport 流通 |
| 诊断面板 | ✅ | 实时显示 NAPI fd + 传输字节数 |

## 三、已验证的确认事实

1. **WG 握手成功**: 服务器 dmesg 确认 `Sending handshake response to peer 32`
2. **双向 Transport**: 服务器 `wg show` 显示 `transfer: X KiB received, Y KiB sent`
3. **TUN 源 IP 问题**: 抓包证实 TUN 捕获的 IP 包 src=172.16.8.40（WiFi IP）
4. **SNAT 必须**: 不改源 IP 则服务器报 `Packet has unallowed src IP (172.16.8.40)`
5. **IPv6 必须过滤**: 否则服务器报 `Packet has unallowed src IP (::)`（全零 IPv6）
6. **SNAT + TCP/UDP checksum 修正后**: 服务器不再报 unallowed，WG 层接受

## 四、当前阻塞 🛑

### **阻塞 #1: VpnConfig.routes 不生效（核心问题）**

**现象**:
- 在 `VpnConfig` 中设置 `routes: [0.0.0.0/1, 128.0.0.0/1]` 后，手机 `/proc/net/route` 中**没有任何新增路由**
- 路由表中只有 VPN 子网路由（10.8.0.0/24 via vpn-tun）
- TUN read 永远返回 EAGAIN（无数据），因为流量不走 TUN

**代码**:
```typescript
const config: vpnExtension.VpnConfig = {
  addresses: [{ address: { address: '10.8.0.9', family: 1 }, prefixLength: 24 }],
  routes: [
    {
      interface: '',  // 尝试过 '', 'vpn-tun'
      destination: {
        address: { address: '0.0.0.0', family: 1 },
        prefixLength: 1,
      },
      gateway: { address: '0.0.0.0', family: 1 },
      hasGateway: false,
      isDefaultRoute: true,
    },
    // 128.0.0.0/1 同理
  ],
  mtu: 1420,
  dnsAddresses: ['114.114.114.114'],
};
```

**问题**:
- `VpnConfig.routes` 在 API 类型声明中存在（`@since 11`，`RouteInfo` 接口完整）
- 但实际调用 `vpnConnection.create(config)` 后系统路由表无变化
- `interface` 字段试过 `''` 和 `'vpn-tun'` 均无效
- **无报错**——API 静默忽略

### **阻塞 #2: HarmonyOS TUN 不做源 NAT**

**现象**:
- TUN 捕获到的 IP 包 src = WiFi IP（172.16.8.40），而非 VPN IP（10.8.0.9）
- 服务器 WG AllowedIPs 检查失败 → 丢包
- 已在客户端做 SNAT（重写源 IP → 10.8.0.9）绕过，但这不是标准做法

**对比**: Android 的 VpnService 自动将 TUN 源 IP 设为 VPN IP

### **阻塞 #3: IPv6 全零地址**

**现象**:
- TUN 捕获的 IPv6 包 src = `::`（未指定地址）
- 服务器 WG 拒绝：`Packet has unallowed src IP (::)`
- 已在客户端过滤 IPv6，浏览器需回退到 IPv4（增加连接延迟）

## 五、向华为开发者 AI 的提问

### 问题 1: VpnConfig.routes 如何正确使用？

我在 `VpnExtensionAbility` 中调用 `vpnConnection.create(config)`，`config.routes` 按 `RouteInfo` 类型构造了 `0.0.0.0/1` 和 `128.0.0.0/1` 路由，但系统路由表（`/proc/net/route`）中没有出现。API 返回成功且无错误。

请问：
- `RouteInfo.interface` 字段应该填什么？（试了 `''` 和 `'vpn-tun'`）
- `RouteInfo.gateway` 对于 TUN 类型的路由应该如何设置？
- API 23 上 `routes` 字段是否有已知限制或额外前置条件？

### 问题 2: TUN 流量源 IP 问题

TUN fd 通过 `fileIo.read` 读到的 IP 包源地址是 WiFi 物理 IP（172.16.8.40），而非 VPN 接口地址（10.8.0.9）。Android 的 VpnService 会对此自动做源 NAT。

请问 HarmonyOS VpnExtensionAbility 是否有机制确保 TUN 包源地址为 VPN 接口地址？还是需要应用层自己做 SNAT？

### 问题 3: IPv6 路由

VpnConfig 中只设置了 IPv4 addresses，未设 IPv6。但 TUN 仍能读到 IPv6 包（src=::, dst=合法 IPv6 地址）。这些包是否应该被路由到 TUN？

如果需要支持 IPv6 全局路由，VpnConfig 应该如何配置？

### 问题 4: fileIo.read 在 TUN fd 上的行为

在 TUN fd 上使用 `fileIo.read()` 读取时，无数据情况下会抛出异常（而非返回 0），导致 `:vpn` 进程每 50ms 触发一次异常。这在生产环境造成大量日志噪音：

```
E C04388/...:vpn/file_api: [prop_n_exporter.cpp:612->ReadExec] Failed to read file for -11
W C01320/...:vpn/JsEnv: [source_map.cpp145] the stack without line info
```

是否有更高效的方式在 ArkTS 中监听 TUN fd 的数据到达事件？（类似 select/poll/epoll）

---

## 六、华为开发者 AI 回复 & 验证结果

### 建议 1: `trustedApplications: []` 
- 尝试设置 `trustedApplications: []`（空数组 = 所有应用）
- **验证结果**: ❌ 无效，路由仍未出现在系统路由表

### 建议 2: `interface: 'vpn-tun'` + 单条 `0.0.0.0/0`
- 改为单一完整默认路由，`interface` 填 `'vpn-tun'`
- **验证结果**: ❌ 无效，路由表无变化

### 建议 3: `isIPv6Accepted: false`
- 显式禁用 IPv6
- **验证结果**: 无法实测（路由未生效，无流量经过 TUN），但设置本身可能有用

### 结论
`VpnConfig.routes` 在 HarmonyOS 6.1 API 23 上**完全不生效**——无论 `trustedApplications`、`interface`、路由格式如何设置，系统路由表 (`/proc/net/route`) 均无变化。此问题需华为官方确认 `routes` 字段在 API 23 上的实现状态。

## 七、服务器端已确认正常

- IP 转发: `net.ipv4.ip_forward = 1`
- NAT: `iptables-legacy MASQUERADE 10.8.0.0/24 → eth0`
- FORWARD: nftables 双向 ACCEPT wg0
- 其他 WG peer 正常工作（10.8.0.6/8 有大量流量）
