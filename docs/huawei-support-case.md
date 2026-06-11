# Case: VpnConfig.routes 在 API 23 上不生效

## 环境

| 项目 | 值 |
|------|-----|
| SDK | HarmonyOS 6.1.0 (API 23) |
| 设备 | Mate 70 Pro (6.1.0.170) |
| 开发工具 | DevEco Studio, hvigor 6.1.1 |
| 场景 | VpnExtensionAbility（`:vpn` 子进程） |

## 问题描述

调用 `vpnConnection.create(config)` 创建 VPN 时，`VpnConfig.routes` 字段设置的路由不生效——系统路由表（`/proc/net/route`）中没有对应条目。

**结果**：TUN 接口只能捕获 VPN 子网流量（`10.8.0.0/24`），无法代理外网流量实现 VPN 上网。

## 复现步骤

```typescript
const config: vpnExtension.VpnConfig = {
  addresses: [{
    address: { address: '10.8.0.9', family: 1, port: 0 },
    prefixLength: 24,
  }],
  routes: [
    {
      interface: 'vpn-tun',
      destination: {
        address: { address: '0.0.0.0', family: 1, port: 0 },
        prefixLength: 0,
      },
      gateway: { address: '0.0.0.0', family: 1, port: 0 },
      hasGateway: false,
      isDefaultRoute: true,
    },
  ],
  mtu: 1420,
};

this.tunFd = await vpnConnection.create(config);
```

1. 代码执行无报错，`create()` 成功返回 fd
2. 检查手机路由：`cat /proc/net/route`
3. 仅存在 VPN 子网路由（10.8.0.0/24 via vpn-tun），无 `0.0.0.0/0`

## 已穷举的配置组合（全部无效）

| # | routes | trustedApps | dnsAddresses | interface | isIPv6Accepted | 结果 |
|---|--------|------------|-------------|-----------|----------------|------|
| 1 | `0.0.0.0/0` | `[]` | 114.114.114.114 | `vpn-tun` | — | ❌ |
| 2 | `0.0.0.0/0` | `[]` | 114.114.114.114 | `''` | — | ❌ |
| 3 | `0.0.0.0/1 + 128.0.0.0/1` | — | 114.114.114.114 | `''` | — | ❌ |
| 4 | `0.0.0.0/0` | `[]` | —（去掉 DNS） | `vpn-tun` | `false` | ❌ |
| 5 | `0.0.0.0/0` | `[]` | 114.114.114.114 | `vpn-tun` | `false` | ❌ |
| 6 | 不设 routes | — | 114.114.114.114 | — | — | ✅ VPN 子网正常 |

> 注：`trustedApplications: []` 按文档应表示"代理所有应用流量"。每种配置均通过 `vpnConnection.destroy()` + 重新 `create()` + 重启 App 验证。`/proc/net/route` 始终只有 `10.8.0.0/24 → vpn-tun`，从未出现其他路由条目。

## 已排除的原因

- ❌ **DNS 冲突**：去掉 `dnsAddresses` 后路由仍不生效
- ❌ **IPv6 冲突**：显式设置 `isIPv6Accepted: false` 无效
- ❌ **trustedApplications 缺失**：设为空数组 `[]` 无效
- ❌ **interface 命名**：`'vpn-tun'` 与空字符串 `''` 均无效
- ❌ **路由格式**：`0.0.0.0/0` 与 `0.0.0.0/1 + 128.0.0.0/1` 均无效
- ❌ **连接状态**：VPN 成功创建（`create()` 无报错），另一 WG 协议层验证通道健康
- ❌ **系统日志**：hilog 中无 NETMGR / NETSTACK 路由添加失败或忽略的警告

## 附加信息

- `netManager` 模块中不存在运行时添加路由的 API
- 同设备其他 VPN 应用能正常路由全局流量
- Android `VpnService.Builder.addRoute()` 同等配置正常工作
- WG 隧道完整可用（握手、加解密、Transport 双向流通）——仅路由功能阻塞

## 期望

1. API 23 上 `VpnConfig.routes` 的正确使用方式（是否有关键前置条件遗漏）
2. 该字段在 API 23 是否为已知缺陷
3. 如需特定权限或配置，请指出具体要求

## 项目

开源 WireGuard VPN 客户端 `harmonyos-wg-client`  
GitHub: https://github.com/wan0791/harmonyos-wg-client
