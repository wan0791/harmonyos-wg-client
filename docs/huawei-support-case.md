# Case: VpnConfig.routes 在 API 23 上不生效（续）

## 新问题：trustedApplications 白名单能否变相实现全局代理？

`VpnConfig.routes` 在 API 23 已验证 6 种组合全部无效。但我们注意到 `VpnConfig` 还有 `trustedApplications` 字段。

**问题 1**：如果把设备上所有已安装应用的包名都填入 `trustedApplications`，是否等价于全局路由？还是说即使填了白名单，没有 `routes` 时流量仍然不走 TUN？

**问题 2**：`trustedApplications` 和 `routes` 的关系是什么——
- 是 `routes` 指定哪些 IP 段走 VPN，`trustedApplications` 指定哪些应用的流量受 `routes` 影响？
- 还是 `trustedApplications` 本身就能决定哪些应用流量进 TUN，`routes` 只是进一步过滤 IP？

**问题 3**：如果 HarmonyOS 的 VPN 设计有意不鼓励全局路由（类比 iOS 的 per-app VPN 模式），那对于纯代理类应用（如 WireGuard 客户端），官方推荐的产品形态是什么？用户期望的是"打开 VPN 后所有流量走隧道"，这个需求在 HarmonyOS 上应该如何正确实现？

## 环境

- SDK: HarmonyOS 6.1.0 (API 23)
- 设备: Mate 70 Pro (6.1.0.170)
- 场景: VpnExtensionAbility（`:vpn` 子进程）
- 项目: WireGuard VPN 客户端开源项目

## 期望

获得 `trustedApplications` + `routes` 协同工作机制的明确说明，以及实现全局代理的官方推荐方案。
