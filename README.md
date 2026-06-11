# HarmonyOS WireGuard VPN Client

鸿蒙 WireGuard VPN 客户端，基于 HarmonyOS NEXT API 23。

**测试设备**: Mate 70 Pro (6.1.0.170) | **当前版本**: [v0.1.0](https://github.com/wan0791/harmonyos-wg-client/releases/tag/v0.1.0)

## 状态

```
WG 握手: ✅ Noise IKpsk2 完整通过
Transport 加解密: ✅ ChaCha20Poly1305 双向流通
NAPI 原生 Socket: ✅ 主进程直连 WG 服务器
互联网路由: ❌ VpnConfig.routes API 23 不生效（阻塞）
```

> 当前 VPN 子网（10.8.0.0/24）可通过隧道通信。外网流量路由需等华为确认 `VpnConfig.routes` 实现状态。
> 详见 [docs/harmonyos-wg-ffi-report.md](docs/harmonyos-wg-ffi-report.md)

## 架构

```
┌─ VPN 进程 (:vpn) ───────────────────────────┐
│  TUN ← encrypt/decrypt → 127.0.0.1 relay     │
│  SNAT (源 IP 重写) + IPv6 过滤               │
└────────── loopback UDP ──────────────────────┘
                     │
┌─ 主进程 ─────────────────────────────────────┐
│  UdpRelay → NAPI C socket(pthread) → WG 服务器 │
└──────────────────────────────────────────────┘
```

- **NAPI C 模块** (`udp_socket.cpp`): 原生 UDP socket + pthread 收包 + TSFN 回调
- **主进程运行**: `protectProcessNet()` 在 API 23 不生效，主进程绕开 TUN
- **无 socat/TCPSocket**: loopback UDP 中继，纯 NAPI 直连

## 功能

| 功能 | 状态 |
|------|------|
| `.conf` 配置导入 | ✅ |
| 二维码扫描（相机/相册） | ✅ |
| Noise IKpsk2 握手 | ✅ |
| Transport 加解密 | ✅ |
| Keepalive + Rekey | ✅ |
| SNAT（源 IP 重写 + checksum 修正） | ✅ |
| IPv6 过滤 | ✅ |
| 诊断面板（实时 Tx/Rx） | ✅ |
| 互联网浏览 | ❌ 等待 API 支持 |

## 密码学（纯 ArkTS）

| 算法 | 用途 |
|------|------|
| BLAKE2s-256 / BLAKE2s-128 | 哈希、HMAC、MAC1 |
| X25519 | DH 密钥交换 |
| ChaCha20-Poly1305 | AEAD 加解密 |
| HMAC-BLAKE2s | KDF (wireguard-go 一致) |

## 构建

```bash
# 需要 HarmonyOS SDK API 23 + DevEco Studio
hvigorw assembleHap --mode module -p module=entry@default -p product=default -p buildMode=debug
```

## 已知限制

- `VpnConfig.routes` 在 API 23 不生效（尝试过所有组合）
- `protectProcessNet()` 不工作 → NAPI socket 在主进程
- `requireNapi` 在 `:vpn` 进程报 error 2147483647

## 更新日志

### [v0.1.0] — 2026-06-11

首个可用版本。

- Noise IKpsk2 握手 (HMAC-BLAKE2s KDF, BLAKE2s-128 MAC1)
- ChaCha20Poly1305 Transport 加解密
- NAPI 原生 UDP socket (pthread + TSFN 收包)
- Loopback 中继 (无 socat/TCPSocket)
- SNAT 源 IP 重写 + TCP/UDP checksum 修正
- IPv6 过滤 + Keepalive
- @kit.ScanKit 系统相机扫码 + 相册选图
- .conf 配置文件导入
- 配置持久化 (preferences)
- 诊断面板

## 许可

[MIT](LICENSE)
