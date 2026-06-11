# HarmonyOS WireGuard VPN Client

基于 HarmonyOS NEXT (API 23) 的 WireGuard VPN 客户端。

## 状态：✅ 握手成功（2026-06-11）

手机实测成功完成 Noise_IKpsk2 握手，数据传输正常。
```
Handshake: ekk0NFM... = 1781096215 ✅
Transfer:  接收 7136 字节 / 发送 736 字节 ✅
```
⏳ TUN ↔ WG 数据转发（Transport 层）待实现，网页暂不能访问。

## 功能

- ✅ **配置文件导入** — 支持 `.conf` 格式
- ✅ **二维码扫描** — 相册选图解码
- ✅ **端口分离 + 域名** — 独立输入框
- ✅ **密钥编辑** — 含 PresharedKey
- ✅ **TUN 虚拟网卡** — 创建 VPN 接口
- ✅ **TCP 隧道中继** — 绕过 TUN 劫持（HarmonyOS API 23 限制）
- ✅ **密码学全通过** — BLAKE2s、X25519、ChaCha20Poly1305
- ✅ **Noise_IKpsk2 握手完成** — Python→内核验证通过

## 核心修复：CookieChecker MAC1

WG 内核的 MAC1 使用 `BLAKE2s("mac1----" || SERVER_PUB)[:16]`，而非 Noise 协议的链式 MAC1。
详见 wireguard-go `device/cookie.go:44-55`。

KDF 使用 **HMAC-BLAKE2s**（非 BLAKE2s keyed mode），见 `noise-helpers.go:43-56`。

## 网络架构

```
手机 ArkTS → UDP loopback → UdpRelay(TCP 8443) → socat → WG UDP 51820
                        ↑ TCP 绕过 TUN，8443 避开运营商封锁
```

## 构建

```bash
hvigorw --mode module -p module=entry@default assembleHap
```
- DevEco Studio / HarmonyOS SDK API 23

## 使用

1. 从 wg-easy 获取 `.conf` 配置
2. App 中点击 **📁 导入配置**
3. 点 **连接 VPN**

## 密码学实现（纯 ArkTS）

| 算法 | 用途 | 验证 |
|------|------|------|
| BLAKE2s-256 | 哈希、HMAC | ✅ RFC 7693 |
| X25519 | 密钥交换 | ✅ RFC 7748 |
| ChaCha20-Poly1305 | AEAD | ✅ RFC 8439 |
| HMAC-BLAKE2s | KDF (HKDF) | ✅ wireguard-go 一致 |

## 已知限制

- `protectProcessNet()` 在 API 23 上不生效 → 使用 TCP 隧道
- 数据包转发（TUN ↔ UDP）待完善
- 仅单 Peer 模式

## 许可

[MIT](LICENSE)
