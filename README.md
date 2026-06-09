# HarmonyOS WireGuard VPN Client

一个基于 HarmonyOS NEXT (API 23+) 的 WireGuard VPN 客户端。

> ⚠️ **非完整品**：本项目是一个实验性学习项目，核心功能已实现但**握手尚未通过服务器验证**。具体问题见下方 [#已知问题](#已知问题)。

## 功能

- ✅ **配置文件导入** — 支持导入标准 `.conf` 格式的 WireGuard 配置文件
- ✅ **二维码扫描** — 从相册选择二维码图片，自动解码配置
- ✅ **端口分离输入** — 服务端地址和端口独立输入，支持域名
- ✅ **密钥编辑** — 可手动修改客户端私钥和服务端公钥
- ✅ **TUN 虚拟网卡** — 成功创建 VPN 接口
- ✅ **UDP 通信** — UDP Socket 绑定和通信正常
- ✅ **Socket 环路保护** — `protectProcessNet` 已调用
- ✅ **密码学全通过 RFC 测试向量** — BLAKE2s、X25519、ChaCha20Poly1305

## 密码学实现

所有密码学算法均为 **纯 ArkTS 实现**，不依赖系统 CryptoKit：

| 算法 | 用途 | 验证 |
|------|------|------|
| BLAKE2s-256 | 哈希、HKDF、MAC | ✅ RFC 7693 验证通过 |
| X25519 (Curve25519) | 密钥交换 | ✅ RFC 7748 验证通过 |
| ChaCha20-Poly1305 | AEAD 加密 | ✅ RFC 8439 验证通过 |
| HKDF (BLAKE2s 密钥模式) | 密钥派生 | ✅ 与 wireguard-go 一致 |

## 构建要求

- DevEco Studio NEXT (5.0+)
- HarmonyOS SDK API 23 (6.1.0.23)
- 已签名的调试/发布证书

### 构建步骤

```bash
# 1. 复制签名配置模板
cp build-profile.template.json5 build-profile.json5

# 2. 编辑 build-profile.json5，填入你的签名信息
#    （或在 DevEco Studio 中直接配置）

# 3. 构建 HAP
hvigorw --mode module -p module=entry@default assembleHap
```

## 使用方式

1. 在 WireGuard 服务器面板（如 wg-easy）创建一个客户端
2. 下载客户端配置文件 (`.conf`)
3. 在 App 中点击 **📁 导入配置**，选择配置文件
4. 检查字段是否自动填充（服务端地址、端口、虚拟 IP、DNS、密钥）
5. 输入你的服务器地址（域名或 IP），点击 **连接 VPN**

## 项目结构

```
entry/src/main/ets/
├── pages/
│   ├── Index.ets                          # 主界面
│   └── ScanPage.ets                       # 二维码扫描页面
├── entryability/
│   └── EntryAbility.ets                   # Ability 入口
├── vpnext/
│   └── WireGuardVpnExtAbility.ets         # VPN 扩展（核心入口）
├── utils/
│   ├── WgConfigParser.ets                 # .conf 配置文件解析器
│   └── QrDecoder.ets                      # QR 码解码器
└── wireguard/
    ├── Constants.ets                      # 协议常量
    ├── crypto/
    │   ├── Blake2s.ets                    # BLAKE2s 哈希
    │   ├── ChaCha20Poly1305.ets           # ChaCha20-Poly1305 AEAD
    │   ├── X25519.ets                     # Curve25519 标量乘法
    │   ├── HKDF.ets                       # 密钥派生函数
    │   └── Base64.ets                     # Base64 编解码
    └── tunnel/
        ├── Handshake.ets                  # Noise IK 握手状态机
        └── WireGuardTunnel.ets            # 隧道主类
```

## 已知问题

### ❌ 握手无法完成（核心问题）

**现象**：App 可以创建 TUN 虚拟网卡、绑定 UDP Socket、发送握手消息（日志显示 `Initiation sent`），但**数据包从未到达服务端**。

**原因分析**：HarmonyOS 的 `VpnExtensionAbility` 在创建 TUN 接口后，系统 VPN 框架将**本进程的 UDP 包也路由到了 TUN 接口**，形成环路。已尝试：

1. `vpnConnection.protectProcessNet()` — 应在进程级别保护 Socket 绕过 VPN，但**未生效**
2. `VpnConfig.trustedApplications` — 将本应用加入信任列表以绕过 VPN，但**未生效**
3. 显式设置 VpnConfig.routes — 需要 `RouteInfo` 完整类型，因 API 兼容问题未实现

**可能的原因**：
- HarmonyOS API 23/24 的 VPN 框架行为问题
- `protectProcessNet()` 在 API 23 上可能未完整实现
- 需要华为官方修复或提供替代方案

### ⏳ 待完善

- [ ] 握手后的数据包转发（TUN ↔ UDP）
- [ ] 连接状态持久化
- [ ] 多 Peer 支持
- [ ] 完整 WireGuard Noise 协议握手验证

## 贡献

欢迎提交 Issue 和 PR！如果你有解决握手问题的思路，请务必告知。

## 许可

[MIT](LICENSE)
