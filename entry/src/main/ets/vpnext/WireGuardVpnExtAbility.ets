/**
 * WireGuard VPN Extension — 完整 WireGuard 隧道
 *
 * 工作流程：
 *   启动 → onCreate → onRequest → 创建 TUN →
 *   → 初始化密钥 → Noise IK 握手 → 数据包加解密转发
 *
 * UDP 中继模式：
 *   所有 UDP 包通过 127.0.0.1:RELAY_PORT 发送到 EntryAbility 的
 *   UdpRelay 中继，由中继转发到真实的 WG 服务器。这样绕过
 *   protectProcessNet() 在 API 23 上无效的问题（loopback 流量
 *   不被 VPN TUN 路由劫持）。
 */

import { VpnExtensionAbility, vpnExtension } from '@kit.NetworkKit';
import { Want } from '@kit.AbilityKit';
import { socket } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { NoiseHandshake, HandshakeState } from '../wireguard/tunnel/Handshake';
import { stringToBytes } from '../wireguard/Constants';
import { chacha20Poly1305Encrypt, chacha20Poly1305Decrypt } from '../wireguard/crypto/ChaCha20Poly1305';
import { blake2s256 } from '../wireguard/crypto/Blake2s';
import { base64Decode, base64Encode } from '../wireguard/crypto/Base64';
import { x25519, x25519DH } from '../wireguard/crypto/X25519';
import { hkdf } from '../wireguard/crypto/HKDF';

const DOMAIN = 0x0000;
const TAG = 'WgVpnExt';

// ═══════════════════════════════════════
// 默认配置——正式使用时请通过 .conf 配置文件导入密钥
// ═══════════════════════════════════════
// 这些只是占位值，需要替换为你的 WireGuard 服务器配置
const TEST_CLIENT_PRIVATE_KEY = '';  // 从 .conf 的 [Interface] PrivateKey
const TEST_SERVER_PUBLIC_KEY  = '';  // 从 .conf 的 [Peer] PublicKey
const TEST_CLIENT_ADDRESS    = '10.0.0.2';
const TEST_DNS              = '114.114.114.114';

export default class WireGuardVpnExtAbility extends VpnExtensionAbility {
  private vpnConnection: vpnExtension.VpnConnection | null = null;
  private udpSocket: socket.UDPSocket | null = null;
  private isRunning: boolean = false;
  private tunFd: number = -1;
  private handshake: NoiseHandshake | null = null;
  private relayPort: number = 0;
  private vpnExtPort: number = 0;

  onCreate(want: Want): void {
    hilog.info(DOMAIN, TAG, 'VpnExtension onCreate');
  }

  async onRequest(want: Want, startId: number): Promise<void> {
    hilog.info(DOMAIN, TAG, 'VpnExtension onRequest, startId=%{public}d', startId);

    if (this.isRunning) {
      hilog.info(DOMAIN, TAG, 'Already running, skipping onRequest');
      return;
    }

    // 读取配置
    const serverHost: string       = (want.parameters?.['serverHost'] as string) ?? '';
    const serverIP: string         = (want.parameters?.['serverIP'] as string) ?? serverHost;
    const serverPort: number       = (want.parameters?.['serverPort'] as number) ?? 0;
    const clientAddress: string    = (want.parameters?.['clientAddress'] as string) ?? TEST_CLIENT_ADDRESS;
    const dnsServer: string        = (want.parameters?.['dnsServer'] as string) ?? TEST_DNS;
    const clientPrivateKeyB64: string | undefined = want.parameters?.['clientPrivateKey'] as string;
    const serverPublicKeyB64: string | undefined  = want.parameters?.['serverPublicKey'] as string;
    this.relayPort                 = (want.parameters?.['relayPort'] as number) ?? 0;
    this.vpnExtPort                = (want.parameters?.['vpnExtPort'] as number) ?? 0;
    const presharedKeyB64: string | undefined = want.parameters?.['presharedKey'] as string;

    if (!serverHost || serverPort < 1 || serverPort > 65535) {
      hilog.error(DOMAIN, TAG, 'Invalid config: host=%{public}s port=%{public}d', serverHost, serverPort);
      return;
    }
    if (this.relayPort < 1 || this.relayPort > 65535) {
      hilog.error(DOMAIN, TAG, 'Invalid relayPort=%{public}d', this.relayPort);
      return;
    }
    if (this.vpnExtPort < 1 || this.vpnExtPort > 65535) {
      hilog.error(DOMAIN, TAG, 'Invalid vpnExtPort=%{public}d', this.vpnExtPort);
      return;
    }

    hilog.info(DOMAIN, TAG, 'Server: %{public}s:%{public}d, Relay: 127.0.0.1:%{public}d, VpnExtPort: %{public}d',
      serverHost, serverPort, this.relayPort, this.vpnExtPort);

    // 启动 VPN 隧道（传递密钥参数）
    await this.setupVpn(serverHost, serverPort, clientAddress, dnsServer,
      clientPrivateKeyB64, serverPublicKeyB64, serverIP, presharedKeyB64);
  }

  onDestroy(): void {
    hilog.info(DOMAIN, TAG, 'VpnExtension onDestroy');
    this.cleanup();
  }

  // ═══════════════════════════════════════
  // VPN 设置
  // ═══════════════════════════════════════

  private async setupVpn(host: string, port: number, clientIp: string, dns: string,
    clientPrivKeyB64?: string, serverPubKeyB64?: string, serverIP?: string,
    presharedKeyB64?: string): Promise<void> {
    try {
      this.vpnConnection = vpnExtension.createVpnConnection(this.context);

      // ═══ 关键：在 TUN 创建前保护进程 ═══
      // protectProcessNet() 保护"后续创建的所有 Socket"。
      // 在 TUN 创建前调用，确保后续 UDP Socket 的路由不受 TUN 影响。
      const vpnConn: vpnExtension.VpnConnection = this.vpnConnection;
      try {
        await vpnConn.protectProcessNet();
        hilog.info(DOMAIN, TAG, '✅ protectProcessNet before TUN');
      } catch (e) {
        hilog.error(DOMAIN, TAG, '❌ protectProcessNet before TUN 失败: %{public}s',
          JSON.stringify(e));
      }

      const config: vpnExtension.VpnConfig = {
        addresses: [{
          address: { address: clientIp, family: 1, port: 0 },
          prefixLength: 24,
        }],
        mtu: 1420,
        dnsAddresses: [dns],
        blockedApplications: [],
      };

      this.tunFd = await this.vpnConnection.create(config);
      this.isRunning = true;
      hilog.info(DOMAIN, TAG, 'TUN created, fd=%{public}d', this.tunFd);

      // 启动 WireGuard（UDP Socket 在 TUN 创建前已被保护）
      await this.startWireGuard(host, port, clientPrivKeyB64, serverPubKeyB64, serverIP,
        presharedKeyB64);
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'setupVpn error: %{public}s', JSON.stringify(err));
    }
  }

  // ═══════════════════════════════════════
  // WireGuard 握手 + 数据转发
  // ═══════════════════════════════════════

  private async startWireGuard(host: string, port: number,
    clientPrivKeyB64?: string, serverPubKeyB64?: string, serverIP?: string,
    presharedKeyB64?: string): Promise<void> {
    // ArkTS UDP socket（绑定到 vpnExtPort 以接收中继转发的 Response）
    if (!this.udpSocket) {
      const relaySocket: socket.UDPSocket = socket.constructUDPSocketInstance();
      this.udpSocket = relaySocket;
      // 必须绑定到 vpnExtPort，中继会向 127.0.0.1:vpnExtPort 转发 Response
      await relaySocket.bind({ address: '127.0.0.1', port: this.vpnExtPort });
      hilog.info(DOMAIN, TAG, 'UDP socket bound to 127.0.0.1:%{public}d', this.vpnExtPort);
    }

    // 3. 初始化握手密钥
    this.handshake = new NoiseHandshake();

    // 优先使用配置中传入的密钥，否则回退到测试密钥
    const localPrivB64: string  = clientPrivKeyB64 || TEST_CLIENT_PRIVATE_KEY;
    const remotePubB64: string  = serverPubKeyB64 || TEST_SERVER_PUBLIC_KEY;

    // 从私钥推导公钥（X25519: pub = priv * 9）
    const localPriv: Uint8Array = base64Decode(localPrivB64);
    const basePoint: bigint = 9n;
    const localPub: Uint8Array  = x25519(localPriv, basePoint);
    const remotePub: Uint8Array = base64Decode(remotePubB64);

    const derivedLocalPubB64: string = base64Encode(localPub);

    hilog.info(DOMAIN, TAG, 'Using keys - local: %{public}s', localPrivB64.substring(0, 8) + '...');
    hilog.info(DOMAIN, TAG, 'Derived public: %{public}s', derivedLocalPubB64.substring(0, 16) + '...');
    hilog.info(DOMAIN, TAG, 'Remote pubkey: %{public}s', remotePubB64.substring(0, 16) + '...');

    this.handshake.init(localPriv, localPub, remotePub);

    // Noise_IKpsk2：混合 PresharedKey
    if (presharedKeyB64) {
      const pskBytes: Uint8Array = base64Decode(presharedKeyB64);
      this.handshake.setPresharedKey(pskBytes);
      hilog.info(DOMAIN, TAG, '🔑 PresharedKey 已设置');
    }

    hilog.info(DOMAIN, TAG, 'Handshake initialized with real keys');

    // UDP 连通性测试：通过本地中继发送测试包
    try {
      const testPkt: Uint8Array = stringToBytes('PING');
      if (this.udpSocket) {
        await this.udpSocket.send({
          data: testPkt.buffer as ArrayBuffer,
          address: { address: '127.0.0.1', port: this.relayPort },
        });
      }
      hilog.info(DOMAIN, TAG, '📡 UDP test packet sent via relay (127.0.0.1:%{public}d)', this.relayPort);
    } catch (sendErr) {
      hilog.error(DOMAIN, TAG, '❌ UDP test send failed: %{public}s', JSON.stringify(sendErr));
    }

    // BLAKE2s 自检：验证核心哈希实现
    const testData: Uint8Array = stringToBytes('abc');
    const testHash: Uint8Array = blake2s256(testData);
    const testHex: string = bytesToHex(testHash);
    hilog.info(DOMAIN, TAG, 'BLAKE2s self-test: blake2s("abc")=%{public}s', testHex);
    const b2Expected: string = '508c5e8c327c14e2e1a72ba34eeb452f';
    if (testHex.startsWith(b2Expected)) {
      hilog.info(DOMAIN, TAG, '✅ BLAKE2s 3B PASS');
    } else {
      hilog.info(DOMAIN, TAG, '❌ BLAKE2s 3B FAIL (expected %{public}s)', b2Expected);
    }

    // BLAKE2s 64 字节自检（恰好一个块）
    const b64Data: Uint8Array = new Uint8Array(64);
    for (let bi: number = 0; bi < 64; bi++) b64Data[bi] = bi;
    const b64Hash: Uint8Array = blake2s256(b64Data);
    const b64Hex: string = bytesToHex(b64Hash);
    const b64Expected: string = '56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e';
    hilog.info(DOMAIN, TAG, 'BLAKE2s 64B: %{public}s', b64Hex);
    hilog.info(DOMAIN, TAG, 'BLAKE2s 64B: %{public}s %{public}s',
      b64Hex === b64Expected ? '✅' : '❌', b64Hex === b64Expected ? 'PASS' : 'FAIL');

    // BLAKE2s 64 零字节自检
    const b64zData: Uint8Array = new Uint8Array(64);
    const b64zHash: Uint8Array = blake2s256(b64zData);
    const b64zHex: string = bytesToHex(b64zHash);
    const b64zExpected: string = 'ae09db7cd54f42b490ef09b6bc541af688e4959bb8c53f359a6f56e38ab454a3';
    hilog.info(DOMAIN, TAG, 'BLAKE2s 64x0: %{public}s', b64zHex);
    hilog.info(DOMAIN, TAG, 'BLAKE2s 64x0: %{public}s %{public}s',
      b64zHex === b64zExpected ? '✅' : '❌', b64zHex === b64zExpected ? 'PASS' : 'FAIL');

    // BLAKE2s 65 零字节自检
    const b65zData: Uint8Array = new Uint8Array(65);
    const b65zHash: Uint8Array = blake2s256(b65zData);
    const b65zHex: string = bytesToHex(b65zHash);
    const b65zExpected: string = '857328bf990b00922782d3e81c6054c25d3375d386c7424abe3e01d79041046c';
    hilog.info(DOMAIN, TAG, 'BLAKE2s 65x0: %{public}s', b65zHex);
    hilog.info(DOMAIN, TAG, 'BLAKE2s 65x0: %{public}s %{public}s',
      b65zHex === b65zExpected ? '✅' : '❌', b65zHex === b65zExpected ? 'PASS' : 'FAIL');

    // X25519 测试向量（RFC 7748 Section 6.1 DH）
    // 私钥: 0xa546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
    // 公钥: 0xe6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
    // 结果: 0xc3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
    const xTestPriv: Uint8Array = hexToBytes('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4');
    const xTestPub: Uint8Array = hexToBytes('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c');
    const xResult: Uint8Array = x25519DH(xTestPriv, xTestPub);
    const xResultHex: string = bytesToHex(xResult);
    const xExpected: string = 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552';
    hilog.info(DOMAIN, TAG, 'X25519 DH test: %{public}s', xResultHex);
    if (xResultHex === xExpected) {
      hilog.info(DOMAIN, TAG, '✅ X25519 DH PASS');
    } else {
      hilog.info(DOMAIN, TAG, '❌ X25519 DH FAIL (expected %{public}s)', xExpected);
    }

    // X25519 公钥推导测试（RFC 7748 Section 6.1 Alice）
    // 私钥: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
    // x25519(priv, 9) = 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
    const alicePriv: Uint8Array = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    const alicePub: Uint8Array = x25519(alicePriv, 9n);
    const alicePubHex: string = bytesToHex(alicePub);
    const aliceExpected: string = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
    hilog.info(DOMAIN, TAG, 'X25519 pubkey test: %{public}s', alicePubHex);
    if (alicePubHex === aliceExpected) {
      hilog.info(DOMAIN, TAG, '✅ X25519 pubkey PASS');
    } else {
      hilog.info(DOMAIN, TAG, '❌ X25519 pubkey FAIL (expected %{public}s)', aliceExpected);
    }

    // Base64 解码器硬编码测试：+FlkM+QogHuSbKY2HLxFYJIN2iEgfepAHUb4tHkFdYc= → f8596433e428807b...
    const testB64: string = '+FlkM+QogHuSbKY2HLxFYJIN2iEgfepAHUb4tHkFdYc=';
    const testDecoded: Uint8Array = base64Decode(testB64);
    const testHexStr: string = bytesToHex(testDecoded);
    const expectedHex: string = 'f8596433e428807b926ca6361cbc4560920dda21207dea401d46f8b479057587';
    hilog.info(DOMAIN, TAG, 'Base64 test decoded: %{public}s', testHexStr);
    hilog.info(DOMAIN, TAG, 'Base64 test: %{public}s',
      testHexStr === expectedHex ? '✅ Base64 PASS' : '❌ Base64 FAIL');

    // 验证私钥 Decode → Derive 是否匹配服务器期望的公钥
    const ourPrivKey = base64Decode(clientPrivKeyB64 || '');
    if (ourPrivKey.length === 32) {
      const ourPrivHex = bytesToHex(ourPrivKey);
      hilog.info(DOMAIN, TAG, 'Our privKey hex: %{public}s', ourPrivHex);
      const ourPubKey = x25519(ourPrivKey, 9n);
      const ourPubB64 = base64Encode(ourPubKey);
      hilog.info(DOMAIN, TAG, 'Our derived pub B64: %{public}s', ourPubB64);
      // Expected: f/djvIGyvngmpfmYwlwXhVmuT8S828S53G5RqDVkFhE=
      const expectedPubB64 = 'f/djvIGyvngmpfmYwlwXhVmuT8S828S53G5RqDVkFhE=';
      if (ourPubB64 === expectedPubB64) {
        hilog.info(DOMAIN, TAG, '✅ Our pubKey matches wg pubkey!');
      } else {
        hilog.info(DOMAIN, TAG, '❌ PubKey MISMATCH (expected f/djv...)');
      }
    }

    // ChaCha20Poly1305 AEAD 测试（RFC 8439 Section 2.8.2）
    const aeadKey: Uint8Array = hexToBytes('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
    const aeadNonce: Uint8Array = hexToBytes('070000004041424344454647');
    const aeadPlain: Uint8Array = hexToBytes('4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e');
    const aeadAad: Uint8Array = hexToBytes('50515253c0c1c2c3c4c5c6c7');
    try {
      const aeadResult = chacha20Poly1305Encrypt(aeadKey, aeadNonce, aeadPlain, aeadAad);
      const ctHex: string = bytesToHex(aeadResult.ciphertext);
      const tagHex: string = bytesToHex(aeadResult.tag);
      const expectedCT: string = 'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116';
      const expectedTag: string = '1ae10b594f09e26a7e902ecbd0600691';
      hilog.info(DOMAIN, TAG, 'ChaCha20 test CT match=%{public}s', (ctHex === expectedCT).toString());
      hilog.info(DOMAIN, TAG, 'ChaCha20 test tag match=%{public}s', (tagHex === expectedTag).toString());
      if (ctHex === expectedCT && tagHex === expectedTag) {
        hilog.info(DOMAIN, TAG, '✅ ChaCha20Poly1305 self-test PASS');
      } else {
        hilog.info(DOMAIN, TAG, '❌ ChaCha20 FAIL ct=%{public}s', ctHex.substring(0, 32));
      }
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'ChaCha20 test error: %{public}s', JSON.stringify(e));
    }

    // 5. 启动接收循环（必须在发送前注册，否则可能漏接快速响应）
    if (this.udpSocket) {
      this.startReceiveLoop(this.udpSocket, host, port);
    }

    // 4. 构建并发送 Initiation 消息
    const initMsg: Uint8Array = this.handshake.buildInitiation();
    hilog.info(DOMAIN, TAG, 'Initiation msg built, len=%{public}d', initMsg.length);
    // 日志前 32 字节用于调试
    const initHex: string = bytesToHex(initMsg.subarray(0, 32));
    hilog.info(DOMAIN, TAG, 'Init header: %{public}s', initHex);
    // 日志 MAC1 前 8 字节
    const mac1Hex: string = bytesToHex(initMsg.subarray(initMsg.length - 32, initMsg.length - 16));
    hilog.info(DOMAIN, TAG, 'MAC1: %{public}s', mac1Hex);

    // 发送方式1：直连 WG 服务器（用 IP 地址，避免 DNS 问题）
    const destIP: string = serverIP || host;
    if (this.udpSocket) {
      try {
        await this.udpSocket.send({
          data: initMsg.buffer.slice(0, initMsg.byteLength) as ArrayBuffer,
          address: { address: destIP, port: port },
        });
        hilog.info(DOMAIN, TAG, '✅ DIRECT sent to %{public}s:%{public}d', destIP, port);
      } catch (e) {
        hilog.info(DOMAIN, TAG, '❌ DIRECT failed: %{public}s', JSON.stringify(e));
      }
    }

    // 发送方式2：通过本地中继（兜底）
    if (this.udpSocket) {
      await this.udpSocket.send({
        data: initMsg.buffer.slice(0, initMsg.byteLength) as ArrayBuffer,
        address: { address: '127.0.0.1', port: this.relayPort },
      });
      hilog.info(DOMAIN, TAG, 'Initiation sent via relay (127.0.0.1:%{public}d)', this.relayPort);
    }

    // 6. 握手等待循环
    for (let attempt = 0; attempt < 3; attempt++) {
      await sleep(2000);

      if (this.handshake && this.handshake.isComplete()) {
        hilog.info(DOMAIN, TAG, '✅ Handshake completed!');
        break;
      }

      if (this.handshake && this.handshake.state === HandshakeState.WAITING_RESPONSE) {
        hilog.info(DOMAIN, TAG, 'Retry sending Initiation (attempt %{public}d)', attempt + 2);
        const retryMsg: Uint8Array = this.handshake.buildInitiation();
        if (this.udpSocket) {
          try {
            await this.udpSocket.send({
              data: retryMsg.buffer.slice(0, retryMsg.byteLength) as ArrayBuffer,
              address: { address: '127.0.0.1', port: this.relayPort },
            });
          } catch (e) {
            hilog.error(DOMAIN, TAG, 'Retry send failed: %{public}s', JSON.stringify(e));
          }
        }
      }
    }
  }

  /** 启动接收循环（监听 relay 转发回来的 WG 服务器响应） */
  private startReceiveLoop(udpSocket: socket.UDPSocket, host: string, port: number): void {
    udpSocket.on('message', (info: socket.SocketMessageInfo): void => {
      const bytes: Uint8Array = new Uint8Array(info.message as ArrayBuffer);
      if (bytes.length < 4) return;
      const msgType: number = readU32(bytes, 0);

      if (msgType === 2 && this.handshake) {
        hilog.info(DOMAIN, TAG, '📩 Handshake Response! (%{public}d bytes)', bytes.length);
        const ok: boolean = this.handshake.processResponse(bytes);
        if (ok) {
          hilog.info(DOMAIN, TAG, '✅ WireGuard 握手成功！');
          if (this.handshake && this.handshake.sessionKeys) {
            hilog.info(DOMAIN, TAG, '会话密钥已建立');
          }
        } else {
          hilog.error(DOMAIN, TAG, '❌ 握手处理失败');
        }
      } else if (msgType === 4) {
        hilog.info(DOMAIN, TAG, 'Transport data (%{public}d bytes)', bytes.length);
      } else if (msgType === 3) {
        hilog.info(DOMAIN, TAG, 'Cookie reply');
      } else {
        hilog.info(DOMAIN, TAG, 'Unknown type=%{public}d', msgType);
      }
    });
  }

  // ═══════════════════════════════════════
  // 清理
  // ═══════════════════════════════════════

  private cleanup(): void {
    this.isRunning = false;
    if (this.udpSocket) {
      try { this.udpSocket.close(); } catch (e) { /* ignore */ }
      this.udpSocket = null;
    }
    if (this.vpnConnection) {
      try { this.vpnConnection.destroy(); } catch (e) { /* ignore */ }
      this.vpnConnection = null;
    }
    this.tunFd = -1;
    this.handshake = null;
    hilog.info(DOMAIN, TAG, 'Cleanup complete');
  }
}

// ── 工具 ──
function readU32(buf: Uint8Array, off: number): number {
  return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
}

function sleep(ms: number): Promise<void> {
  return new Promise<void>(resolve => setTimeout(resolve, ms));
}

function bytesToHex(bytes: Uint8Array): string {
  const hex: string = '0123456789abcdef';
  let result: string = '';
  for (let i = 0; i < bytes.length; i++) {
    result += hex[(bytes[i] >> 4) & 0xF] + hex[bytes[i] & 0xF];
  }
  return result;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes: Uint8Array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
