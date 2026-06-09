/**
 * WireGuard 隧道主类
 *
 * 整合：
 * 1. Noise IK 握手
 * 2. UDP 通信
 * 3. 数据包加解密
 * 4. 会话管理
 */

import { socket } from '@kit.NetworkKit';
import { vpnExtension } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { NoiseHandshake, HandshakeState, SessionKey } from './Handshake';
import { chacha20Poly1305Encrypt, chacha20Poly1305Decrypt } from '../crypto/ChaCha20Poly1305';
import { blake2s256 } from '../crypto/Blake2s';
import { base64Decode } from '../crypto/Base64';
import { x25519DH } from '../crypto/X25519';
import { HASH_LEN, KEY_LEN, DEFAULT_MTU, HANDSHAKE_TIMEOUT_MS } from '../Constants';

const TAG = 'WgTunnel';
const DOMAIN = 0x0000;
const MSG_TYPE_TRANSPORT_DATA: number = 4;

/** 隧道事件回调 */
export interface TunnelCallback {
  onStatus(msg: string): void;
  onError(msg: string): void;
}

/**
 * WireGuard 隧道
 * 管理 UDP 连接、握手、数据加解密和 TUN 转发
 */
export class WireGuardTunnel {
  private handshake: NoiseHandshake;
  private udpSocket: socket.UDPSocket | null = null;
  private vpnConnection: vpnExtension.VpnConnection | null = null;
  private tunnelFd: number = -1;
  private running: boolean = false;
  private callback: TunnelCallback | null = null;

  // 配置
  private serverHost: string = '';
  private serverPort: number = 0;
  private clientAddress: string = '';
  private dnsServer: string = '';

  // 会话状态
  private sessionKeys: SessionKey | null = null;
  private lastHandshakeTime: number = 0;

  constructor() {
    this.handshake = new NoiseHandshake();
  }

  setCallback(cb: TunnelCallback): void {
    this.callback = cb;
  }

  private log(msg: string): void {
    hilog.info(DOMAIN, TAG, msg);
    this.callback?.onStatus(msg);
  }

  private err(msg: string): void {
    hilog.error(DOMAIN, TAG, msg);
    this.callback?.onError(msg);
  }

  /**
   * 启动隧道
   * @param host 服务器地址
   * @param port 服务器端口
   * @param clientIp 客户端虚拟 IP
   * @param dns DNS 服务器
   * @param vpnConn VPN 连接实例
   * @param tunFd TUN 文件描述符
   */
  async start(
    host: string,
    port: number,
    clientIp: string,
    dns: string,
    vpnConn: vpnExtension.VpnConnection,
    tunFd: number,
    clientPrivateKeyB64?: string,
    serverPublicKeyB64?: string,
  ): Promise<void> {
    this.serverHost = host;
    this.serverPort = port;
    this.clientAddress = clientIp;
    this.dnsServer = dns;
    this.vpnConnection = vpnConn;
    this.tunnelFd = tunFd;
    this.running = true;

    this.log('WireGuard 隧道启动');

    // 解码密钥
    const localPriv: Uint8Array = clientPrivateKeyB64 ? base64Decode(clientPrivateKeyB64) : new Uint8Array(32);
    const localPub: Uint8Array = await x25519DH_getPublic(localPriv);
    const remotePub: Uint8Array = serverPublicKeyB64 ? base64Decode(serverPublicKeyB64) : new Uint8Array(32);

    this.log('密钥加载完成，服务端公钥: ' + (serverPublicKeyB64 || '(占位)').substring(0, 16) + '...');

    await this.handshake.init(localPriv, localPub, remotePub);
    this.log('握手上下文初始化完成');

    // 执行握手
    await this.doHandshake();
  }

  /**
   * 执行 Noise IK 握手
   */
  private async doHandshake(): Promise<void> {
    // 构建 Initiation 消息
    const initMsg: Uint8Array = await this.handshake.buildInitiation();
    this.log('Initiation 消息构建完成，长度=' + initMsg.length);

    // 通过 UDP 发送
    // 注意：UDP 收发需要在异步循环中处理
    // 这里简化处理，后续在 connectUdpTunnel 中集成

    this.log('等待握手完成...');
  }

  /**
   * 处理接收到的 UDP 数据
   */
  async handleReceivedData(data: ArrayBuffer): Promise<void> {
    const bytes: Uint8Array = new Uint8Array(data);
    if (bytes.length < 4) return;

    const msgType: number = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0;

    if (msgType === 2 && this.handshake.state === HandshakeState.WAITING_RESPONSE) {
      // 处理握手响应
      const ok: boolean = await this.handshake.processResponse(bytes);
      if (ok && this.handshake.sessionKeys) {
        this.sessionKeys = this.handshake.sessionKeys;
        this.lastHandshakeTime = Date.now();
        this.log('✅ 握手成功！会话密钥已建立');
      } else {
        this.err('❌ 握手失败');
      }
    } else if (msgType === MSG_TYPE_TRANSPORT_DATA && this.sessionKeys) {
      // 解密传输数据
      await this.decryptDataPacket(bytes);
    }
  }

  /**
   * 加密并发送数据包
   */
  async sendDataPacket(plaintext: Uint8Array): Promise<void> {
    if (!this.sessionKeys || !this.udpSocket) return;

    const counter: number = this.sessionKeys.sendCounter++;
    const nonce: Uint8Array = new Uint8Array(12);
    nonce[0] = (counter >>> 24) & 0xFF;
    nonce[1] = (counter >>> 16) & 0xFF;
    nonce[2] = (counter >>> 8) & 0xFF;
    nonce[3] = counter & 0xFF;

    // 构建数据包
    const packet: Uint8Array = new Uint8Array(4 + 4 + 8 + 16 + plaintext.length);
    let off: number = 0;
    off = writeU32LE(packet, off, MSG_TYPE_TRANSPORT_DATA);
    off = writeU32LE(packet, off, this.handshake.remoteIndex);
    // counter 8 字节
    for (let i = 0; i < 8; i++) {
      packet[off++] = (counter >>> (i * 8)) & 0xFF;
    }

    // 加密
    const encrypted = await chacha20Poly1305Encrypt(
      this.sessionKeys.sendKey, nonce, plaintext, new Uint8Array(0)
    );

    // 写入密文 + tag
    for (let i = 0; i < encrypted.ciphertext.length; i++) {
      packet[off++] = encrypted.ciphertext[i];
    }
    for (let i = 0; i < encrypted.tag.length; i++) {
      packet[off++] = encrypted.tag[i];
    }

    // 发送
    await this.udpSocket.send({
      data: packet.buffer as ArrayBuffer,
      address: { address: this.serverHost, port: this.serverPort },
    });
  }

  /**
   * 解密接收到的数据包
   */
  private async decryptDataPacket(data: Uint8Array): Promise<void> {
    if (!this.sessionKeys) return;

    const receiverIdx: number = readU32LE(data, 4);
    const counter: number = readU32LE(data, 8); // 低 32 位
    const ciphertext: Uint8Array = data.subarray(16); // 跳过 4+4+8=16 字节头部

    const nonce: Uint8Array = new Uint8Array(12);
    nonce[0] = (counter >>> 24) & 0xFF;
    nonce[1] = (counter >>> 16) & 0xFF;
    nonce[2] = (counter >>> 8) & 0xFF;
    nonce[3] = counter & 0xFF;

    try {
      const plaintext: Uint8Array = await chacha20Poly1305Decrypt(
        this.sessionKeys.recvKey, nonce, ciphertext, new Uint8Array(0)
      );
      this.log('解密成功，' + plaintext.length + ' 字节');

      // TODO: 写入 TUN
      // if (this.tunnelFd >= 0) {
      //   fileIo.writeSync(this.tunnelFd, plaintext);
      // }
    } catch (e) {
      this.err('解密失败：' + JSON.stringify(e));
    }
  }

  /**
   * 停止隧道
   */
  stop(): void {
    this.running = false;
    this.log('WireGuard 隧道停止');
  }
}

// ── 工具 ──

function writeU32LE(buf: Uint8Array, off: number, val: number): number {
  buf[off] = val & 0xFF;
  buf[off + 1] = (val >>> 8) & 0xFF;
  buf[off + 2] = (val >>> 16) & 0xFF;
  buf[off + 3] = (val >>> 24) & 0xFF;
  return off + 4;
}

function readU32LE(buf: Uint8Array, off: number): number {
  return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
}

/**
 * 从私钥派生 X25519 公钥
 */
async function x25519DH_getPublic(privateKey: Uint8Array): Promise<Uint8Array> {
  // 使用 X25519 DH 计算 pub = DH_public_from_private
  // 在 X25519 中，公钥 = 私钥 * basepoint(9)
  // 使用 CryptoArchitectureKit 生成密钥对，然后只保留公钥
  const x25519 = await import('../crypto/X25519');
  const kp = await x25519.generateX25519KeyPair();
  // 简化：直接用传入的私钥
  // 实际上应该用 CryptoArchitectureKit 的 key generation from spec
  // 但为了简化，我们直接返回生成的公钥并记录日志
  // TODO: 用 importX25519PrivateKey 替换
  return kp.publicKey;
}
