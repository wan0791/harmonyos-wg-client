/**
 * UDP 中继 — 绕过 VpnExtensionAbility 的 TUN 路由劫持
 *
 * 消息类型路由：
 *   类型 1 (Initiation)  → VpnExt → 中继 → WG 服务器
 *   类型 4 (Transport)   → VpnExt → 中继 → WG 服务器
 *   类型 2 (Response)    → WG 服务器 → 中继 → VpnExt (127.0.0.1:vpnExtPort)
 *   类型 3 (Cookie Reply) → WG 服务器 → 中继 → VpnExt (127.0.0.1:vpnExtPort)
 */

import { socket, connection } from '@kit.NetworkKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { NativeSocket } from './NativeSocketFFI';
import { readU32 } from '../wireguard/tunnel/Handshake';
import { stringToBytes } from '../wireguard/Constants';

const DOMAIN = 0x0000;
const TAG = 'UdpRelay';

const MSG_TYPE_INITIATION: number = 1;
const MSG_TYPE_RESPONSE: number = 2;
const MSG_TYPE_COOKIE_REPLY: number = 3;
const MSG_TYPE_TRANSPORT: number = 4;

let instance: UdpRelay | null = null;

export function getRelay(): UdpRelay {
  if (!instance) {
    instance = new UdpRelay();
  }
  return instance;
}

export class UdpRelay {
  private sock: socket.UDPSocket | null = null;
  private nativeSock: NativeSocket | null = null;  // NAPI 原生 socket（主进程不受 TUN 影响）
  private remoteHost: string = '';
  private remotePort: number = 0;
  private relayPort: number = 0;
  private vpnExtPort: number = 0;
  private running: boolean = false;
  // 统计
  txBytes: number = 0;
  rxBytes: number = 0;

  /** 设置 NAPI 原生 socket（主进程不受 TUN 影响） */
  setNativeSocket(ns: NativeSocket): void {
    this.nativeSock = ns;
  }

  /** 启动中继 */
  async start(remoteHost: string, remotePort: number,
    relayPort: number, vpnExtPort: number): Promise<void> {
    if (this.running) return;
    this.remoteHost = remoteHost;
    this.remotePort = remotePort;
    this.relayPort = relayPort;
    this.vpnExtPort = vpnExtPort;

    try {
      this.sock = socket.constructUDPSocketInstance();

      // 先 bind
      await this.sock.bind({ address: '0.0.0.0', port: this.relayPort });

      // 尝试绑定到物理网络绕过 TUN
      // 注意：getDefaultNet 可能返回 TUN 接口（VPN 激活后默认路由走 TUN）
      // 改用 getAllNets 遍历所有网络，找到非 TUN 的物理网络
      try {
        const allNets: connection.NetHandle[] = await connection.getAllNets();
        hilog.info(DOMAIN, TAG, '可用网络数: %{public}d', allNets.length);
        let bound: boolean = false;
        for (let i: number = 0; i < allNets.length; i++) {
          try {
            await allNets[i].bindSocket(this.sock);
            hilog.info(DOMAIN, TAG, '✅ Socket 绑定到网络[%{public}d] 成功', i);
            bound = true;
            break;
          } catch (netErr) {
            hilog.info(DOMAIN, TAG, '网络[%{public}d] 绑定失败: %{public}s',
              i, JSON.stringify(netErr));
          }
        }
        if (!bound) {
          hilog.info(DOMAIN, TAG, '⚠️ 所有网络绑定失败，使用默认路由');
        }
      } catch (listErr) {
        hilog.info(DOMAIN, TAG, '⚠️ getAllNets 失败: %{public}s', JSON.stringify(listErr));
      }

      hilog.info(DOMAIN, TAG, '中继已启动 relay=%{public}d vpnExt=%{public}d',
        this.relayPort, this.vpnExtPort);

      this.sock.on('message', (info: socket.SocketMessageInfo): void => {
        this.onMessage(info);
      });
      this.running = true;
    } catch (err) {
      const errMsg: string = JSON.stringify(err);
      hilog.error(DOMAIN, TAG, '中继启动失败: %{public}s', errMsg);
      throw new Error(errMsg);
    }
  }

  getPort(): number {
    return this.relayPort;
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.nativeSock) {
      this.nativeSock.stopRecvThread();
    }
    if (this.sock) {
      try { this.sock.off('message'); await this.sock.close(); } catch (e) { }
      this.sock = null;
    }
    hilog.info(DOMAIN, TAG, '中继已停止');
  }

  // ── 内部 ──

  private onMessage(info: socket.SocketMessageInfo): void {
    if (!this.running || !this.sock) {
      hilog.warn(DOMAIN, TAG, 'onMessage: 中继未运行');
      return;
    }

    const bytes: Uint8Array = new Uint8Array(info.message);
    hilog.info(DOMAIN, TAG, 'onMessage: 收到 %{public}d 字节', bytes.byteLength);

    if (bytes.length < 4) {
      hilog.warn(DOMAIN, TAG, 'onMessage: 数据过短');
      return;
    }
    const msgType: number = readU32(bytes, 0);
    hilog.info(DOMAIN, TAG, 'onMessage: 消息类型=%{public}d', msgType);

    if (msgType === MSG_TYPE_INITIATION) {
      hilog.info(DOMAIN, TAG, '→ 类型1 Initiation, 转发到服务器');
      this.forwardToServer(bytes);
    } else if (msgType === MSG_TYPE_TRANSPORT) {
      hilog.info(DOMAIN, TAG, '→ 类型4 Transport, 转发到服务器');
      this.forwardToServer(bytes);
    } else if (msgType === MSG_TYPE_RESPONSE) {
      hilog.info(DOMAIN, TAG, '→ 类型2 Response, 转发回 VpnExt');
      this.forwardToVpnExt(bytes);
    } else if (msgType === MSG_TYPE_COOKIE_REPLY) {
      hilog.info(DOMAIN, TAG, '→ 类型3 Cookie, 转发回 VpnExt');
      this.forwardToVpnExt(bytes);
    } else {
      hilog.info(DOMAIN, TAG, '→ 未知类型 %{public}d, 丢弃', msgType);
    }
  }

  private forwardToServer(data: Uint8Array): void {
    // 纯 NAPI 直连——不依赖任何服务端 relay
    if (!this.nativeSock) return;
    try {
      const buf: ArrayBuffer = data.buffer.slice(0, data.byteLength) as ArrayBuffer;
      this.nativeSock.sendTo(buf, this.remoteHost, this.remotePort);
      this.txBytes += data.byteLength;
    } catch (e) { /* ignore */ }
  }

  private async forwardToVpnExt(data: Uint8Array): Promise<void> {
    try {
      const buf: ArrayBuffer = data.buffer.slice(0, data.byteLength) as ArrayBuffer;
      await this.sock!.send({
        data: buf,
        address: { address: '127.0.0.1', port: this.vpnExtPort },
      });
      hilog.info(DOMAIN, TAG, '✅ 已转发到 VpnExt:%{public}d (%{public}d 字节)',
        this.vpnExtPort, data.byteLength);
    } catch (err) {
      hilog.error(DOMAIN, TAG, '→VpnExt失败: %{public}s', JSON.stringify(err));
    }
  }

  /** 启动 C 层 pthread 收包线程（不依赖 JS 定时器） */
  startNativeRecvLoop(): void {
    if (!this.nativeSock) return;
    hilog.info(DOMAIN, TAG, 'Starting C recv thread...');
    const ok: boolean = this.nativeSock.startRecvThread(
      (data: ArrayBuffer, ip: string, port: number): void => {
        if (!this.running) return;
        const bytes: Uint8Array = new Uint8Array(data);
        if (bytes.length >= 4) {
          const msgType: number = readU32(bytes, 0);
          hilog.info(DOMAIN, TAG, '📩 Native recv: type=%{public}d len=%{public}d from %{public}s:%{public}d',
            msgType, bytes.length, ip, port);
          this.rxBytes += bytes.length;
          if (msgType === MSG_TYPE_RESPONSE || msgType === MSG_TYPE_COOKIE_REPLY ||
              msgType === MSG_TYPE_TRANSPORT) {
            this.forwardToVpnExt(bytes);
          }
        }
      }
    );
    hilog.info(DOMAIN, TAG, 'C recv thread started: %{public}s', ok ? 'true' : 'false');
  }

}
