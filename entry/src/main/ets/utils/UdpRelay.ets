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

function readU32(buf: Uint8Array, off: number): number {
  return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
}

function stringToBytes(s: string): Uint8Array {
  const buf: Uint8Array = new Uint8Array(s.length);
  for (let i: number = 0; i < s.length; i++) buf[i] = s.charCodeAt(i) & 0xFF;
  return buf;
}

export class UdpRelay {
  private sock: socket.UDPSocket | null = null;
  private tcpSock: socket.TCPSocket | null = null;
  private remoteHost: string = '';
  private remotePort: number = 0;
  private relayPort: number = 0;
  private vpnExtPort: number = 0;
  private running: boolean = false;

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

      // TCP 隧道：连接到服务器 socat（TCP 51820 → WG UDP 51820）
      this.connectTcpTunnel();

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
    if (this.tcpSock) {
      try { this.tcpSock.off('message'); await this.tcpSock.close(); } catch (e) { }
      this.tcpSock = null;
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

  private async forwardToServer(data: Uint8Array): Promise<void> {
    // 方式1：通过 TCP 隧道（优先，能绕过 TUN）
    if (this.tcpSock) {
      try {
        await this.tcpSock.send({
          data: data.buffer.slice(0, data.byteLength) as ArrayBuffer,
        });
        hilog.info(DOMAIN, TAG, '✅ TCP 隧道转发 %{public}d 字节到服务器', data.byteLength);
        return;
      } catch (tcpErr) {
        hilog.info(DOMAIN, TAG, '⚠️ TCP 转发失败，回退 UDP: %{public}s', JSON.stringify(tcpErr));
      }
    }
    // 方式2：UDP（兜底，可能被 TUN 拦截）
    try {
      const buf: ArrayBuffer = data.buffer.slice(0, data.byteLength) as ArrayBuffer;
      await this.sock!.send({
        data: buf,
        address: { address: this.remoteHost, port: this.remotePort },
      });
      hilog.info(DOMAIN, TAG, '✅ UDP 转发到服务器 %{public}s:%{public}d (%{public}d 字节)',
        this.remoteHost, this.remotePort, data.byteLength);
    } catch (err) {
      hilog.error(DOMAIN, TAG, '→服务器失败: %{public}s', JSON.stringify(err));
    }
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

  /** 建立 TCP 隧道（TCPSocket → socat → WG UDP） */
  private async connectTcpTunnel(): Promise<void> {
    try {
      // TCP relay 端口（8443 避免移动网络封锁，服务端 relay.py 在 8443 监听）
      const tcpRelayPort: number = 8443;
      const tcpSock: socket.TCPSocket = socket.constructTCPSocketInstance();
      await tcpSock.connect({
        address: { address: this.remoteHost, port: tcpRelayPort },
        timeout: 10000,
      });
      this.tcpSock = tcpSock;
      hilog.info(DOMAIN, TAG, '✅ TCP 隧道已建立 %{public}s:51820', this.remoteHost);

      // 注册 TCP 接收回调（来自 WG 服务器的响应）
      tcpSock.on('message', (info: socket.SocketMessageInfo): void => {
        const resp: Uint8Array = new Uint8Array(info.message);
        hilog.info(DOMAIN, TAG, '📩 TCP 收到 %{public}d 字节服务器响应', resp.byteLength);
        // 转发回 VpnExtAbility
        this.forwardToVpnExt(resp);
      });
    } catch (tcpErr) {
      hilog.info(DOMAIN, TAG, '⚠️ TCP 隧道建立失败: %{public}s', JSON.stringify(tcpErr));
    }
  }
}
