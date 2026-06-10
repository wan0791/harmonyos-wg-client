/**
 * NativeSocket — 使用原生 C UDP Socket 绕过 TUN 路由劫持
 *
 * 方案：在主进程（EntryAbility）中用 requireNapi 创建原生 Socket，
 * 然后保护它。因为 requireNapi 可能在 VpnExtension 进程中不可用。
 */

import { hilog } from '@kit.PerformanceAnalysisKit';
import { vpnExtension } from '@kit.NetworkKit';

const DOMAIN = 0x0000;
const TAG = 'NativeSock';

interface NativeUdpModule {
  createUdpSocket(): number;
  udpBind(fd: number, port: number): void;
  udpSendTo(fd: number, data: ArrayBuffer, host: string, port: number): number;
  udpRecvFrom(fd: number, bufSize: number, timeoutMs: number): NativeRecvResult | null;
  closeUdpSocket(fd: number): void;
  getLocalPort(fd: number): number;
}

interface NativeAddress {
  address: string;
  port: number;
}

interface NativeRecvResult {
  data: ArrayBuffer;
  from: NativeAddress;
}

/** HarmonyOS 内置函数 */
declare function requireNapi(name: string): Object;

export class RecvResult {
  data: Uint8Array = new Uint8Array(0);
  fromAddress: string = '';
  fromPort: number = 0;
}

/**
 * 原生 UDP Socket 封装
 */
export class NativeSocket {
  private static fd: number = -1;
  private static mod: NativeUdpModule | null = null;

  /** 加载原生模块并创建 Socket（必须在主进程调用） */
  static async create(port: number, vpnConn?: vpnExtension.VpnConnection): Promise<number> {
    if (!NativeSocket.mod) {
      try {
        NativeSocket.mod = requireNapi('udp_socket') as NativeUdpModule;
        hilog.info(DOMAIN, TAG, '原生模块加载成功');
      } catch (e) {
        const errStr: string = JSON.stringify(e);
        hilog.error(DOMAIN, TAG, 'requireNapi 失败: %{public}s', errStr);
        throw new Error('原生模块不可用');
      }
    }

    NativeSocket.fd = NativeSocket.mod.createUdpSocket();
    if (NativeSocket.fd < 0) {
      throw new Error('createUdpSocket 失败');
    }
    hilog.info(DOMAIN, TAG, 'Socket 创建成功 fd=%{public}d', NativeSocket.fd);

    if (vpnConn) {
      try {
        await vpnConn.protect(NativeSocket.fd);
        hilog.info(DOMAIN, TAG, '✅ protect(fd=%{public}d) 成功', NativeSocket.fd);
      } catch (e) {
        const errStr: string = JSON.stringify(e);
        hilog.error(DOMAIN, TAG, '❌ protect(fd) 失败: %{public}s', errStr);
        NativeSocket.close();
        throw new Error('protect(fd) failed');
      }
    }

    try {
      NativeSocket.mod.udpBind(NativeSocket.fd, port);
      const actualPort: number = NativeSocket.mod.getLocalPort(NativeSocket.fd);
      hilog.info(DOMAIN, TAG, 'Socket 绑定到端口 %{public}d', actualPort);
      return actualPort;
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'bind 失败: %{public}s', JSON.stringify(e));
      NativeSocket.close();
      throw e;
    }
  }

  /** 发送数据 */
  static sendTo(data: Uint8Array, host: string, port: number): boolean {
    if (!NativeSocket.mod || NativeSocket.fd < 0) return false;
    try {
      const buf: ArrayBuffer = data.buffer.slice(0, data.byteLength) as ArrayBuffer;
      const sent: number = NativeSocket.mod.udpSendTo(NativeSocket.fd, buf, host, port);
      return sent > 0;
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'sendTo 失败: %{public}s', JSON.stringify(e));
      return false;
    }
  }

  /** 接收数据 */
  static recvFrom(timeoutMs: number): RecvResult | null {
    if (!NativeSocket.mod || NativeSocket.fd < 0) return null;
    try {
      const result: NativeRecvResult | null = NativeSocket.mod.udpRecvFrom(NativeSocket.fd, 65535, timeoutMs);
      if (result === null) return null;
      const r: RecvResult = new RecvResult();
      r.data = new Uint8Array(result.data);
      r.fromAddress = result.from.address;
      r.fromPort = result.from.port;
      return r;
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'recvFrom 失败: %{public}s', JSON.stringify(e));
      return null;
    }
  }

  /** 关闭 */
  static close(): void {
    if (NativeSocket.mod && NativeSocket.fd >= 0) {
      NativeSocket.mod.closeUdpSocket(NativeSocket.fd);
    }
    NativeSocket.fd = -1;
  }

  static isAvailable(): boolean {
    return NativeSocket.mod !== null && NativeSocket.fd >= 0;
  }
}
