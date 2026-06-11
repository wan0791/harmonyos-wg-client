/**
 * 原生 UDP Socket（NAPI C 模块 + pthread 收包线程）
 *
 * 使用 CMake 编译的 libudp_socket.so：
 *   - createUdpSocket(): 创建 socket，返回 fd
 *   - udpSendTo(): 发送 UDP 数据
 *   - startRecvThread(fd, callback): 启动 pthread 收包线程，收到数据时回调
 *   - stopRecvThread(): 停止收包线程
 */

import nativeModule from 'libudp_socket.so';

export class NativeSocket {
  private fd: number = -1;

  create(): number {
    this.fd = nativeModule.createUdpSocket();
    return this.fd;
  }

  getFd(): number { return this.fd; }

  /** 发送数据，返回发送字节数 */
  sendTo(data: ArrayBuffer, host: string, port: number): number {
    if (this.fd < 0) return -1;
    return nativeModule.udpSendTo(this.fd, data, host, port);
  }

  /** 启动收包线程。onData: (data: ArrayBuffer, fromIP: string, fromPort: number) => void */
  startRecvThread(onData: (data: ArrayBuffer, ip: string, port: number) => void): boolean {
    if (this.fd < 0) return false;
    return nativeModule.startRecvThread(this.fd, onData) as boolean;
  }

  /** 停止收包线程 */
  stopRecvThread(): void {
    if (this.fd >= 0) {
      nativeModule.stopRecvThread();
    }
  }

  close(): void {
    this.stopRecvThread();
    if (this.fd >= 0) {
      nativeModule.closeUdpSocket(this.fd);
      this.fd = -1;
    }
  }
}
