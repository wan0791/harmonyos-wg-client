/**
 * WireGuard 协议常量
 *
 * 参考：https://www.wireguard.com/protocol/
 */

// ── 版本 ──
export const WG_VERSION: number = 1;

// ── 消息类型 ──
export const MSG_TYPE_INITIATION: number = 1;    // 握手发起
export const MSG_TYPE_RESPONSE: number = 2;      // 握手响应
export const MSG_TYPE_COOKIE_REPLY: number = 3;  // Cookie 回复
export const MSG_TYPE_TRANSPORT_DATA: number = 4;// 传输数据

// ── 密钥和哈希长度 ──
export const KEY_LEN: number = 32;              // 256-bit 密钥
export const HASH_LEN: number = 32;             // BLAKE2s-256 哈希

// ── 消息体长度（不含 MAC 头）──
export const MSG_INITIATION_BODY_LEN: number = 148;  // 握手发起消息体
export const MSG_RESPONSE_BODY_LEN: number = 92;     // 握手响应消息体
export const MSG_COOKIE_REPLY_LEN: number = 64;      // Cookie 回复
export const DATA_PACKET_OVERHEAD: number = 32;       // 数据包额外开销（类型 + 接收者索引 + 计数器 + 标签）

// ── HMAC / HKDF 相关 ──
export const LABEL_MAC1: string = 'mac1----';
export const LABEL_COOKIE: string = 'cookie--';

// ── 构造标签 ──
export function stringToBytes(s: string): Uint8Array {
  const buf: Uint8Array = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) buf[i] = s.charCodeAt(i) & 0xFF;
  return buf;
}

export function hkdfLabel(prefix: string): Uint8Array {
  return stringToBytes(prefix);
}

// ── 连接超时 ──
export const HANDSHAKE_TIMEOUT_MS: number = 5000;    // 握手超时 5 秒
export const KEEPALIVE_INTERVAL_MS: number = 10000;  // 心跳间隔 10 秒
export const REKEY_AFTER_MS: number = 120000;        // 120 秒后重密钥
export const MAX_PEERS: number = 1;                  // 单 Peer（Step 2）

// ── TUN ──
export const DEFAULT_MTU: number = 1420;
export const MAX_DATA_PACKET_SIZE: number = DEFAULT_MTU + DATA_PACKET_OVERHEAD;
