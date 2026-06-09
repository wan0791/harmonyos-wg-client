/**
 * WireGuard Noise IKpsk2 握手状态机
 *
 * 参考：https://www.wireguard.com/protocol/
 * 实现了 Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s_BLAKE2s
 *
 * 流程：
 *   客户端（发起者）                        服务端（响应者）
 *   ← s (static public key)
 *   → e, es, s, ss, t  (Initiation)
 *   ← e, ee, se        (Response)
 *   之后双方均可发送 Transport Data
 */

import { blake2s256 } from '../crypto/Blake2s';
import { kdf2 } from '../crypto/HKDF';
import { generateX25519KeyPair, X25519KeyPairResult, x25519DH } from '../crypto/X25519';
import { chacha20Poly1305Encrypt, chacha20Poly1305Decrypt } from '../crypto/ChaCha20Poly1305';
import { HASH_LEN, KEY_LEN, LABEL_MAC1, LABEL_COOKIE, stringToBytes } from '../Constants';

/** WireGuard 协议构造字符串 */
const CONSTRUCTION: string = 'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s_BLAKE2s';
const IDENTIFIER: string = 'WireGuard v1 zx2c4 Jason@zx2c4.com';

/** 消息类型 */
const MSG_TYPE_INITIATION: number = 1;
const MSG_TYPE_RESPONSE: number = 2;

/** 握手状态 */
export enum HandshakeState {
  /** 初始状态，等待发起握手 */
  INITIATION = 0,
  /** 已发送 Initiation，等待 Response */
  WAITING_RESPONSE = 1,
  /** 已收到 Response，握手完成 */
  COMPLETE = 2,
  /** 握手失败 */
  FAILED = 3,
}

/** 握手结果：会话密钥 */
export class SessionKey {
  /** 发送加密密钥 */
  sendKey: Uint8Array = new Uint8Array(32);
  /** 接收加密密钥 */
  recvKey: Uint8Array = new Uint8Array(32);
  /** 发送计数器 */
  sendCounter: number = 0;
  /** 接收计数器 */
  recvCounter: number = 0;
}

/**
 * Noise IK 握手状态机
 */
export class NoiseHandshake {
  // ── 配置 ──
  localStaticPrivate: Uint8Array = new Uint8Array(32);
  localStaticPublic: Uint8Array = new Uint8Array(32);
  remoteStaticPublic: Uint8Array = new Uint8Array(32);

  // ── 握手状态 ──
  state: HandshakeState = HandshakeState.INITIATION;
  chainingKey: Uint8Array = new Uint8Array(32);
  hash: Uint8Array = new Uint8Array(32);
  ephemeralPrivate: Uint8Array = new Uint8Array(32);
  ephemeralPublic: Uint8Array = new Uint8Array(32);
  localIndex: number = 0;
  remoteIndex: number = 0;

  // ── 会话密钥 ──
  sessionKeys: SessionKey | null = null;

  /** 初始化握手上下文 */
  init(localPriv: Uint8Array, localPub: Uint8Array, remotePub: Uint8Array): void {
    this.localStaticPrivate = localPriv;
    this.localStaticPublic = localPub;
    this.remoteStaticPublic = remotePub;

    // Noise IK 初始化哈希
    const constructionBytes: Uint8Array = stringToBytes(CONSTRUCTION);
    this.chainingKey = blake2s256(constructionBytes);
    this.hash = blake2s256(concatBytes(this.chainingKey, stringToBytes(IDENTIFIER)));

    // ← s：接收服务端公钥
    this.hash = blake2s256(concatBytes(this.hash, remotePub));

    this.state = HandshakeState.INITIATION;
  }

  /**
   * 构建 Initiation 消息（Type = 1）
   * @returns 完整的 Initiation 消息字节数组
   */
  buildInitiation(): Uint8Array {
    // → e：生成临时密钥对
    const ephemeralKeyPair = x25519DH_generate();
    this.ephemeralPrivate = ephemeralKeyPair.privateKey;
    this.ephemeralPublic = ephemeralKeyPair.publicKey;

    this.hash = blake2s256(concatBytes(this.hash, this.ephemeralPublic));

    // → es：DH(ephemeral, remote_static)
    const dhES: Uint8Array = x25519DH(this.ephemeralPrivate, this.remoteStaticPublic);
    const kdfES: Uint8Array[] = kdf2(this.chainingKey, dhES);
    this.chainingKey = kdfES[0];
    const keyES: Uint8Array = kdfES[1];

    // → s：加密本地静态公钥
    const encryptedStatic: Uint8Array = aeadEncrypt(keyES, 0, this.localStaticPublic, this.hash);
    this.hash = blake2s256(concatBytes(this.hash, encryptedStatic));

    // → ss：DH(static_private, remote_static)
    const dhSS: Uint8Array = x25519DH(this.localStaticPrivate, this.remoteStaticPublic);
    const kdfSS: Uint8Array[] = kdf2(this.chainingKey, dhSS);
    this.chainingKey = kdfSS[0];
    const keySS: Uint8Array = kdfSS[1];

    // → t：加密时间戳
    const timestamp: Uint8Array = timestampBytes();
    const encryptedTimestamp: Uint8Array = aeadEncrypt(keySS, 0, timestamp, this.hash);
    this.hash = blake2s256(concatBytes(this.hash, encryptedTimestamp));

    // 分配本地索引
    this.localIndex = randomU32();

    // 构建消息体
    const msg: Uint8Array = new Uint8Array(4 + 4 + 4 + 32 + encryptedStatic.length + encryptedTimestamp.length + 16 + 16);
    let off: number = 0;
    off = writeU32(msg, off, MSG_TYPE_INITIATION);
    off = writeU32(msg, off, 0); // reserved
    off = writeU32(msg, off, this.localIndex);
    off = writeBytes(msg, off, this.ephemeralPublic);
    off = writeBytes(msg, off, encryptedStatic);
    off = writeBytes(msg, off, encryptedTimestamp);

    // mac1：BLAKE2s(ck || "mac1----") 和 BLAKE2s(mac1_key || msg)[:16] — 非密钥模式
    const mac1Key: Uint8Array = blake2s256(concatBytes(this.chainingKey, stringToBytes(LABEL_MAC1)));
    const mac1Input: Uint8Array = msg.subarray(0, off);
    const mac1: Uint8Array = blake2s256(concatBytes(mac1Key, mac1Input)).subarray(0, 16);
    off = writeBytes(msg, off, mac1);

    // mac2：暂填 0（需要 cookie）
    off = writeBytes(msg, off, new Uint8Array(16));

    this.state = HandshakeState.WAITING_RESPONSE;
    return msg;
  }

  /**
   * 处理 Response 消息（Type = 2）
   * @param data 完整的 Response 消息
   * @returns true 表示握手成功
   */
  processResponse(data: Uint8Array): boolean {
    if (this.state !== HandshakeState.WAITING_RESPONSE) {
      return false;
    }

    try {
      let off: number = 0;
      const msgType: number = readU32(data, off); off += 4;
      if (msgType !== MSG_TYPE_RESPONSE) return false;

      off += 4; // reserved
      this.remoteIndex = readU32(data, off); off += 4;
      const remoteEphemeral: Uint8Array = data.subarray(off, off + 32); off += 32;

      // ← e
      this.hash = blake2s256(concatBytes(this.hash, remoteEphemeral));

      // ← ee：DH(ephemeral_private, remote_ephemeral)
      const dhEE: Uint8Array = x25519DH(this.ephemeralPrivate, remoteEphemeral);
      const kdfEE: Uint8Array[] = kdf2(this.chainingKey, dhEE);
      this.chainingKey = kdfEE[0];
      const keyEE: Uint8Array = kdfEE[1];

      // ← se：DH(static_private, remote_ephemeral)
      const dhSE: Uint8Array = x25519DH(this.localStaticPrivate, remoteEphemeral);
      const kdfSE: Uint8Array[] = kdf2(this.chainingKey, dhSE);
      this.chainingKey = kdfSE[0];
      const keySE: Uint8Array = kdfSE[1];

      // ← empty (AEAD 认证空数据)
      const encryptedNothing: Uint8Array = data.subarray(off, off + 16); off += 16;
      const decryptedResult: Uint8Array | null = aeadDecrypt(keySE, 0, encryptedNothing, this.hash);
      if (decryptedResult === null || decryptedResult.length !== 0) {
        return false;
      }
      this.hash = blake2s256(concatBytes(this.hash, encryptedNothing));

      // 派生会话密钥
      const kdfKeys: Uint8Array[] = kdf2(this.chainingKey, new Uint8Array(0));

      this.sessionKeys = new SessionKey();
      this.sessionKeys.sendKey = kdfKeys[0];
      this.sessionKeys.recvKey = kdfKeys[1];
      this.sessionKeys.sendCounter = 0;
      this.sessionKeys.recvCounter = 0;

      this.state = HandshakeState.COMPLETE;
      return true;
    } catch (e) {
      this.state = HandshakeState.FAILED;
      return false;
    }
  }

  /** 握手是否完成 */
  isComplete(): boolean {
    return this.state === HandshakeState.COMPLETE;
  }
}

// ── 工具函数 ──

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const r: Uint8Array = new Uint8Array(a.length + b.length);
  for (let i = 0; i < a.length; i++) r[i] = a[i];
  for (let i = 0; i < b.length; i++) r[a.length + i] = b[i];
  return r;
}

function writeU32(buf: Uint8Array, off: number, val: number): number {
  buf[off] = val & 0xFF;
  buf[off + 1] = (val >>> 8) & 0xFF;
  buf[off + 2] = (val >>> 16) & 0xFF;
  buf[off + 3] = (val >>> 24) & 0xFF;
  return off + 4;
}

function readU32(buf: Uint8Array, off: number): number {
  return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
}

function writeBytes(buf: Uint8Array, off: number, data: Uint8Array): number {
  for (let i = 0; i < data.length; i++) buf[off + i] = data[i];
  return off + data.length;
}

function randomU32(): number {
  const buf: Uint8Array = new Uint8Array(4);
  // 使用 CryptoArchitectureKit 的随机数生成器
  // 简化为 Math.random
  return (Math.random() * 0xFFFFFFFF) >>> 0;
}

/**
 * 生成临时 X25519 密钥对
 */
function x25519DH_generate(): X25519KeyPairResult {
  return generateX25519KeyPair();
}

/**
 * HKDF 输出 2 个密钥（WireGuard 常用模式，委托给 HKDF.ets 的 kdf2）
 * 注意：WireGuard 使用 BLAKE2s 密钥模式替代 HMAC
 */

/**
 * AEAD 加密（ChaCha20Poly1305，WireGuard 固定 nonce = 大端序计数器）
 */
function aeadEncrypt(key: Uint8Array, counter: number, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  const nonce: Uint8Array = new Uint8Array(12);
  // WireGuard 使用计数器作为 nonce 的前 4 字节（大端序）
  nonce[0] = (counter >>> 24) & 0xFF;
  nonce[1] = (counter >>> 16) & 0xFF;
  nonce[2] = (counter >>> 8) & 0xFF;
  nonce[3] = counter & 0xFF;

  const result = chacha20Poly1305Encrypt(key, nonce, plaintext, aad);
  // 返回 ciphertext || tag（与 WireGuard 格式一致）
  return concatBytes(result.ciphertext, result.tag);
}

/**
 * AEAD 解密
 */
function aeadDecrypt(key: Uint8Array, counter: number, ciphertextWithTag: Uint8Array, aad: Uint8Array): Uint8Array | null {
  const nonce: Uint8Array = new Uint8Array(12);
  nonce[0] = (counter >>> 24) & 0xFF;
  nonce[1] = (counter >>> 16) & 0xFF;
  nonce[2] = (counter >>> 8) & 0xFF;
  nonce[3] = counter & 0xFF;

  try {
    return chacha20Poly1305Decrypt(key, nonce, ciphertextWithTag, aad);
  } catch (e) {
    return null;
  }
}

/**
 * 生成当前时间的 Tai64n 时间戳（WireGuard 格式）
 */
function timestampBytes(): Uint8Array {
  // Tai64n 格式：12 字节
  // 前 8 字节：Tai64n 纪元偏移 (2^62)
  // 后 4 字节：纳秒
  const now: number = Date.now();
  const tai64n: bigint = BigInt(Math.floor(now / 1000)) + 4611686018427387904n; // 2^62 + unix seconds
  const nanos: number = (now % 1000) * 1000000;

  const buf: Uint8Array = new Uint8Array(8);
  // WireGuard 使用 8 字节 TAI64 时间戳（不含纳秒）
  for (let i = 0; i < 8; i++) {
    buf[i] = Number((tai64n >> BigInt((7 - i) * 8)) & 0xFFn);
  }
  return buf;
}

export { concatBytes, writeU32, readU32, writeBytes, randomU32 };
