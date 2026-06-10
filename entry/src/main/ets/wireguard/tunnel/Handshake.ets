/**
 * WireGuard Noise IKpsk2 握手状态机
 *
 * 严格匹配 wireguard-go 实现：
 *   - KDF 使用 HMAC-BLAKE2s（非 BLAKE2s keyed mode）
 *   - Initiation 阶段不混合 PSK
 *   - Response 阶段用 mixKey(one-step KDF1) 处理 ee/se
 *   - PSK 在 Response 中用 KDF3 混合
 *
 * 流程：
 *   客户端（发起者）                         服务端（响应者）
 *   ← s (static public key) 预消息
 *   → e, es, s, ss, t         Initiation
 *   ← e, ee, se, psk          Response
 *   之后双方均可发送 Transport Data
 */

import { blake2s256 } from '../crypto/Blake2s';
import { kdf1, kdf2, kdf3, hmacBlake2s } from '../crypto/HKDF';
import { generateX25519KeyPair, X25519KeyPairResult, x25519DH } from '../crypto/X25519';
import { chacha20Poly1305Encrypt, chacha20Poly1305Decrypt } from '../crypto/ChaCha20Poly1305';
import { HASH_LEN, KEY_LEN, LABEL_MAC1, LABEL_COOKIE, stringToBytes } from '../Constants';
import { hilog } from '@kit.PerformanceAnalysisKit';

const DOMAIN = 0x0000;
const TAG = 'WgHs';

/** WireGuard 协议构造字符串 */
const CONSTRUCTION: string = 'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s';
const IDENTIFIER: string = 'WireGuard v1 zx2c4 Jason@zx2c4.com';

/** 消息类型 */
const MSG_TYPE_INITIATION: number = 1;
const MSG_TYPE_RESPONSE: number = 2;

/** 握手状态 */
export enum HandshakeState {
  INITIATION = 0,
  WAITING_RESPONSE = 1,
  COMPLETE = 2,
  FAILED = 3,
}

/** 会话密钥 */
export class SessionKey {
  sendKey: Uint8Array = new Uint8Array(32);
  recvKey: Uint8Array = new Uint8Array(32);
  sendCounter: number = 0;
  recvCounter: number = 0;
}

/**
 * Noise IKpsk2 握手状态机（匹配 wireguard-go）
 */
export class NoiseHandshake {
  // ── 配置 ──
  localStaticPrivate: Uint8Array = new Uint8Array(32);
  localStaticPublic: Uint8Array = new Uint8Array(32);
  remoteStaticPublic: Uint8Array = new Uint8Array(32);
  presharedKey: Uint8Array = new Uint8Array(32); // 默认全零

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

  setPresharedKey(psk: Uint8Array): void {
    if (psk.length === 32) {
      this.presharedKey = psk;
    }
  }

  /** 初始化握手上下文 */
  init(localPriv: Uint8Array, localPub: Uint8Array, remotePub: Uint8Array): void {
    this.localStaticPrivate = localPriv;
    this.localStaticPublic = localPub;
    this.remoteStaticPublic = remotePub;

    // wireguard-go init():
    //   InitialChainKey = blake2s.Sum256(NoiseConstruction)
    //   mixHash(&InitialHash, &InitialChainKey, WGIdentifier)
    this.chainingKey = blake2s256(stringToBytes(CONSTRUCTION));
    this.hash = blake2s256(concatBytes(this.chainingKey, stringToBytes(IDENTIFIER)));

    // CreateInitiation: handshake.hash = InitialHash; handshake.chainKey = InitialChainKey
    // handshake.mixHash(handshake.remoteStatic[:])
    this.hash = blake2s256(concatBytes(this.hash, remotePub));
    dh_log('ck_init', this.chainingKey);
    dh_log('hash_after_id', this.hash);

    this.state = HandshakeState.INITIATION;
  }

  /**
   * 构建 Initiation 消息（Type = 1）
   * 严格匹配 wireguard-go CreateMessageInitiation
   */
  buildInitiation(): Uint8Array {
    // → e：生成临时密钥对
    const ephemeralKeyPair: X25519KeyPairResult = x25519DH_generate();
    this.ephemeralPrivate = ephemeralKeyPair.privateKey;
    this.ephemeralPublic = ephemeralKeyPair.publicKey;
    dh_log('e_pub', this.ephemeralPublic);

    // wireguard-go:
    //   handshake.mixKey(msg.Ephemeral[:])
    //   handshake.mixHash(msg.Ephemeral[:])
    this.chainingKey = mixKey(this.chainingKey, this.ephemeralPublic);
    this.hash = mixHash(this.hash, this.ephemeralPublic);
    dh_log('ck_after_mixKey_e', this.chainingKey);
    dh_log('hash_after_e', this.hash);

    // → es：KDF2(ck, DH(e_priv, s_pub))
    const dhES: Uint8Array = x25519DH(this.ephemeralPrivate, this.remoteStaticPublic);
    dh_log('dh_es', dhES);
    const kdfES: Uint8Array[] = kdf2(this.chainingKey, dhES);
    this.chainingKey = kdfES[0];
    const keyES: Uint8Array = kdfES[1];
    dh_log('ck_after_es', this.chainingKey);
    dh_log('key_es', keyES);

    // → s：加密本地静态公钥
    const encryptedStatic: Uint8Array = aeadEncrypt(keyES, 0, this.localStaticPublic, this.hash);
    dh_log('enc_static', encryptedStatic);
    this.hash = mixHash(this.hash, encryptedStatic);
    dh_log('hash_after_s', this.hash);

    // → ss：WireGuard 使用预计算的 static-static DH
    // 这里直接计算 DH(local_static_priv, remote_static_pub)
    const dhSS: Uint8Array = x25519DH(this.localStaticPrivate, this.remoteStaticPublic);
    dh_log('dh_ss', dhSS);
    const kdfSS: Uint8Array[] = kdf2(this.chainingKey, dhSS);
    this.chainingKey = kdfSS[0];
    let keySS: Uint8Array = kdfSS[1];
    dh_log('ck_after_ss', this.chainingKey);
    dh_log('key_ss', keySS);

    // 注意：wireguard-go 在 Initiation 中不混合 PSK！
    // PSK 只在 Response 阶段（CreateResponse/ConsumeResponse）混合

    // → t：加密时间戳
    const timestamp: Uint8Array = timestampBytes();
    dh_log('timestamp', timestamp);
    const encryptedTimestamp: Uint8Array = aeadEncrypt(keySS, 0, timestamp, this.hash);
    dh_log('enc_ts', encryptedTimestamp);
    this.hash = mixHash(this.hash, encryptedTimestamp);
    dh_log('hash_final', this.hash);

    // 分配本地索引
    this.localIndex = randomU32();

    // 构建消息
    const msg: Uint8Array = new Uint8Array(148);
    let off: number = 0;
    off = writeU32(msg, off, MSG_TYPE_INITIATION);
    off = writeU32(msg, off, this.localIndex);
    off = writeBytes(msg, off, this.ephemeralPublic);
    off = writeBytes(msg, off, encryptedStatic);
    off = writeBytes(msg, off, encryptedTimestamp);

    // MAC1 (CookieChecker style: key = BLAKE2s("mac1----" || server_pub))
    const mac1Key: Uint8Array = blake2s256(concatBytes(stringToBytes(LABEL_MAC1), this.remoteStaticPublic));
    const mac1Input: Uint8Array = msg.subarray(0, off);
    const mac1: Uint8Array = blake2s256(mac1Input, mac1Key).subarray(0, 16);
    dh_log('mac1', mac1);
    off = writeBytes(msg, off, mac1);

    // MAC2：暂填 0
    off = writeBytes(msg, off, new Uint8Array(16));

    this.state = HandshakeState.WAITING_RESPONSE;
    return msg;
  }

  /**
   * 处理 Response 消息（Type = 2）
   * 严格匹配 wireguard-go ConsumeMessageResponse
   */
  processResponse(data: Uint8Array): boolean {
    if (this.state !== HandshakeState.WAITING_RESPONSE) {
      return false;
    }

    try {
      let off: number = 0;
      const msgType: number = readU32(data, off); off += 4;
      if (msgType !== MSG_TYPE_RESPONSE) return false;

      const senderIdx: number = readU32(data, off); off += 4;
      this.remoteIndex = senderIdx;
      const receiverIdx: number = readU32(data, off); off += 4;
      const remoteEphemeral: Uint8Array = data.subarray(off, off + 32); off += 32;

      // wireguard-go ConsumeResponse:
      //   mixHash(&hash, &handshake.hash, msg.Ephemeral[:])
      //   mixKey(&chainKey, &handshake.chainKey, msg.Ephemeral[:])
      dh_log('e_r_pub', remoteEphemeral);
      this.hash = mixHash(this.hash, remoteEphemeral);
      this.chainingKey = mixKey(this.chainingKey, remoteEphemeral);

      // ← ee：mixKey(DH(e_i, e_r))
      const dhEE: Uint8Array = x25519DH(this.ephemeralPrivate, remoteEphemeral);
      dh_log('dh_ee', dhEE);
      this.chainingKey = mixKey(this.chainingKey, dhEE);
      dh_log('ck_after_ee', this.chainingKey);

      // ← se：mixKey(DH(s_i, e_r))
      const dhSE: Uint8Array = x25519DH(this.localStaticPrivate, remoteEphemeral);
      dh_log('dh_se', dhSE);
      this.chainingKey = mixKey(this.chainingKey, dhSE);
      dh_log('ck_after_se', this.chainingKey);

      // ← PSK：KDF3(ck, psk) → ck, tau, key
      const pskIsZero: boolean = this.presharedKey.every((b: number): boolean => b === 0);
      let keySE: Uint8Array;
      if (!pskIsZero) {
        dh_log('psk', this.presharedKey);
        const pskKdf: Uint8Array[] = kdf3(this.chainingKey, this.presharedKey);
        this.chainingKey = pskKdf[0];
        const tau: Uint8Array = pskKdf[1];
        keySE = pskKdf[2];
        this.hash = mixHash(this.hash, tau);
        dh_log('ck_after_psk', this.chainingKey);
        dh_log('tau', tau);
        dh_log('key_psk', keySE);
        dh_log('hash_after_psk', this.hash);
      } else {
        // 无 PSK：用 KDF2 从 chainKey 派生 key
        const kdfSE: Uint8Array[] = kdf2(this.chainingKey, new Uint8Array(0));
        this.chainingKey = kdfSE[0];
        keySE = kdfSE[1];
      }

      // ← empty：AEAD 解密空数据
      const encryptedNothing: Uint8Array = data.subarray(off, off + 16); off += 16;
      const decryptedResult: Uint8Array | null = aeadDecrypt(keySE, 0, encryptedNothing, this.hash);
      if (decryptedResult === null || decryptedResult.length !== 0) {
        dh_log('empty_decrypt_fail', new Uint8Array(0));
        return false;
      }
      this.hash = mixHash(this.hash, encryptedNothing);
      dh_log('hash_final_resp', this.hash);

      // 派生会话密钥：KDF2(ck, empty)
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

  isComplete(): boolean {
    return this.state === HandshakeState.COMPLETE;
  }
}

// ── 调试日志 ──

const hexChars: string = '0123456789abcdef';

function bytesToHex(b: Uint8Array): string {
  let r: string = '';
  for (let i = 0; i < b.length; i++) {
    r += hexChars[(b[i] >> 4) & 0xF] + hexChars[b[i] & 0xF];
  }
  return r;
}

function dh_log(label: string, data: Uint8Array): void {
  const max: number = data.length > 64 ? 64 : data.length;
  hilog.info(DOMAIN, TAG, 'DBG %{public}s[%{public}d]=%{public}s',
    label, data.length, bytesToHex(data.subarray(0, max)));
}

// ── WireGuard 核心工具函数 ──

/** mixHash: hash = BLAKE2s(hash || data) */
function mixHash(hash: Uint8Array, data: Uint8Array): Uint8Array {
  return blake2s256(concatBytes(hash, data));
}

/** mixKey: chainKey = KDF1(chainKey, data) */
function mixKey(ck: Uint8Array, data: Uint8Array): Uint8Array {
  return kdf1(ck, data);
}

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
  return (Math.random() * 0xFFFFFFFF) >>> 0;
}

function x25519DH_generate(): X25519KeyPairResult {
  return generateX25519KeyPair();
}

/** AEAD 加密（ChaCha20Poly1305，WireGuard 固定 nonce = 大端序计数器 + 8零字节） */
function aeadEncrypt(key: Uint8Array, counter: number, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  const nonce: Uint8Array = new Uint8Array(12);
  nonce[0] = (counter >>> 24) & 0xFF;
  nonce[1] = (counter >>> 16) & 0xFF;
  nonce[2] = (counter >>> 8) & 0xFF;
  nonce[3] = counter & 0xFF;
  const result = chacha20Poly1305Encrypt(key, nonce, plaintext, aad);
  return concatBytes(result.ciphertext, result.tag);
}

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

/** TAI64N 时间戳 */
function timestampBytes(): Uint8Array {
  const now: number = Date.now();
  const tai64n: bigint = BigInt(Math.floor(now / 1000)) + 4611686018427387904n;
  const nanos: number = (now % 1000) * 1000000;
  const buf: Uint8Array = new Uint8Array(12);
  for (let i = 0; i < 8; i++) {
    buf[i] = Number((tai64n >> BigInt((7 - i) * 8)) & 0xFFn);
  }
  for (let i = 0; i < 4; i++) {
    buf[8 + i] = Number((BigInt(nanos) >> BigInt((3 - i) * 8)) & 0xFFn);
  }
  return buf;
}

export { concatBytes, writeU32, readU32, writeBytes, randomU32, mixHash, mixKey };
