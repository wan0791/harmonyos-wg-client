/**
 * WireGuard HKDF — 使用 HMAC-BLAKE2s（非 BLAKE2s keyed mode！）
 *
 * WireGuard 的 KDF 基于 HMAC-BLAKE2s：
 *   HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
 * 其中 H = unkeyed BLAKE2s-256，block size = 64
 *
 * 参考 wireguard-go 的 noise-helpers.go
 */

import { blake2s256 } from './Blake2s';

const BLOCK_SIZE: number = 64;
const OPAD: number = 0x5c;
const IPAD: number = 0x36;

/** 连接两个 Uint8Array */
function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const r: Uint8Array = new Uint8Array(a.length + b.length);
  for (let i = 0; i < a.length; i++) r[i] = a[i];
  for (let i = 0; i < b.length; i++) r[a.length + i] = b[i];
  return r;
}

/**
 * HMAC-BLAKE2s-256
 * HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
 */
export function hmacBlake2s(key: Uint8Array, message: Uint8Array): Uint8Array {
  // Step 1: 规范化 key 到 block size
  let kPad: Uint8Array;
  if (key.length > BLOCK_SIZE) {
    // key 过长 → 先哈希
    const hashed: Uint8Array = blake2s256(key);
    kPad = new Uint8Array(BLOCK_SIZE);
    for (let i = 0; i < hashed.length; i++) kPad[i] = hashed[i];
  } else {
    kPad = new Uint8Array(BLOCK_SIZE);
    for (let i = 0; i < key.length; i++) kPad[i] = key[i];
  }

  // Step 2: 计算 inner = H((K' ⊕ ipad) || message)
  const innerKey: Uint8Array = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) innerKey[i] = kPad[i] ^ IPAD;
  const inner: Uint8Array = blake2s256(concatBytes(innerKey, message));

  // Step 3: 计算 outer = H((K' ⊕ opad) || inner)
  const outerKey: Uint8Array = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) outerKey[i] = kPad[i] ^ OPAD;
  return blake2s256(concatBytes(outerKey, inner));
}

/**
 * WireGuard KDF1：输出 1 个密钥
 * t0 = HMAC(HMAC(key, input), 0x01)
 */
export function kdf1(key: Uint8Array, input: Uint8Array): Uint8Array {
  const prk: Uint8Array = hmacBlake2s(key, input);
  return hmacBlake2s(prk, new Uint8Array([0x01]));
}

/**
 * WireGuard KDF2：输出 2 个密钥
 * prk = HMAC(key, input)
 * t0 = HMAC(prk, 0x01)
 * t1 = HMAC(prk, t0 || 0x02)
 */
export function kdf2(key: Uint8Array, input: Uint8Array): Uint8Array[] {
  const prk: Uint8Array = hmacBlake2s(key, input);
  const t0: Uint8Array = hmacBlake2s(prk, new Uint8Array([0x01]));
  const t1Input: Uint8Array = concatBytes(t0, new Uint8Array([0x02]));
  const t1: Uint8Array = hmacBlake2s(prk, t1Input);
  return [t0, t1];
}

/**
 * WireGuard KDF3：输出 3 个密钥
 */
export function kdf3(key: Uint8Array, input: Uint8Array): Uint8Array[] {
  const prk: Uint8Array = hmacBlake2s(key, input);
  const t0: Uint8Array = hmacBlake2s(prk, new Uint8Array([0x01]));
  const t1Input: Uint8Array = concatBytes(t0, new Uint8Array([0x02]));
  const t1: Uint8Array = hmacBlake2s(prk, t1Input);
  const t2Input: Uint8Array = concatBytes(t1, new Uint8Array([0x03]));
  const t2: Uint8Array = hmacBlake2s(prk, t2Input);
  return [t0, t1, t2];
}

/**
 * 标准 HKDF 兼容接口（HMAC-BLAKE2s）
 */
export function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, okmLen: number): Uint8Array {
  // Extract: PRK = HMAC(salt, IKM)
  const prk: Uint8Array = hmacBlake2s(salt, ikm);

  // Expand
  const result: Uint8Array = new Uint8Array(okmLen);
  let t: Uint8Array = new Uint8Array(0);
  let pos: number = 0;

  for (let i: number = 1; pos < okmLen; i++) {
    const input: Uint8Array = concatBytes(t, info);
    const counter: Uint8Array = new Uint8Array(1);
    counter[0] = i;
    t = hmacBlake2s(prk, concatBytes(input, counter));
    for (let j = 0; j < t.length && pos < okmLen; j++, pos++) {
      result[pos] = t[j];
    }
  }

  return result;
}
