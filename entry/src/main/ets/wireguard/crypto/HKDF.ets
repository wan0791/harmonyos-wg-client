/**
 * WireGuard HKDF 实现
 *
 * 注意：WireGuard 不使用标准 HMAC，而是使用 BLAKE2s 密钥模式
 * 作为其伪随机函数（PRF），替代了标准 HKDF 中的 HMAC。
 *
 * 参考 wireguard-go 的 kdf() 实现
 */

import { blake2s256 } from './Blake2s';

/** 连接两个 Uint8Array */
function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const r: Uint8Array = new Uint8Array(a.length + b.length);
  for (let i = 0; i < a.length; i++) r[i] = a[i];
  for (let i = 0; i < b.length; i++) r[a.length + i] = b[i];
  return r;
}

/**
 * WireGuard KDF1：输出 1 个密钥
 * PRK = BLAKE2s(key, input)  // keyed mode
 * t0 = BLAKE2s(PRK, 0x01)    // expand step 1
 */
export function kdf1(key: Uint8Array, input: Uint8Array): Uint8Array {
  const prk: Uint8Array = blake2s256(input, key); // BLAKE2s keyed: MAC(key, input)
  const t0: Uint8Array = blake2s256(new Uint8Array([0x01]), prk); // BLAKE2s keyed: MAC(PRK, 0x01)
  return t0;
}

/**
 * WireGuard KDF2：输出 2 个密钥
 */
export function kdf2(key: Uint8Array, input: Uint8Array): Uint8Array[] {
  const prk: Uint8Array = blake2s256(input, key);
  const t0: Uint8Array = blake2s256(new Uint8Array([0x01]), prk);
  const t1Input: Uint8Array = concatBytes(t0, new Uint8Array([0x02]));
  const t1: Uint8Array = blake2s256(t1Input, prk);
  return [t0, t1];
}

/**
 * WireGuard KDF3：输出 3 个密钥
 */
export function kdf3(key: Uint8Array, input: Uint8Array): Uint8Array[] {
  const prk: Uint8Array = blake2s256(input, key);
  const t0: Uint8Array = blake2s256(new Uint8Array([0x01]), prk);
  const t1Input: Uint8Array = concatBytes(t0, new Uint8Array([0x02]));
  const t1: Uint8Array = blake2s256(t1Input, prk);
  const t2Input: Uint8Array = concatBytes(t1, new Uint8Array([0x03]));
  const t2: Uint8Array = blake2s256(t2Input, prk);
  return [t0, t1, t2];
}

/**
 * 标准 HKDF 兼容接口（使用 BLAKE2s 密钥模式替代 HMAC）
 * 用于需要指定输出长度的场景
 */
export function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, okmLen: number): Uint8Array {
  // Extract: PRK = BLAKE2s(salt, IKM)
  const prk: Uint8Array = blake2s256(ikm, salt);

  // Expand: 逐步生成输出
  const result: Uint8Array = new Uint8Array(okmLen);
  let t: Uint8Array = new Uint8Array(0);
  let pos: number = 0;

  for (let i: number = 1; pos < okmLen; i++) {
    const input: Uint8Array = concatBytes(t, info);
    const counter: Uint8Array = new Uint8Array(1);
    counter[0] = i;
    t = blake2s256(concatBytes(input, counter), prk);
    for (let j = 0; j < t.length && pos < okmLen; j++, pos++) {
      result[pos] = t[j];
    }
  }

  return result;
}
