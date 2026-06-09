/**
 * ChaCha20Poly1305 AEAD 实现（纯 ArkTS）
 *
 * 实现 RFC 8439 定义的 ChaCha20-Poly1305 AEAD 构造：
 *   1. ChaCha20 流加密（256-bit 密钥，96-bit nonce）
 *   2. Poly1305 MAC 认证
 */

// ════════════════════════════════════════
// ChaCha20 核心
// ════════════════════════════════════════

/** 32 位循环左移 */
function rotl32(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/** ChaCha20 quarter round */
function quarterRound(state: number[], a: number, b: number, c: number, d: number): void {
  state[a] = (state[a] + state[b]) >>> 0; state[d] = rotl32(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0; state[b] = rotl32(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b]) >>> 0; state[d] = rotl32(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0; state[b] = rotl32(state[b] ^ state[c], 7);
}

/** 生成 ChaCha20 块（64 字节） */
function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  // 初始化状态：4 个常数 + 8 个密钥 + 2 个 counter + 3 个 nonce
  const s: number[] = [
    0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,  // "expand 32-byte k"
    readU32LE(key, 0), readU32LE(key, 4), readU32LE(key, 8), readU32LE(key, 12),
    readU32LE(key, 16), readU32LE(key, 20), readU32LE(key, 24), readU32LE(key, 28),
    counter,  // 32-bit block counter (RFC 8439)
    readU32LE(nonce, 0), readU32LE(nonce, 4), readU32LE(nonce, 8),
  ];

  const working: number[] = s.slice();

  // 20 轮（10 次双轮）
  for (let i = 0; i < 10; i++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }

  // 序列化
  const out: Uint8Array = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    writeU32LE(out, i * 4, (working[i] + s[i]) >>> 0);
  }
  return out;
}

/** ChaCha20 流加密（XOR） */
function chacha20Encrypt(key: Uint8Array, counter: number, nonce: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const out: Uint8Array = new Uint8Array(plaintext.length);
  let blockCount: number = counter;
  let offset: number = 0;

  while (offset < plaintext.length) {
    const keystream: Uint8Array = chacha20Block(key, blockCount, nonce);
    const chunkSize: number = Math.min(64, plaintext.length - offset);
    for (let i = 0; i < chunkSize; i++) {
      out[offset + i] = plaintext[offset + i] ^ keystream[i];
    }
    offset += chunkSize;
    blockCount++;
  }

  return out;
}

// ════════════════════════════════════════
// Poly1305 MAC
// ════════════════════════════════════════

const POLY1305_P: bigint = (1n << 130n) - 5n;

/** Poly1305 逐字节 clamp */
function polyClamp(r: Uint8Array): void {
  r[3] &= 15;    // 0x0F — 清高4位
  r[4] &= 252;   // 0xFC — 清低2位
  r[7] &= 15;
  r[8] &= 252;
  r[11] &= 15;
  r[12] &= 252;
  r[15] &= 15;
}

/** 小端序 16 字节 → bigint */
function le128(buf: Uint8Array): bigint {
  let r: bigint = 0n;
  for (let i = 15; i >= 0; i--) r = (r << 8n) | BigInt(buf[i]);
  return r;
}

/** Poly1305 MAC 计算 */
function poly1305Mac(key: Uint8Array, data: Uint8Array): Uint8Array {
  const rBytes: Uint8Array = key.subarray(0, 16);
  polyClamp(rBytes);
  const r: bigint = le128(rBytes);
  const s: bigint = le128(key.subarray(16, 32));

  let acc: bigint = 0n;
  const blockSize: number = 16;
  let off: number = 0;

  while (off < data.length) {
    const chunk: number = Math.min(blockSize, data.length - off);
    // 小端序加载块，在高位加 1（Poly1305 规范要求的高位标记）
    let n: bigint = 0n;
    for (let i = 0; i < chunk; i++) {
      n |= BigInt(data[off + i]) << BigInt(i * 8);
    }
    n |= (1n << BigInt(chunk * 8)); // 在最后一个数据字节之上加 1
    acc = (acc + n);
    acc = (acc * r) % POLY1305_P;
    off += blockSize;
  }

  // 加 s，模 2^128
  const TWO_128: bigint = (1n << 128n);
  acc = ((acc + s) % TWO_128);

  // 输出 16 字节（小端序）
  const out: Uint8Array = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = Number((acc >> BigInt(i * 8)) & 0xFFn);
  }
  return out;
}

// ════════════════════════════════════════
// AEAD 构造（RFC 8439 Section 2.8）
// ════════════════════════════════════════

/** ChaCha20Poly1305 加密结果 */
export class AeadEncryptResult {
  ciphertext: Uint8Array = new Uint8Array(0);
  tag: Uint8Array = new Uint8Array(16);
}

/**
 * ChaCha20Poly1305 AEAD 加密
 */
export function chacha20Poly1305Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): AeadEncryptResult {
  if (key.length !== 32) throw new Error('ChaCha20Poly1305: 密钥必须为 32 字节');
  if (nonce.length !== 12) throw new Error('ChaCha20Poly1305: nonce 必须为 12 字节');

  // 1. 生成 Poly1305 一次性密钥（从 ChaCha20 第一个块的 64 字节中取前 32 字节）
  const polyKeyBlock: Uint8Array = chacha20Block(key, 0, nonce);
  const polyKey: Uint8Array = polyKeyBlock.subarray(0, 32);

  // 2. 用 counter=1 开始加密明文
  const ciphertext: Uint8Array = chacha20Encrypt(key, 1, nonce, plaintext);

  // 3. 构造 Poly1305 输入（AAD || padding || ciphertext || padding || len(AAD) || len(ciphertext)）
  const aadPadding: number = (16 - (aad.length % 16)) % 16;
  const ctPadding: number = (16 - (ciphertext.length % 16)) % 16;
  const macData: Uint8Array = new Uint8Array(
    aad.length + aadPadding + ciphertext.length + ctPadding + 8 + 8
  );

  let off: number = 0;
  for (let i = 0; i < aad.length; i++) macData[off++] = aad[i];
  off += aadPadding;
  for (let i = 0; i < ciphertext.length; i++) macData[off++] = ciphertext[i];
  off += ctPadding;
  // 小端序 64 位长度
  writeU64LE(macData, off, BigInt(aad.length));
  writeU64LE(macData, off + 8, BigInt(ciphertext.length));

  // 4. 计算 MAC
  const tag: Uint8Array = poly1305Mac(polyKey, macData);

  const result: AeadEncryptResult = new AeadEncryptResult();
  result.ciphertext = ciphertext;
  result.tag = tag;
  return result;
}

/**
 * ChaCha20Poly1305 AEAD 解密
 */
export function chacha20Poly1305Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertextWithTag: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  if (key.length !== 32) throw new Error('ChaCha20Poly1305: 密钥必须为 32 字节');
  if (nonce.length !== 12) throw new Error('ChaCha20Poly1305: nonce 必须为 12 字节');

  if (ciphertextWithTag.length < 16) return null;

  const ctLen: number = ciphertextWithTag.length - 16;
  const ciphertext: Uint8Array = ciphertextWithTag.subarray(0, ctLen);
  const expectedTag: Uint8Array = ciphertextWithTag.subarray(ctLen);

  // 1. Poly1305 密钥
  const polyKeyBlock: Uint8Array = chacha20Block(key, 0, nonce);
  const polyKey: Uint8Array = polyKeyBlock.subarray(0, 32);

  // 2. 构造 MAC 输入
  const aadPadding: number = (16 - (aad.length % 16)) % 16;
  const ctPadding: number = (16 - (ciphertext.length % 16)) % 16;
  const macData: Uint8Array = new Uint8Array(
    aad.length + aadPadding + ciphertext.length + ctPadding + 8 + 8
  );

  let off: number = 0;
  for (let i = 0; i < aad.length; i++) macData[off++] = aad[i];
  off += aadPadding;
  for (let i = 0; i < ciphertext.length; i++) macData[off++] = ciphertext[i];
  off += ctPadding;
  writeU64LE(macData, off, BigInt(aad.length));
  writeU64LE(macData, off + 8, BigInt(ciphertext.length));

  // 3. 验证 MAC
  const computedTag: Uint8Array = poly1305Mac(polyKey, macData);
  if (!constantTimeEqual(computedTag, expectedTag)) {
    return null;
  }

  // 4. 解密
  return chacha20Encrypt(key, 1, nonce, ciphertext);
}

// ════════════════════════════════════════
// 工具函数
// ════════════════════════════════════════

function readU32LE(buf: Uint8Array, off: number): number {
  return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
}

function writeU32LE(buf: Uint8Array, off: number, val: number): void {
  buf[off] = val & 0xFF;
  buf[off + 1] = (val >>> 8) & 0xFF;
  buf[off + 2] = (val >>> 16) & 0xFF;
  buf[off + 3] = (val >>> 24) & 0xFF;
}

function writeU64LE(buf: Uint8Array, off: number, val: bigint): void {
  for (let i = 0; i < 8; i++) {
    buf[off + i] = Number((val >> BigInt(i * 8)) & 0xFFn);
  }
}

/** 常量时间比较 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff: number = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
