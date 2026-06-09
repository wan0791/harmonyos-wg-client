/**
 * BLAKE2s 哈希实现（纯 ArkTS）
 * 参考：RFC 7693 — 使用 Array<number> 而非 Uint32Array 避免位运算问题
 */

const IV: number[] = [
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SIGMA: number[][] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

const BLOCK_SIZE: number = 64;

function rotr32(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function readU32LE(buf: Uint8Array, off: number): number {
  return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
}

class Blake2sState {
  h: number[] = [0, 0, 0, 0, 0, 0, 0, 0];
  t: number = 0; // total bytes in full blocks
  buf: Uint8Array = new Uint8Array(64);
  buflen: number = 0;
  outlen: number = 32;
  finalized: boolean = false;

  constructor(key?: Uint8Array) {
    const klen: number = key ? key.length : 0;
    this.outlen = 32;

    // 初始化参数
    for (let i = 0; i < 8; i++) {
      this.h[i] = IV[i];
    }
    // h[0] ^= 参数块：digest_len | (key_len<<8) | (1<<16) | (1<<24)
    this.h[0] = (this.h[0] ^ (this.outlen & 0xFF) ^ 0x01010000 ^ ((klen & 0xFF) << 8)) >>> 0;

    if (klen > 0 && key) {
      const keyBlock: Uint8Array = new Uint8Array(64);
      for (let i = 0; i < key.length; i++) keyBlock[i] = key[i];
      this.update(keyBlock);
    }
  }

  private compress(block: Uint8Array, last: boolean): void {
    const v: number[] = new Array(16);
    const m: number[] = new Array(16);

    // 加载消息
    for (let i = 0; i < 16; i++) {
      m[i] = readU32LE(block, i * 4);
    }

    // 初始化工作向量
    for (let i = 0; i < 8; i++) {
      v[i] = this.h[i];
      v[i + 8] = IV[i];
    }

    // 64 位计数器
    v[12] = (v[12] ^ (this.t & 0xFFFFFFFF)) >>> 0;
    v[13] = (v[13] ^ ((this.t / 0x100000000) >>> 0)) >>> 0;

    // 最后块标志
    if (last) {
      v[14] = (~v[14]) >>> 0;
    }

    // 10 轮
    for (let r = 0; r < 10; r++) {
      const s: number[] = SIGMA[r];

      // 列步骤
      this.G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
      this.G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
      this.G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
      this.G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

      // 对角步骤
      this.G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
      this.G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
      this.G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
      this.G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    // 更新状态
    for (let i = 0; i < 8; i++) {
      this.h[i] = (this.h[i] ^ v[i] ^ v[i + 8]) >>> 0;
    }
  }

  private G(v: number[], a: number, b: number, c: number, d: number, x: number, y: number): void {
    v[a] = (v[a] + v[b] + x) >>> 0;
    v[d] = rotr32(v[d] ^ v[a], 16);
    v[c] = (v[c] + v[d]) >>> 0;
    v[b] = rotr32(v[b] ^ v[c], 12);
    v[a] = (v[a] + v[b] + y) >>> 0;
    v[d] = rotr32(v[d] ^ v[a], 8);
    v[c] = (v[c] + v[d]) >>> 0;
    v[b] = rotr32(v[b] ^ v[c], 7);
  }

  update(data: Uint8Array): void {
    let off: number = 0;
    let rem: number = data.length;

    // 填充缓冲
    if (this.buflen > 0) {
      const fill: number = Math.min(64 - this.buflen, rem);
      for (let i = 0; i < fill; i++) this.buf[this.buflen + i] = data[off + i];
      this.buflen += fill;
      off += fill;
      rem -= fill;

      if (this.buflen === 64) {
        this.compress(this.buf, false);
        this.t += 64;
        this.buflen = 0;
      }
    }

    // 处理完整块
    while (rem >= 64) {
      const block: Uint8Array = data.subarray(off, off + 64);
      this.compress(block, false);
      this.t += 64;
      off += 64;
      rem -= 64;
    }

    // 剩余
    for (let i = 0; i < rem; i++) this.buf[this.buflen + i] = data[off + i];
    this.buflen += rem;
  }

  digest(): Uint8Array {
    if (this.finalized) return this._digest();

    // 末尾填充（t 加上末尾部分块——BLAKE2 规范要求 t=总消息长度）
    for (let i = this.buflen; i < 64; i++) this.buf[i] = 0;
    this.t += this.buflen;
    this.compress(this.buf, true);
    this.finalized = true;
    return this._digest();
  }

  private _digest(): Uint8Array {
    const out: Uint8Array = new Uint8Array(this.outlen);
    for (let i = 0; i < this.outlen; i += 4) {
      out[i] = this.h[i / 4] & 0xFF;
      out[i + 1] = (this.h[i / 4] >>> 8) & 0xFF;
      out[i + 2] = (this.h[i / 4] >>> 16) & 0xFF;
      out[i + 3] = (this.h[i / 4] >>> 24) & 0xFF;
    }
    return out;
  }
}

export function blake2s256(data: Uint8Array, key?: Uint8Array): Uint8Array {
  const ctx: Blake2sState = new Blake2sState(key);
  ctx.update(data);
  return ctx.digest();
}
