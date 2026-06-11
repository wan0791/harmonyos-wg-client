/**
 * BLAKE2s-256 哈希实现（纯 ArkTS）
 *
 * 完全重写，直接基于 RFC 7693 伪代码实现
 * 参考 https://tools.ietf.org/html/rfc7693
 */

const IV: number[] = [
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SIGMA: number[][] = [
  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
  [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
  [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
  [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
  [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
  [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
  [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
  [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
  [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
  [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
];

function rotr32(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function bytesToHex(b: Uint8Array): string {
  const hex: string = '0123456789abcdef';
  let r: string = '';
  for (let i = 0; i < b.length; i++) r += hex[(b[i] >> 4) & 0xF] + hex[b[i] & 0xF];
  return r;
}

/**
 * BLAKE2s 上下文
 */
class B2sCtx {
  h: number[] = [0, 0, 0, 0, 0, 0, 0, 0];
  t0: number = 0;  // 低 32 位计数器
  t1: number = 0;  // 高 32 位计数器
  buf: Uint8Array = new Uint8Array(64);
  buflen: number = 0;

  constructor(outlen: number, key?: Uint8Array) {
    const klen: number = key ? key.length : 0;
    // 初始化参数块
    for (let i = 0; i < 8; i++) this.h[i] = IV[i];
    this.h[0] ^= (outlen & 0xFF) ^ ((klen & 0xFF) << 8) ^ 0x01010000;
    this.h[0] >>>= 0;
    // RFC 7693 Section 3.4: 密钥块必须作为独立 64 字节块压缩
    if (klen > 0 && key) {
      // Step 1: 将密钥放入缓冲区，零填充到 64 字节
      for (let i = 0; i < klen; i++) this.buf[i] = key[i];
      for (let i = klen; i < 64; i++) this.buf[i] = 0;
      // Step 2: 计数器 t 设为块大小（64），代表已处理 64 字节
      this.t0 = 64;
      this.t1 = 0;
      // Step 3: 压缩密钥块（f=0），使用 t0=64
      this.compress(false);
      // 注意：不在此处递增 t。RFC 步骤 4 的"t += block_size"
      // 实际在后续 update() 处理数据块时自然完成：t0 从 64 开始，
      // update 会在此基础上 +=64，首数据块使用 counter=128。
      this.buflen = 0;
    }
  }

  private G(v: number[], a: number, b: number, c: number, d: number,
            x: number, y: number): void {
    v[a] = (v[a] + v[b] + x) >>> 0;
    v[d] = rotr32(v[d] ^ v[a], 16);
    v[c] = (v[c] + v[d]) >>> 0;
    v[b] = rotr32(v[b] ^ v[c], 12);
    v[a] = (v[a] + v[b] + y) >>> 0;
    v[d] = rotr32(v[d] ^ v[a], 8);
    v[c] = (v[c] + v[d]) >>> 0;
    v[b] = rotr32(v[b] ^ v[c], 7);
  }

  private compress(last: boolean): void {
    const v: number[] = new Array(16);
    const m: number[] = new Array(16);

    // 加载消息块（64 字节 = 16 个 u32）
    for (let i = 0; i < 16; i++) {
      const off: number = i * 4;
      m[i] = (this.buf[off] | (this.buf[off + 1] << 8) |
              (this.buf[off + 2] << 16) | (this.buf[off + 3] << 24)) >>> 0;
    }

    // 初始化工作向量
    for (let i = 0; i < 8; i++) {
      v[i] = this.h[i];
      v[i + 8] = IV[i];
    }

    // 64 位计数器注入
    v[12] = (v[12] ^ this.t0) >>> 0;
    v[13] = (v[13] ^ this.t1) >>> 0;

    // 最后块标志
    if (last) {
      v[14] = (~v[14]) >>> 0;
    }

    // 10 轮迭代
    for (let r = 0; r < 10; r++) {
      const s: number[] = SIGMA[r];
      this.G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
      this.G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
      this.G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
      this.G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
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

  /** 处理输入数据 */
  update(data: Uint8Array, len?: number): void {
    const length: number = len !== undefined ? len : data.length;
    let pos: number = 0;
    let rem: number = length;

    // 如果缓冲区有数据，先填充
    if (this.buflen > 0) {
      const fill: number = Math.min(64 - this.buflen, rem);
      for (let i = 0; i < fill; i++) this.buf[this.buflen + i] = data[pos + i];
      this.buflen += fill;
      pos += fill;
      rem -= fill;

      if (this.buflen === 64) {
        // RFC 7693: 先更新计数器，再压缩
        this.t0 += 64;
        if (this.t0 < 64) this.t1++;
        this.compress(false);
        this.buflen = 0;
      }
    }

    // 处理完整 64 字节块（最后一个完整块留给 digest 用 f=1 压缩）
    while (rem > 64) {
      for (let i = 0; i < 64; i++) this.buf[i] = data[pos + i];
      // RFC 7693: 先更新计数器，再压缩
      this.t0 += 64;
      if (this.t0 < 64) this.t1++;
      this.compress(false);
      pos += 64;
      rem -= 64;
    }

    // 剩余字节到缓冲区
    for (let i = 0; i < rem; i++) this.buf[this.buflen + i] = data[pos + i];
    this.buflen += rem;
  }

  /** 完成计算，返回摘要 */
  digest(): Uint8Array {
    // 填充剩余字节为零
    for (let i = this.buflen; i < 64; i++) this.buf[i] = 0;
    // 更新计数器（加上当前块中的字节数）
    this.t0 += this.buflen;
    if (this.t0 < this.buflen) this.t1++;  // t0 回绕时进位

    // 压缩最后一块
    this.compress(true);

    // 输出 h[0..7] 为小端序字节
    const out: Uint8Array = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      out[i * 4] = this.h[i] & 0xFF;
      out[i * 4 + 1] = (this.h[i] >>> 8) & 0xFF;
      out[i * 4 + 2] = (this.h[i] >>> 16) & 0xFF;
      out[i * 4 + 3] = (this.h[i] >>> 24) & 0xFF;
    }
    return out;
  }
}

/**
 * BLAKE2s-256 哈希
 * @param data 输入数据
 * @param key 可选密钥（密钥模式）
 * @returns 32 字节哈希值
 */
export function blake2s256(data: Uint8Array, key?: Uint8Array): Uint8Array {
  const ctx: B2sCtx = new B2sCtx(32, key);
  ctx.update(data);
  return ctx.digest();
}

/**
 * BLAKE2s-128 哈希（WireGuard MAC1/Cookie）
 * @param data 输入数据
 * @param key 密钥（密钥模式）
 * @returns 16 字节哈希值
 */
export function blake2s128(data: Uint8Array, key?: Uint8Array): Uint8Array {
  const ctx: B2sCtx = new B2sCtx(16, key);
  ctx.update(data);
  return ctx.digest();
}
