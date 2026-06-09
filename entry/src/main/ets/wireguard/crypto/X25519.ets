/**
 * X25519（Curve25519 ECDH）纯 ArkTS 实现
 *
 * 实现 RFC 7748 定义的 X25519 函数：
 *   x25519(k, u) = decode(scalarmult(clamp(k), decode(u)))
 *
 * 使用 Montgomery 梯子进行标量乘法。
 * 字段为 GF(p)，p = 2^255 - 19
 */

const P: bigint = (1n << 255n) - 19n;
const A24: bigint = 121665n; // (486662 - 2) / 4

/** 对私钥做 clamping */
function clamp(k: Uint8Array): Uint8Array {
  const out: Uint8Array = new Uint8Array(k);
  out[0] &= 248;     // 清低3位
  out[31] &= 127;    // 清高位
  out[31] |= 64;     // 置高位
  return out;
}

/** 小端序 32 字节 → bigint */
function decodeLE(buf: Uint8Array): bigint {
  let r: bigint = 0n;
  for (let i = buf.length - 1; i >= 0; i--) {
    r = (r << 8n) | BigInt(buf[i]);
  }
  return r;
}

/** bigint → 小端序 32 字节 */
function encodeLE(n: bigint): Uint8Array {
  const out: Uint8Array = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number((n >> BigInt(i * 8)) & 0xFFn);
  }
  return out;
}

/** GF(p) 加法 */
function add(a: bigint, b: bigint): bigint {
  const r: bigint = a + b;
  return r >= P ? r - P : r;
}

/** GF(p) 减法 */
function sub(a: bigint, b: bigint): bigint {
  const r: bigint = a - b;
  return r < 0n ? r + P : r;
}

/** GF(p) 乘法 */
function mul(a: bigint, b: bigint): bigint {
  return (a * b) % P;
}

/** GF(p) 平方 */
function sqr(a: bigint): bigint {
  return (a * a) % P;
}

/** GF(p) 倒数（用费马小定理 a^(p-2) mod p） */
function inv(a: bigint): bigint {
  let e: bigint = P - 2n;
  let r: bigint = 1n;
  let b: bigint = a % P;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return r;
}

/**
 * Montgomery 梯子：标量乘法
 * 输入：标量 k（clamped 32 字节），坐标 u（bigint）
 * 输出：结果 x 坐标（bigint）
 */
function scalarMult(scalar: Uint8Array, u: bigint): bigint {
  const clamped: Uint8Array = clamp(scalar);
  let x1: bigint = u;
  let x2: bigint = 1n;
  let z2: bigint = 0n;
  let x3: bigint = u;
  let z3: bigint = 1n;
  let swap: number = 0;

  for (let t = 254; t >= 0; t--) {
    const byteIdx: number = t >> 3;
    const bitIdx: number = t & 7;
    const kt: number = (clamped[byteIdx] >> bitIdx) & 1;

    swap ^= kt;
    // 条件交换
    if (swap !== 0) {
      let tmp: bigint = x2; x2 = x3; x3 = tmp;
      tmp = z2; z2 = z3; z3 = tmp;
    }
    swap = kt;

    const a: bigint = add(x2, z2);
    const aa: bigint = sqr(a);
    const b: bigint = sub(x2, z2);
    const bb: bigint = sqr(b);
    const e: bigint = sub(aa, bb);
    const c: bigint = add(x3, z3);
    const d: bigint = sub(x3, z3);
    const da: bigint = mul(d, a);
    const cb: bigint = mul(c, b);

    x3 = sqr(add(da, cb));
    z3 = mul(x1, sqr(sub(da, cb)));
    x2 = mul(aa, bb);
    z2 = mul(e, add(aa, mul(A24, e)));
  }

  // 如果 swap=1 则再交换一次
  if (swap !== 0) {
    let tmp: bigint = x2; x2 = x3; x3 = tmp;
    tmp = z2; z2 = z3; z3 = tmp;
  }

  // 结果 = x2 / z2
  return mul(x2, inv(z2));
}

// ── 对外 API ──

/** X25519 密钥对 */
export class X25519KeyPairResult {
  privateKey: Uint8Array = new Uint8Array(32);
  publicKey: Uint8Array = new Uint8Array(32);
}

/** 基点 9 的小端序编码 */
const BASE_POINT: bigint = 9n;

/**
 * 生成 X25519 密钥对
 * 私钥 = 32 随机字节（clamped），公钥 = x25519(私钥, 9)
 */
export function generateX25519KeyPair(): X25519KeyPairResult {
  const priv: Uint8Array = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    priv[i] = (Math.random() * 256) | 0;
  }

  const pub: Uint8Array = x25519(priv, BASE_POINT);

  const result: X25519KeyPairResult = new X25519KeyPairResult();
  result.privateKey = priv;
  result.publicKey = pub;
  return result;
}

/**
 * X25519 Diffie-Hellman 函数
 * @param privateKey 32 字节私钥
 * @param publicKey 32 字节公钥
 * @returns 32 字节共享密钥
 */
export function x25519DH(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  // 解码 u 坐标
  const u: bigint = decodeLE(publicKey);
  // 标量乘法
  const result: bigint = scalarMult(privateKey, u);
  // 编码结果
  return encodeLE(result);
}

/**
 * x25519(k, u) — RFC 7748 标准接口
 */
export function x25519(k: Uint8Array, u: bigint): Uint8Array {
  const result: bigint = scalarMult(k, u);
  return encodeLE(result);
}
