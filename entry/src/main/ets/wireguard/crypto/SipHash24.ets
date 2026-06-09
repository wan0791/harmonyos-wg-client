/**
 * SipHash-2-4 哈希实现（纯 ArkTS）
 *
 * 参考：https://131002.net/siphash/ 算法规范
 * WireGuard 用于哈希表键的快速伪随机函数。
 *
 * SipHash-2-4：每消息块 2 轮压缩，最后 4 轮最终化
 */

function rotl64(x: bigint, b: bigint): bigint {
  return ((x << b) | (x >> (64n - b))) & 0xFFFFFFFFFFFFFFFFn;
}

function readU64LE(buf: Uint8Array, off: number): bigint {
  return BigInt(buf[off]) | (BigInt(buf[off + 1]) << 8n) |
         (BigInt(buf[off + 2]) << 16n) | (BigInt(buf[off + 3]) << 24n) |
         (BigInt(buf[off + 4]) << 32n) | (BigInt(buf[off + 5]) << 40n) |
         (BigInt(buf[off + 6]) << 48n) | (BigInt(buf[off + 7]) << 56n);
}

/**
 * SipRound — SipHash 的核心轮函数
 * 每轮：v0+=v1; v1=rotl13; v1^=v0; v0=rotl32;
 *        v2+=v3; v3=rotl16; v3^=v2;
 *        v0+=v3; v3=rotl21; v3^=v0;
 *        v2+=v1; v1=rotl17; v1^=v2; v2=rotl32;
 */
function sipRound(v: bigint[]): void {
  v[0] = (v[0] + v[1]) & 0xFFFFFFFFFFFFFFFFn;
  v[1] = rotl64(v[1], 13n);
  v[1] ^= v[0];
  v[0] = rotl64(v[0], 32n);

  v[2] = (v[2] + v[3]) & 0xFFFFFFFFFFFFFFFFn;
  v[3] = rotl64(v[3], 16n);
  v[3] ^= v[2];

  v[0] = (v[0] + v[3]) & 0xFFFFFFFFFFFFFFFFn;
  v[3] = rotl64(v[3], 21n);
  v[3] ^= v[0];

  v[2] = (v[2] + v[1]) & 0xFFFFFFFFFFFFFFFFn;
  v[1] = rotl64(v[1], 17n);
  v[1] ^= v[2];
  v[2] = rotl64(v[2], 32n);
}

/**
 * SipHash-2-4 计算
 * @param key 16 字节密钥
 * @param data 输入数据
 * @returns 8 字节哈希值
 */
export function siphash24(key: Uint8Array, data: Uint8Array): Uint8Array {
  const k0: bigint = readU64LE(key, 0);
  const k1: bigint = readU64LE(key, 8);

  // 初始化
  const v: bigint[] = [
    k0 ^ 0x736F6D6570736575n,
    k1 ^ 0x646F72616E646F6Dn,
    k0 ^ 0x6C7967656E657261n,
    k1 ^ 0x7465646279746573n,
  ];

  const len: number = data.length;
  let off: number = 0;

  // 处理完整 8 字节块
  while (off + 8 <= len) {
    const m: bigint = readU64LE(data, off);
    v[3] ^= m;
    sipRound(v); // 2 rounds
    sipRound(v);
    v[0] ^= m;
    off += 8;
  }

  // 处理末尾字节 + 长度域
  let last: bigint = BigInt(len) << 56n;
  for (let i = 0; off + i < len; i++) {
    last |= BigInt(data[off + i]) << BigInt(i * 8);
  }

  v[3] ^= last;
  sipRound(v);
  sipRound(v);
  v[0] ^= last;

  // 最终化（异或 0xFF）
  v[2] ^= 0xFFn;

  // 4 轮最终化
  sipRound(v);
  sipRound(v);
  sipRound(v);
  sipRound(v);

  // 输出
  const result: bigint = (v[0] ^ v[1] ^ v[2] ^ v[3]) & 0xFFFFFFFFFFFFFFFFn;
  const out: Uint8Array = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    out[i] = Number((result >> BigInt(i * 8)) & 0xFFn);
  }
  return out;
}
