/**
 * Base64 编解码工具（ArkTS 兼容版）
 *
 * 用于解码 WireGuard 配置中的 Base64 编码密钥
 */

const BASE64_CHARS: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Base64 解码
 * @param input Base64 编码字符串
 * @returns 解码后的字节数组
 */
export function base64Decode(input: string): Uint8Array {
  // 去除空白字符和填充
  let s: string = input.replace(/\s/g, '').replace(/=+$/, '');

  const result: number[] = [];
  let i: number = 0;

  // 每 4 个 base64 字符解码为 3 字节
  while (i < s.length) {
    // 读取 4 个有效字符的索引
    const idx: number[] = [];
    let j: number = i;
    while (idx.length < 4 && j < s.length) {
      const ci: number = BASE64_CHARS.indexOf(s[j]);
      if (ci !== -1) {
        idx.push(ci);
      }
      j++;
    }
    i = j;

    // 解码小组：4 个 6 位 → 3 个 8 位
    if (idx.length >= 2) {
      result.push(((idx[0] << 2) | (idx[1] >> 4)) & 0xFF);
    }
    if (idx.length >= 3) {
      result.push(((idx[1] << 4) | (idx[2] >> 2)) & 0xFF);
    }
    if (idx.length >= 4) {
      result.push(((idx[2] << 6) | idx[3]) & 0xFF);
    }
  }

  return new Uint8Array(result);
}

/**
 * Base64 编码
 * @param data 字节数组
 * @returns Base64 编码字符串
 */
export function base64Encode(data: Uint8Array): string {
  let result: string = '';
  let buffer: number = 0;
  let bitsCollected: number = 0;

  for (let i = 0; i < data.length; i++) {
    buffer = (buffer << 8) | data[i];
    bitsCollected += 8;

    while (bitsCollected >= 6) {
      bitsCollected -= 6;
      result += BASE64_CHARS[(buffer >> bitsCollected) & 0x3F];
      buffer &= (1 << bitsCollected) - 1;
    }
  }

  if (bitsCollected > 0) {
    buffer <<= (6 - bitsCollected);
    result += BASE64_CHARS[buffer & 0x3F];
  }

  // 填充
  while (result.length % 4 !== 0) {
    result += '=';
  }

  return result;
}
