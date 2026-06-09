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
  // 去除空白字符
  let s: string = input.replace(/\s/g, '');

  // 处理填充
  const padLen: number = s.endsWith('==') ? 2 : (s.endsWith('=') ? 1 : 0);
  if (padLen > 0) {
    s = s.substring(0, s.length - padLen);
  }

  // 解码
  const result: number[] = [];
  let buffer: number = 0;
  let bitsCollected: number = 0;

  for (let i = 0; i < s.length; i++) {
    const c: string = s[i];
    const idx: number = BASE64_CHARS.indexOf(c);
    if (idx === -1) continue; // 跳过非法字符

    buffer = (buffer << 6) | idx;
    bitsCollected += 6;

    if (bitsCollected >= 8) {
      bitsCollected -= 8;
      result.push((buffer >> bitsCollected) & 0xFF);
      buffer &= (1 << bitsCollected) - 1;
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
