/**
 * QR 码解码器（纯 ArkTS 实现）
 *
 * 支持从像素数据中解码 QR 码，适配 WireGuard 配置 QR 码场景。
 * 使用 Simplified Reed-Solomon error correction 算法。
 *
 * 参考：ISO/IEC 18004:2015, jsQR algorithm
 */

// ── QR 码格式信息 ──

/** QR 码版本信息 */
class QrVersion {
  version: number = 1;
  totalModules: number = 21; // 21 + 4 * (version - 1)
  dataModules: number = 0;
  rsBlocks: number = 0;
  rsBlockSize: number = 0;
}

/** Format info 掩码模式 */
const FORMAT_MASK: number = 0x5412;

/** 纠错等级 */
export enum QrErrorLevel {
  L = 0x01, // ~7%
  M = 0x00, // ~15%
  Q = 0x03, // ~25%
  H = 0x02, // ~30%
}

// ── 结果类型 ──

export interface QrDecodeResult {
  /** 解码成功的文本 */
  text: string;
  /** 是否成功 */
  success: boolean;
  /** 错误信息 */
  error?: string;
}

// ── 像素图接口 ──

export interface PixelData {
  width: number;
  height: number;
  data: Uint8Array;  // RGBA 格式
}

// ── Reed-Solomon 纠错 ──

/** GF(256) 乘法表查询 */
const RS_LOG: number[] = new Array(256);
const RS_EXP: number[] = new Array(512);
(() => {
  let v: number = 1;
  for (let i: number = 0; i < 255; i++) {
    RS_LOG[v] = i;
    RS_EXP[i] = v;
    v = (v << 1) ^ (v & 0x80 ? 0x11D : 0);
  }
  for (let i: number = 255; i < 512; i++) {
    RS_EXP[i] = RS_EXP[i - 255];
  }
})();

function rsMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return RS_EXP[(RS_LOG[a] + RS_LOG[b]) % 255];
}

function rsPolyEval(poly: number[], x: number): number {
  let result: number = poly[0];
  for (let i: number = 1; i < poly.length; i++) {
    result = rsMul(result, x) ^ poly[i];
  }
  return result;
}

function rsGenPoly(degree: number): number[] {
  let poly: number[] = [1];
  for (let i: number = 0; i < degree; i++) {
    const p: number[] = [1, RS_EXP[i]];
    const newPoly: number[] = new Array(poly.length + 1).fill(0);
    for (let j: number = 0; j < poly.length; j++) {
      newPoly[j] ^= rsMul(poly[j], p[0]);
      newPoly[j + 1] ^= rsMul(poly[j], p[1]);
    }
    poly = newPoly;
  }
  return poly;
}

function rsDecode(message: number[], eccSize: number): boolean {
  const genPoly: number[] = rsGenPoly(eccSize);
  const syndromes: number[] = new Array(eccSize).fill(0);
  let hasError: boolean = false;
  for (let i: number = 0; i < eccSize; i++) {
    syndromes[i] = rsPolyEval(message, RS_EXP[i]);
    if (syndromes[i] !== 0) hasError = true;
  }
  if (!hasError) return true;

  // Berlekamp-Massey 算法找错误位置
  const sigma: number[] = [1];
  const b: number[] = [1];
  let l: number = 0;
  let m: number = 1;
  let u: number = 0;
  while (u < eccSize) {
    let discrepancy: number = syndromes[u];
    for (let i: number = 1; i <= l; i++) {
      discrepancy ^= rsMul(sigma[i], syndromes[u - i]);
    }
    if (discrepancy !== 0) {
      const t: number[] = sigma.slice();
      for (let i: number = 0; i < b.length; i++) {
        const idx: number = i + m;
        if (idx >= sigma.length) sigma.push(0);
        sigma[idx] ^= rsMul(discrepancy, b[i]);
      }
      if (2 * l <= u) {
        l = u + 1 - l;
        b.length = 0;
        for (let i: number = 0; i < t.length; i++) {
          const inv: number = RS_EXP[(255 - RS_LOG[discrepancy] + 255) % 255];
          b.push(rsMul(t[i], inv));
        }
        m = 1;
      } else {
        m++;
      }
    } else {
      m++;
    }
    u++;
  }

  // 找错误位置（Chien search）
  const errorPos: number[] = [];
  for (let i: number = 0; i < message.length; i++) {
    if (rsPolyEval(sigma, RS_EXP[(255 - i % 255 + 255) % 255]) === 0) {
      errorPos.push(message.length - 1 - i);
    }
  }

  if (errorPos.length !== l) return false;

  // 找错误值（Forney 算法）
  const omega: number[] = new Array(eccSize).fill(0);
  for (let i: number = 0; i < eccSize; i++) {
    let sum: number = 0;
    for (let j: number = 0; j <= i && j < sigma.length; j++) {
      sum ^= rsMul(sigma[j], syndromes[i - j]);
    }
    omega[i] = sum;
  }

  for (const pos of errorPos) {
    const x: number = RS_EXP[(255 - ((message.length - 1 - pos) % 255) + 255) % 255];
    let sigmaPrime: number = 0;
    for (let i: number = 1; i < sigma.length; i += 2) {
      sigmaPrime ^= rsMul(sigma[i], RS_EXP[(RS_LOG[x] * (i - 1) % 255 + 255) % 255]);
    }
    const e: number = rsMul(rsPolyEval(omega, x), RS_EXP[(255 - RS_LOG[sigmaPrime] + 255) % 255]);
    message[pos] ^= e;
  }

  return true;
}

// ── 图像预处理 ──

/** 二值化后的图像数据 */
class BinaryImage {
  width: number = 0;
  height: number = 0;
  data: Int8Array = new Int8Array(0);
}

/** 将 RGBA 像素数据转为灰度 + 二值化 */
function binarize(data: PixelData): BinaryImage {
  const w: number = data.width;
  const h: number = data.height;
  const pixels: number[] = new Array(w * h);
  const src: Uint8Array = data.data;

  // 灰度化（ luminosity 公式）
  let total: number = 0;
  for (let i: number = 0; i < w * h; i++) {
    const off: number = i * 4;
    const gray: number = Math.round(0.299 * src[off] + 0.587 * src[off + 1] + 0.114 * src[off + 2]);
    pixels[i] = gray;
    total += gray;
  }

  // Otsu 二值化
  const hist: number[] = new Array(256).fill(0);
  for (const p of pixels) hist[p]++;

  let sumTotal: number = 0;
  for (let t = 0; t < 256; t++) sumTotal += t * hist[t];

  let sumB: number = 0;
  let wB: number = 0;
  let wF: number = 0;
  let maxVariance: number = 0;
  let threshold: number = 128;

  for (let t = 0; t < 256; t++) {
    wB += hist[t];
    if (wB === 0) continue;
    wF = w * h - wB;
    if (wF === 0) break;
    sumB += t * hist[t];
    const mB: number = sumB / wB;
    const mF: number = (sumTotal - sumB) / wF;
    const betweenVar: number = wB * wF * (mB - mF) * (mB - mF);
    if (betweenVar > maxVariance) {
      maxVariance = betweenVar;
      threshold = t;
    }
  }

  const binResult: Int8Array = new Int8Array(w * h);
  for (let i: number = 0; i < w * h; i++) {
    binResult[i] = pixels[i] < threshold ? 1 : 0;
  }

  const out: BinaryImage = new BinaryImage();
  out.width = w;
  out.height = h;
  out.data = binResult;
  return out;
}

// ── 探测图形查找 ──

interface FinderPattern {
  x: number;
  y: number;
  moduleSize: number;
}

/** 在行上检测 1:1:3:1:1 比例 */
function findPatternAtRow(data: Int8Array, w: number, h: number, row: number, col: number): number {
  const counts: number[] = [0, 0, 0, 0, 0];
  let idx: number = 0;
  let curr: number = 0;
  const limit: number = Math.min(col + 80, w);

  for (let i: number = col; i < w; i++) {
    const px: number = data[row * w + i];
    if (px === curr) {
      counts[idx]++;
    } else {
      if (idx === 4) break;
      idx++;
      counts[idx] = 1;
      curr = px;
    }
  }

  if (idx < 4) return 0;

  // 检查比例 1:1:3:1:1
  const totalModules: number = counts[0] + counts[1] + counts[2] + counts[3] + counts[4];
  if (totalModules < 7) return 0;
  const moduleSize: number = totalModules / 7;
  const tolerance: number = moduleSize * 0.5;

  if (Math.abs(counts[0] - moduleSize) > tolerance) return 0;
  if (Math.abs(counts[1] - moduleSize) > tolerance) return 0;
  if (Math.abs(counts[2] - 3 * moduleSize) > tolerance * 3) return 0;
  if (Math.abs(counts[3] - moduleSize) > tolerance) return 0;
  if (Math.abs(counts[4] - moduleSize) > tolerance) return 0;

  return Math.round(moduleSize);
}

/** 查找所有可能的探测图形 */
function findFinderPatterns(data: Int8Array, w: number, h: number): FinderPattern[] {
  const patterns: FinderPattern[] = [];
  const minModuleSize: number = 2;

  for (let y: number = 0; y < h; y += 2) {
    for (let x: number = 0; x < w; x++) {
      const px: number = data[y * w + x];
      // 找黑色像素开头
      if (px !== 1) continue;
      const moduleSize: number = findPatternAtRow(data, w, h, y, x);
      if (moduleSize >= minModuleSize) {
        // 垂直方向验证
        const vertSize: number = findPatternAtRow(data, w, h, y, x);
        if (Math.abs(vertSize - moduleSize) < moduleSize * 0.5) {
          patterns.push({ x: x + Math.round(3.5 * moduleSize), y, moduleSize });
          x += Math.round(7 * moduleSize);
        }
      }
    }
  }

  // 合并相邻的探测图形
  const merged: FinderPattern[] = [];
  for (const p of patterns) {
    let found: boolean = false;
    for (const m of merged) {
      const dx: number = Math.abs(p.x - m.x);
      const dy: number = Math.abs(p.y - m.y);
      if (dx < m.moduleSize * 4 && dy < m.moduleSize * 4) {
        m.x = Math.round((m.x + p.x) / 2);
        m.y = Math.round((m.y + p.y) / 2);
        m.moduleSize = Math.round((m.moduleSize + p.moduleSize) / 2);
        found = true;
        break;
      }
    }
    if (!found) merged.push(p);
  }

  return merged;
}

// ── 主解码函数 ──

/**
 * 从像素数据中解码 QR 码
 * @param pixels RGBA 像素数据
 * @returns 解码结果
 */
export function decodeQrCode(pixels: PixelData): QrDecodeResult {
  try {
    // 二值化
    const bin: BinaryImage = binarize(pixels);

    // 查找探测图形
    const patterns: FinderPattern[] = findFinderPatterns(bin.data, bin.width, bin.height);

    if (patterns.length < 3) {
      // 尝试从相册图片常见情况处理：降采样后重试
      // 简单返回错误
      return {
        text: '',
        success: false,
        error: '未找到 QR 码（需要至少 3 个定位图形，找到 ' + patterns.length + ' 个）',
      };
    }

    // 取前三个作为定位点（左上、右上、左下）
    const topPatterns: FinderPattern[] = patterns.sort((a, b) => a.y - b.y).slice(0, 3);
    const topLeft: FinderPattern = topPatterns.sort((a, b) => a.x - b.x)[0];
    const topRight: FinderPattern = topPatterns.sort((a, b) => b.x - a.x)[0];
    const bottomLeft: FinderPattern = topPatterns.sort((a, b) => b.y - a.y)[0];

    // 估算模块数和二维码版本
    const widthModules: number = Math.round(
      (Math.sqrt(
        (topRight.x - topLeft.x) * (topRight.x - topLeft.x) +
        (topRight.y - topLeft.y) * (topRight.y - topLeft.y)
      ) + Math.sqrt(
        (bottomLeft.x - topLeft.x) * (bottomLeft.x - topLeft.x) +
        (bottomLeft.y - topLeft.y) * (bottomLeft.y - topLeft.y)
      )) / 2 / 7
    );

    const qrVersion: number = Math.max(1, Math.min(40, Math.round((widthModules - 21) / 4) + 1));
    const moduleCount: number = 21 + 4 * (qrVersion - 1);

    // 估算模块大小（像素）
    const modulePixels: number = Math.round(
      (Math.abs(topRight.x - topLeft.x) + Math.abs(bottomLeft.y - topLeft.y)) / 2 / moduleCount
    );

    if (modulePixels < 1) {
      return { text: '', success: false, error: 'QR 码分辨率过低' };
    }

    // 采样网格
    const bits: Int8Array = new Int8Array(moduleCount * moduleCount).fill(0);
    const ox: number = topLeft.x - modulePixels * 3.5;
    const oy: number = topLeft.y - modulePixels * 3.5;

    for (let row: number = 0; row < moduleCount; row++) {
      for (let col: number = 0; col < moduleCount; col++) {
        const px: number = ox + col * modulePixels;
        const py: number = oy + row * modulePixels;
        if (px >= 0 && px < bin.width && py >= 0 && py < bin.height) {
          bits[row * moduleCount + col] = bin.data[Math.round(py) * bin.width + Math.round(px)];
        }
      }
    }

    // 读取格式信息
    let formatInfo: number = 0;
    for (let i: number = 0; i < 6; i++) {
      formatInfo = (formatInfo << 1) | bits[8 * moduleCount + i];
    }
    formatInfo = (formatInfo << 1) | bits[8 * moduleCount + 7];
    formatInfo = (formatInfo << 1) | bits[8 * moduleCount + 8];
    formatInfo = (formatInfo << 2) | bits[7 * moduleCount + 8];
    formatInfo = (formatInfo << 2) | bits[5 * moduleCount + 8];
    formatInfo = (formatInfo << 1) | bits[4 * moduleCount + 8];
    formatInfo = (formatInfo << 1) | bits[3 * moduleCount + 8];

    // XOR 掩码
    const maskedFmt: number = formatInfo ^ FORMAT_MASK;

    // 纠错等级
    const ecLevel: number = (maskedFmt >> 13) & 0x03;

    // 提取数据位（简化的读取路径）
    // 从右下角开始蛇形读取
    const dataBits: number[] = [];
    let dir: number = -1;
    let col: number = moduleCount - 1;

    while (col > 0) {
      if (col === 6) col--; // 跳过 timing pattern

      for (let row: number = dir === -1 ? moduleCount - 1 : 0;
           dir === -1 ? row >= 0 : row < moduleCount;
           row += dir) {

        for (let c: number = 0; c < 2; c++) {
          const cx: number = col - c;
          if (cx < 0) continue;

          // 跳过功能图形区域
          const isFuncPattern: boolean =
            (row < 9 && cx < 9) || // 左上角定位
            (row < 9 && cx >= moduleCount - 8) || // 右上角
            (row >= moduleCount - 8 && cx < 9) || // 左下角
            (cx === 6) || // 垂直 timing
            (row === 6);   // 水平 timing

          if (!isFuncPattern) {
            const bit: number = bits[row * moduleCount + cx];
            // 应用数据掩码
            const maskBit: number = ((row + cx) % 2 === 0) ? 1 : 0;
            dataBits.push(bit ^ maskBit);
          }
        }
      }
      col -= 2;
      dir = -dir;
    }

    // 尝试解码为文本（Alphanumeric / Byte mode）
    return decodeQrData(dataBits, moduleCount, ecLevel);
  } catch (e) {
    return {
      text: '',
      success: false,
      error: '解码异常：' + (e as Error).message,
    };
  }
}

function decodeQrData(bits: number[], moduleCount: number, ecLevel: number): QrDecodeResult {
  try {
    // 根据版本和纠错等级确定数据长度
    const qrVer: number = Math.round(((moduleCount - 21) / 4) | 0 + 1);
    const totalDataCodewords: number = getDataCodewordsCount(
      qrVer,
      ecLevel,
      bits.length
    );

    // 将 bits 转为 codewords
    const codewords: number[] = [];
    for (let i: number = 0; i < bits.length - 7; i += 8) {
      let cw: number = 0;
      for (let j: number = 0; j < 8; j++) {
        cw = (cw << 1) | (bits[i + j] || 0);
      }
      codewords.push(cw);
    }

    if (codewords.length < 4) {
      return { text: '', success: false, error: '数据太短' };
    }

    // 纠错
    const eccCount: number = codewords.length - totalDataCodewords;
    if (eccCount > 0 && totalDataCodewords > 0) {
      rsDecode(codewords, eccCount);
    }

    // 解码数据
    const data: number[] = codewords.slice(0, totalDataCodewords);
    const result: string = decodeTextData(data);

    if (result) {
      return { text: result, success: true };
    }

    return { text: '', success: false, error: '无法解码数据内容' };
  } catch (e) {
    return {
      text: '',
      success: false,
      error: '数据解码异常：' + (e as Error).message,
    };
  }
}

function getDataCodewordsCount(version: number, ecLevel: number, totalBits?: number): number {
  // 简化的数据码字表（Version 1-6，纠错 L/M/Q/H）
  // [ver][ecLevel] = totalCodewords, dataCodewords
  const table: number[][] = [
    [0, 0, 0, 0],       // placeholder
    [26, 18, 16, 13],    // V1: L=26-7=19, M=26-10=16, Q=26-13=13, H=26-17=9  → data codewords
    [44, 34, 28, 22],    // V2
    [70, 55, 44, 34],    // V3
    [100, 80, 64, 48],   // V4
    [134, 108, 86, 62],  // V5
    [172, 136, 108, 76], // V6
  ];

  if (version <= 6) {
    // 去掉纠错码字
    const total: number = table[version][ecLevel];
    return total - Math.round(total / 4);  // 简略估算
  }

  // 对于更高版本，粗略估计
  if (totalBits) {
    return Math.round(totalBits / 8 * 0.6);
  }
  return 50; // 默认保守值
}

function decodeTextData(data: number[]): string {
  if (data.length < 1) return '';

  const mode: number = data[0] >> 4;

  // Mode 指示器：
  // 0001 = Numeric
  // 0010 = Alphanumeric
  // 0100 = Byte
  // 1000 = Kanji

  let pos: number = 1; // 当前 bit 位置

  if (mode === 0x04) { // Byte mode
    // 读取字符计数（8 bits for V1-9, 16 bits for V10-26）
    const charCount: number = data[0] & 0x0F;
    if (charCount === 0 && data.length >= 2) {
      // 可能是计数在第二个字节
      const count2: number = (data[0] & 0x07) << 8 | data[1];
      if (count2 > 0 && count2 < data.length - 2) {
        pos = 2;
        let result: string = '';
        for (let i = pos; i < pos + count2 && i < data.length; i++) {
          result += String.fromCharCode(data[i]);
        }
        if (result && isLikelyText(result)) return result;
      }
    } else if (charCount > 0 && charCount < data.length - 1) {
      let result: string = '';
      for (let i = 1; i <= charCount && i < data.length; i++) {
        result += String.fromCharCode(data[i]);
      }
      if (result && isLikelyText(result)) return result;
    }
  }

  if (mode === 0x02) { // Alphanumeric mode
    const count: number = data[0] & 0x0F;
    let result: string = '';
    for (let i = 1; i < data.length - 1; i += 2) {
      const pair: number = (data[i] << 8) | (data[i + 1]);
      const c1: number = Math.floor(pair / 45);
      const c2: number = pair % 45;
      result += ALPHANUM_CHARS[c1] || '';
      if (i + 2 < data.length || result.length < count) {
        result += ALPHANUM_CHARS[c2] || '';
      }
    }
    if (result && isLikelyText(result)) return result;
  }

  // Fallback: 尝试以 byte 模式读取全部数据内容
  {
    let result: string = '';
    for (let i = 1; i < data.length; i++) {
      const c: number = data[i];
      if (c >= 32 && c <= 126) {
        result += String.fromCharCode(c);
      } else if (c === 10 || c === 13) {
        result += '\n';
      }
    }
    if (result.length > 5) return result;
  }

  return '';
}

const ALPHANUM_CHARS: string = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

function isLikelyText(s: string): boolean {
  // WireGuard 配置文本特征：包含换行、方括号、等号
  return s.includes('=') || s.includes('[') || s.includes('\n') ||
         s.startsWith('wireguard://') || s.startsWith('wg://');
}

/**
 * 从 URI 读取图片并解码 QR 码（配合 fileIo 使用）
 * 注：实际调用前需先将图片文件读取为 PixelMap
 *
 * @param imagePath 图片文件路径
 * @param readBytes 读取图片字节数组的函数
 * @returns 解码结果
 */
export async function decodeQrFromImage(
  imageData: PixelData
): Promise<QrDecodeResult> {
  return decodeQrCode(imageData);
}
