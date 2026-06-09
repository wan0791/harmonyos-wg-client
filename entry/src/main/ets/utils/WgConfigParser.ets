/**
 * WireGuard 配置文件解析器
 *
 * 支持解析标准 .conf 文件格式：
 *   [Interface] → Address, DNS, PrivateKey
 *   [Peer]      → Endpoint (host:port), PublicKey, AllowedIPs
 *   # 和 ; 开头的行是注释，跳过
 */

export interface WgParsedConfig {
  /** Endpoint 中的主机（IP 或域名） */
  serverHost: string;
  /** Endpoint 中的端口号 */
  serverPort: string;
  /** Interface 的 Address（取第一个 IP） */
  clientAddress: string;
  /** DNS 服务器（取第一个） */
  dnsServer: string;
  /** 完整的客户端私有 IP（含掩码） */
  clientAddressFull: string;
  /** PrivateKey */
  privateKey?: string;
  /** Peer PublicKey */
  publicKey?: string;
  /** AllowedIPs */
  allowedIPs?: string;
  /** 原始解析错误 */
  error?: string;
}

/**
 * 解析 WireGuard .conf 文件内容
 * @param content 文件文本内容
 * @returns 解析结果
 */
export function parseWgConfig(content: string): WgParsedConfig {
  const result: WgParsedConfig = {
    serverHost: '',
    serverPort: '51820',
    clientAddress: '',
    dnsServer: '',
    clientAddressFull: '',
  };

  const lines: string[] = content.split(/\r?\n/);
  let currentSection: string = '';

  for (const rawLine of lines) {
    const line: string = rawLine.trim();

    // 跳过空行和注释
    if (line === '' || line.startsWith('#') || line.startsWith(';')) {
      continue;
    }

    // 章节标记 [Interface] / [Peer] / ...
    if (line.startsWith('[') && line.endsWith(']')) {
      currentSection = line.slice(1, -1).trim().toLowerCase();
      continue;
    }

    // 解析 key = value
    const eqIdx: number = line.indexOf('=');
    if (eqIdx === -1) {
      continue;
    }
    const key: string = line.substring(0, eqIdx).trim().toLowerCase();
    const value: string = line.substring(eqIdx + 1).trim();

    if (currentSection === 'interface') {
      switch (key) {
        case 'address': {
          result.clientAddressFull = value;
          // 取第一个 IP，去掉掩码
          const firstIp: string = value.split(',')[0].trim().split('/')[0];
          result.clientAddress = firstIp;
          break;
        }
        case 'dns': {
          // 取第一个 DNS
          result.dnsServer = value.split(',')[0].trim();
          break;
        }
        case 'privatekey':
          result.privateKey = value;
          break;
        case 'mtu':
          // 可以扩展：暂不处理 MTU
          break;
      }
    } else if (currentSection === 'peer') {
      switch (key) {
        case 'endpoint': {
          // endpoint = host:port 或 [host]:port
          const ep: string = value.trim();
          const lastColon: number = ep.lastIndexOf(':');
          if (lastColon === -1) {
            result.serverHost = ep;
            result.serverPort = '51820';
          } else {
            // 检测 IPv6 格式 [::1]:port
            if (ep.startsWith('[')) {
              const closeBracket: number = ep.indexOf(']');
              if (closeBracket !== -1) {
                result.serverHost = ep.substring(0, closeBracket + 1);
                result.serverPort = ep.substring(closeBracket + 2); // skip "]:"
              }
            } else {
              result.serverHost = ep.substring(0, lastColon);
              result.serverPort = ep.substring(lastColon + 1);
            }
          }
          break;
        }
        case 'publickey':
          result.publicKey = value;
          break;
        case 'allowedips':
          result.allowedIPs = value;
          break;
        case 'persistentkeepalive':
          break;
      }
    }
  }

  // 验证结果
  if (!result.serverHost) {
    result.error = '配置文件中未找到 [Peer] Endpoint';
  }
  if (!result.clientAddress) {
    result.error = (result.error ? result.error + '；' : '') + '配置文件中未找到 [Interface] Address';
  }

  return result;
}
