/**
 * WireGuard VPN Client for HarmonyOS
 * Step 2: 配置文件导入 + 端口分离 + 域名支持
 */

import { Want, common } from '@kit.AbilityKit';
import { connection, vpnExtension } from '@kit.NetworkKit';
import { picker, fileIo } from '@kit.CoreFileKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { router } from '@kit.ArkUI';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { preferences } from '@kit.ArkData';
import { parseWgConfig, WgParsedConfig } from '../utils/WgConfigParser';
import { getRelay } from '../utils/UdpRelay';
import { NativeSocket } from '../utils/NativeSocketFFI';

const DOMAIN = 0x0000;
const TAG = 'WgImport';

/** VpnExtAbility 固定端口（中继将 WG 响应发回此端口） */
const VPN_EXT_PORT: number = 52788;
/** 中继端口基值（自动尝试 +0 ~ +9） */
const RELAY_PORT_BASE: number = 52789;
const PORT_RANGE: number = 10;

/** 简单判断字符串是否为 IP 地址（非域名） */
function isIP(s: string): boolean {
  const parts: string[] = s.split('.');
  if (parts.length !== 4) return false;
  for (let i: number = 0; i < parts.length; i++) {
    const n: number = parseInt(parts[i]);
    if (isNaN(n) || n < 0 || n > 255) return false;
  }
  return true;
}

@Entry
@Component
struct Index {
  @State serverHost: string = '';
  @State serverPort: string = '51820';
  @State clientAddress: string = '10.0.0.2';
  @State dnsServer: string = '114.114.114.114';
  @State clientPrivateKey: string = '';
  @State serverPublicKey: string = '';
  @State presharedKey: string = '';
  @State isConnected: boolean = false;
  @State statusText: string = '就绪';
  @State statusLog: string = '';
  @State isDarkMode: boolean = true;
  @State diagText: string = '';  // 实时诊断
  @State tunRxBytes: number = 0;
  @State tunTxBytes: number = 0;

  private nativeSock: NativeSocket | null = null;
  private diagTimer: number = -1;
  private prefs: preferences.Preferences | null = null;

  async aboutToAppear(): Promise<void> {
    // 加载持久化配置
    await this.loadConfig();

    // 检查是否有扫码返回的结果（onPageShow 每次可见都检查）
    this.checkScanResult();
  }

  onPageShow(): void {
    this.checkScanResult();
  }

  private checkScanResult(): void {
    const scanResult: string | undefined = AppStorage.Get<string>('scanResult');
    if (scanResult) {
      this.applyScanResult(scanResult);
      this.appendLog('✅ 扫码配置已接收');
      AppStorage.Delete('scanResult');
    }
  }

  // 连接状态颜色
  private get statusColor(): ResourceColor {
    return this.isConnected ? '#48bb78' : '#718096';
  }

  build() {
    Column() {
      // ── 顶栏 ──
      Row() {
        Column() {
          Text('WireGuard VPN').fontSize(22).fontWeight(700).fontColor('#ffffff')
          Text('隧道测试版').fontSize(13).fontColor('#718096').margin({ top: 2 })
        }
        .alignItems(HorizontalAlign.Start)
        .layoutWeight(1)
      }
      .width('100%')
      .padding({ top: 16, bottom: 8 })

      Scroll() {
        Column() {
          // ── 状态卡片 ──
          this.buildStatusCard()

          // ── 服务器配置 ──
          this.buildSectionTitle('服务器配置')
          this.buildHostPortRow()

          // ── 客户端配置 ──
          this.buildSectionTitle('客户端配置')
          Column() {
            Text('虚拟 IP').fontSize(12).fontColor('#a0aec0').width('100%').margin({ bottom: 4 })
            TextInput({ placeholder: 'TUN 接口 IP 地址', text: $$this.clientAddress })
              .width('100%').height(40).fontSize(14).fontColor('#e2e8f0')
              .placeholderColor('#4a5568').backgroundColor('#161b22').borderRadius(8)
          }.width('100%').margin({ bottom: 12 })
          Column() {
            Text('DNS 服务器').fontSize(12).fontColor('#a0aec0').width('100%').margin({ bottom: 4 })
            TextInput({ placeholder: '例如 114.114.114.114', text: $$this.dnsServer })
              .width('100%').height(40).fontSize(14).fontColor('#e2e8f0')
              .placeholderColor('#4a5568').backgroundColor('#161b22').borderRadius(8)
          }.width('100%').margin({ bottom: 12 })

          // ── 密钥配置 ──
          this.buildSectionTitle('密钥配置')
          Column() {
            Text('客户端私钥 (PrivateKey)').fontSize(12).fontColor('#a0aec0').width('100%').margin({ bottom: 4 })
            TextInput({ placeholder: 'Base64 编码', text: $$this.clientPrivateKey })
              .width('100%').height(40).fontSize(14).fontColor('#e2e8f0')
              .placeholderColor('#4a5568').backgroundColor('#161b22').borderRadius(8)
          }.width('100%').margin({ bottom: 12 })
          Column() {
            Text('服务端公钥 (PublicKey)').fontSize(12).fontColor('#a0aec0').width('100%').margin({ bottom: 4 })
            TextInput({ placeholder: 'Base64 编码', text: $$this.serverPublicKey })
              .width('100%').height(40).fontSize(14).fontColor('#e2e8f0')
              .placeholderColor('#4a5568').backgroundColor('#161b22').borderRadius(8)
          }.width('100%').margin({ bottom: 12 })
          Column() {
            Row() {
              Text('预共享密钥 (PresharedKey)').fontSize(12).fontColor('#a0aec0').margin({ bottom: 4 }).layoutWeight(1)
              Text('⚠️ 如握手失败可尝试删除').fontSize(10).fontColor('#e53e3e').margin({ bottom: 4 })
            }.width('100%')
            TextInput({ placeholder: '可选，留空不使用 PSK', text: $$this.presharedKey })
              .width('100%').height(40).fontSize(14).fontColor('#e2e8f0')
              .placeholderColor('#4a5568').backgroundColor('#161b22').borderRadius(8)
          }.width('100%').margin({ bottom: 12 })

          // ── 操作按钮栏 ──
          Row() {
            Button('📁 导入配置')
              .height(40)
              .fontSize(14)
              .fontColor('#e2e8f0')
              .backgroundColor('#2d3748')
              .borderRadius(8)
              .layoutWeight(1)
              .margin({ right: 6 })
              .onClick(() => { this.importConfig(); })

            Button('📷 扫码')
              .height(40)
              .fontSize(14)
              .fontColor('#e2e8f0')
              .backgroundColor('#2d3748')
              .borderRadius(8)
              .layoutWeight(1)
              .margin({ left: 6 })
              .onClick(() => { this.handleScanClick(); })
          }
          .width('100%')
          .margin({ top: 8, bottom: 12 })

          // ── 连接按钮 ──
          Button(this.isConnected ? '断开连接' : '连接 VPN')
            .width('100%')
            .height(48)
            .fontSize(16)
            .fontWeight(600)
            .fontColor('#ffffff')
            .backgroundColor(this.isConnected ? '#e53e3e' : '#3b7bbf')
            .borderRadius(10)
            .margin({ bottom: 12 })
            .onClick(() => {
              if (this.isConnected) {
                this.disconnectVpn();
              } else {
                this.connectVpn();
              }
            })

          // ── 连接诊断 ──
          this.buildSectionTitle('连接诊断')
          Row() {
            Button('🩺 诊断')
              .height(32).fontSize(12).fontColor('#e2e8f0')
              .backgroundColor('#2d3748').borderRadius(6)
              .layoutWeight(1).margin({ right: 4 })
              .onClick(() => { this.runDiagnostic(); })
            Button('📡 测试连通')
              .height(32).fontSize(12).fontColor('#e2e8f0')
              .backgroundColor('#2d3748').borderRadius(6)
              .layoutWeight(1).margin({ left: 4 })
              .onClick(() => { this.testConnectivity(); })
          }.width('100%').margin({ bottom: 8 })
          Text(this.diagText || '点击诊断...')
            .fontSize(11).fontColor('#a0aec0')
            .width('100%').padding(8)
            .backgroundColor('#0f1f3a').borderRadius(6)
            .margin({ bottom: 12 })

          // ── 操作日志 ──
          this.buildSectionTitle('运行日志')
          Text(this.statusLog)
            .fontSize(12)
            .fontColor('#a0aec0')
            .width('100%')
            .height(160)
            .padding(10)
            .backgroundColor('#0f1f3a')
            .borderRadius(8)
            .textAlign(TextAlign.Start)
        }
        .width('100%')
        .padding({ top: 8, bottom: 16 })
      }
      .layoutWeight(1)
    }
    .width('100%')
    .height('100%')
    .padding({ left: 16, right: 16 })
    .backgroundColor('#0d1117')
  }

  // ── 构建函数 ──

  @Builder buildStatusCard() {
    Row() {
      Circle({ width: 12, height: 12 }).fill(this.statusColor)
      Text(this.isConnected ? '已连接' : '未连接')
        .fontSize(16).fontWeight(600).fontColor('#e2e8f0')
        .margin({ left: 10 })
        .layoutWeight(1)
      Text(this.statusText).fontSize(12).fontColor('#718096')
    }
    .width('100%')
    .padding({ top: 14, bottom: 14, left: 14, right: 14 })
    .backgroundColor('#161b22')
    .borderRadius(10)
    .margin({ bottom: 20 })
  }

  @Builder buildSectionTitle(title: string) {
    Text(title).fontSize(14).fontWeight(600).fontColor('#e2e8f0')
      .width('100%').margin({ top: 8, bottom: 8 })
  }

  @Builder buildInputRow(label: string, placeholder: string, textVal: string) {
    Column() {
      Text(label).fontSize(12).fontColor('#a0aec0').width('100%').margin({ bottom: 4 })
      TextInput({ placeholder: placeholder, text: textVal })
        .width('100%')
        .height(40)
        .fontSize(14)
        .fontColor('#e2e8f0')
        .placeholderColor('#4a5568')
        .backgroundColor('#161b22')
        .borderRadius(8)
    }
    .width('100%')
    .margin({ bottom: 12 })
  }

  @Builder buildHostPortRow() {
    Column() {
      Text('服务端地址').fontSize(12).fontColor('#a0aec0').width('100%').margin({ bottom: 4 })
      Row() {
        TextInput({ placeholder: 'IP 或域名，如 vpn.example.com', text: $$this.serverHost })
          .layoutWeight(1)
          .height(40)
          .fontSize(14)
          .fontColor('#e2e8f0')
          .placeholderColor('#4a5568')
          .backgroundColor('#161b22')
          .borderRadius(8)

        TextInput({ placeholder: '端口', text: $$this.serverPort })
          .width(90)
          .height(40)
          .fontSize(14)
          .fontColor('#e2e8f0')
          .placeholderColor('#4a5568')
          .backgroundColor('#161b22')
          .borderRadius(8)
          .margin({ left: 8 })
      }
      .width('100%')
    }
    .width('100%')
    .margin({ bottom: 12 })
  }

  // ── 日志 ──
  private appendLog(msg: string): void {
    const now = new Date();
    const time = now.getHours().toString().padStart(2, '0') + ':' +
                 now.getMinutes().toString().padStart(2, '0') + ':' +
                 now.getSeconds().toString().padStart(2, '0');
    this.statusLog = '[' + time + '] ' + msg + '\n' + this.statusLog;
    if (this.statusLog.length > 2000) {
      this.statusLog = this.statusLog.substring(0, 2000);
    }
  }

  // ── 连接 VPN ──
  private async connectVpn(): Promise<void> {
    if (!this.serverHost) {
      this.appendLog('错误：请输入服务端地址');
      return;
    }
    const port: number = parseInt(this.serverPort);
    if (isNaN(port) || port < 1 || port > 65535) {
      this.appendLog('错误：端口号无效（1-65535）');
      return;
    }

    this.statusText = '正在连接...';
    this.appendLog('服务端: ' + this.serverHost + ':' + this.serverPort);

    try {
      // 0. DNS 解析：将域名解析为 IP 地址（避免 DNS 问题导致包发不到服务器）
      let serverIP: string = this.serverHost;
      if (this.serverHost.indexOf('.') >= 0 && !isIP(this.serverHost)) {
        try {
          this.appendLog('正在解析域名 ' + this.serverHost + '...');
          const addrs: connection.NetAddress[] = await connection.getAddressesByName(this.serverHost);
          if (addrs && addrs.length > 0) {
            serverIP = addrs[0].address;
            this.appendLog('域名解析结果: ' + this.serverHost + ' → ' + serverIP);
          }
        } catch (dnsErr) {
          this.appendLog('DNS 解析失败，使用原始域名: ' + JSON.stringify(dnsErr));
        }
      }

      // 1. 创建 NAPI 原生 socket（主进程不受 TUN 影响，直连 WG 服务器）
      try {
        if (!this.nativeSock) {
          this.nativeSock = new NativeSocket();
          const fd: number = this.nativeSock.create();
          this.appendLog('NAPI socket fd=' + fd);
          hilog.info(DOMAIN, TAG, 'NAPI native socket created, fd=%{public}d', fd);
        }
      } catch (e) {
        this.appendLog('NAPI socket failed: ' + JSON.stringify(e));
      }

      // 2. 启动 UDP 中继（运行在 EntryAbility 进程，绕过 TUN 劫持）
      this.appendLog('正在启动 UDP 中继...');
      this.appendLog('中继目标: ' + serverIP + ':' + port + ' (域名: ' + this.serverHost + ')');
      const relay = getRelay();
      if (this.nativeSock) {
        relay.setNativeSocket(this.nativeSock);
        relay.startNativeRecvLoop();
        this.appendLog('NAPI socket hooked into relay');
      }
      await relay.start(serverIP, port, RELAY_PORT_BASE, VPN_EXT_PORT);
      const relayPort: number = relay.getPort();
      this.appendLog('UDP 中继已启动 relay=' + relayPort + ' vpnExt=' + VPN_EXT_PORT);

      // 2. 准备 VpnExtension 启动参数
      const want: Want = {
        deviceId: '',
        bundleName: 'com.lianhui.wireguard',
        abilityName: 'WireGuardVpnExt',
        parameters: {
          'serverHost': this.serverHost,
          'serverIP': serverIP,
          'serverPort': port,
          'clientAddress': this.clientAddress,
          'dnsServer': this.dnsServer,
          'relayPort': relayPort,
          'vpnExtPort': VPN_EXT_PORT,
        }
      };

      // 如果从配置导入了密钥，一并传递
      if (this.clientPrivateKey) {
        want.parameters!['clientPrivateKey'] = this.clientPrivateKey;
      }
      if (this.serverPublicKey) {
        want.parameters!['serverPublicKey'] = this.serverPublicKey;
      }
      if (this.presharedKey) {
        want.parameters!['presharedKey'] = this.presharedKey;
      }

      await vpnExtension.startVpnExtensionAbility(want);
      this.isConnected = true;
      this.statusText = '已连接';
      this.appendLog('VPN 扩展启动成功');
      // 启动诊断定时器
      this.startDiagTimer();
    } catch (e) {
      // 中继或 VPN 启动失败 → 停止中继
      this.statusText = '连接失败';
      this.appendLog('启动失败：' + JSON.stringify(e));
      try { getRelay().stop(); } catch (_) { /* ignore */ }
    }
  }

  // ── 导入配置文件 ──
  private async importConfig(): Promise<void> {
    try {
      const context: common.UIAbilityContext = getContext(this) as common.UIAbilityContext;
      const documentPicker: picker.DocumentViewPicker = new picker.DocumentViewPicker(context);

      const options: picker.DocumentSelectOptions = {
        fileSuffixFilters: ['.conf', '.wg', '.txt'],
        maxSelectNumber: 1,
      };

      const uris: string[] = await documentPicker.select(options);
      if (!uris || uris.length === 0) {
        this.appendLog('已取消选择文件');
        return;
      }

      const uri: string = uris[0];
      this.appendLog('正在读取配置文件...');
      hilog.info(DOMAIN, TAG, 'URI=%{public}s', uri);

      // 通过 URI 打开文件并读取内容
      const file: fileIo.File = await fileIo.open(uri);
      const buf: ArrayBuffer = new ArrayBuffer(4096);
      const bytesRead: number = await fileIo.read(file.fd, buf);
      const bytes: Uint8Array = new Uint8Array(buf.slice(0, bytesRead));
      let content: string = '';
      for (let i = 0; i < bytes.length; i++) {
        content += String.fromCharCode(bytes[i]);
      }
      fileIo.closeSync(file);
      this.appendLog('配置文件读取成功（' + content.length + ' 字符）');
      hilog.info(DOMAIN, TAG, '读取到 %{public}d 字节', content.length);

      // 解析配置
      const preview: string = content.substring(0, 100).replace(/\n/g, '\\n');
      this.appendLog('文件内容前100字符：' + preview);
      hilog.info(DOMAIN, TAG, '内容前100: %{public}s', preview);
      const config = parseWgConfig(content);
      const resultLog: string = 'host=' + config.serverHost +
        ' port=' + config.serverPort +
        ' ip=' + config.clientAddress +
        ' dns=' + config.dnsServer +
        ' priv=' + (config.privateKey ? '有' : '无') +
        ' pub=' + (config.publicKey ? '有' : '无');
      this.appendLog('解析结果：' + resultLog);
      hilog.info(DOMAIN, TAG, '解析: %{public}s', resultLog);
      if (config.error) {
        this.appendLog('⚠️ ' + config.error);
      }

      // 更新状态（$$ 双向绑定会自动更新 TextInput）
      this.serverHost = config.serverHost;
      this.serverPort = config.serverPort;
      this.clientAddress = config.clientAddress;
      this.dnsServer = config.dnsServer;
      this.clientPrivateKey = config.privateKey || '';
      this.serverPublicKey = config.publicKey || '';
      this.presharedKey = config.presharedKey || '';

      this.appendLog('✅ 配置已加载：' + (config.serverHost || '(空)') + ':' + (config.serverPort || '51820'));
      if (config.privateKey) {
        this.appendLog('🔑 客户端私钥已导入（' + config.privateKey.substring(0, 8) + '...）');
      }
      if (config.publicKey) {
        this.appendLog('🔑 服务端公钥已导入（' + config.publicKey.substring(0, 16) + '...）');
      }
      if (config.presharedKey) {
        this.appendLog('🔑 PresharedKey 已导入');
      }
      this.saveConfig();
    } catch (e) {
      const errMsg: string = JSON.stringify(e);
      this.appendLog('导入失败：' + errMsg);
      hilog.error(DOMAIN, TAG, '导入失败: %{public}s', errMsg);
    }
  }

  // ── 扫码 ──
  private handleScanClick(): void {
    try {
      router.pushUrl({ url: 'pages/ScanPage' });
    } catch (e) {
      this.appendLog('扫码页面跳转失败：' + JSON.stringify(e));
    }
  }

  private applyScanResult(text: string): void {
    // QR 码内容可能是纯文本配置或 wireguard:// 链接
    if (text.startsWith('wireguard://')) {
      const encoded: string = text.substring('wireguard://'.length);
      try {
        const decoded: string = decodeURIComponent(encoded);
        this.applyParsedConfig(parseWgConfig(decoded));
        return;
      } catch {
        this.applyParsedConfig(parseWgConfig(text));
        return;
      }
    }
    this.applyParsedConfig(parseWgConfig(text));
  }

  private applyParsedConfig(config: WgParsedConfig): void {
    if (config.serverHost) this.serverHost = config.serverHost;
    if (config.serverPort) this.serverPort = config.serverPort;
    if (config.clientAddress) this.clientAddress = config.clientAddress;
    if (config.dnsServer) this.dnsServer = config.dnsServer;
    if (config.privateKey) this.clientPrivateKey = config.privateKey;
    if (config.publicKey) this.serverPublicKey = config.publicKey;
    if (config.presharedKey) this.presharedKey = config.presharedKey;
    this.appendLog('配置已加载：' + config.serverHost + ':' + config.serverPort);
    this.saveConfig();
  }

  // ── 断开 VPN ──
  private async disconnectVpn(): Promise<void> {
    this.statusText = '断开中...';
    this.appendLog('正在停止 VPN...');

    try {
      const want: Want = {
        deviceId: '',
        bundleName: 'com.lianhui.wireguard',
        abilityName: 'WireGuardVpnExt',
      };

      await vpnExtension.stopVpnExtensionAbility(want);
      this.isConnected = false;
      this.statusText = '已断开';
      this.appendLog('VPN 已停止');
      this.stopDiagTimer();

      // 停止 UDP 中继
      try { getRelay().stop(); } catch (_) { /* ignore */ }
      this.appendLog('UDP 中继已停止');
    } catch (e) {
      this.appendLog('停止失败：' + JSON.stringify(e));
    }
  }

  // ── 诊断 ──
  private startDiagTimer(): void {
    this.diagTimer = setInterval((): void => {
      this.runDiagnostic();
    }, 3000);
  }

  private stopDiagTimer(): void {
    if (this.diagTimer >= 0) { clearInterval(this.diagTimer); this.diagTimer = -1; }
  }

  private runDiagnostic(): void {
    const relay = getRelay();
    const lines: string[] = [];
    lines.push('VPN: ' + (this.isConnected ? '✅' : '❌'));
    lines.push('NAPI fd=' + (this.nativeSock ? this.nativeSock.getFd() : '?'));
    lines.push('Relay Tx=' + relay.txBytes + 'B Rx=' + relay.rxBytes + 'B');
    this.diagText = lines.join(' | ');
  }

  private async testConnectivity(): Promise<void> {
    if (!this.isConnected) {
      this.appendLog('❌ 请先连接 VPN');
      return;
    }
    this.appendLog('🔍 测试连通性...');
    try {
      // 通过 relay 的 NAPI socket 发送一个测试数据到 WG 服务器
      const relay = getRelay();
      const testBuf: ArrayBuffer = new ArrayBuffer(4);
      const testView: Uint8Array = new Uint8Array(testBuf);
      testView[0] = 1; testView[1] = 0; testView[2] = 0; testView[3] = 0; // type=1 (initiation-like test)
      if (this.nativeSock) {
        const sent: number = this.nativeSock.sendTo(testBuf, this.serverHost, parseInt(this.serverPort));
        this.appendLog('📤 测试包已发送: ' + sent + 'B → ' + this.serverHost + ':' + this.serverPort);
      } else {
        this.appendLog('❌ NAPI socket 未就绪');
      }
    } catch (e) {
      this.appendLog('❌ 测试失败: ' + JSON.stringify(e));
    }
  }

  // ── 配置持久化 ──

  private async getPrefs(): Promise<preferences.Preferences> {
    if (!this.prefs) {
      const context: common.UIAbilityContext = getContext(this) as common.UIAbilityContext;
      this.prefs = await preferences.getPreferences(context, 'wg_config');
    }
    return this.prefs;
  }

  private async saveConfig(): Promise<void> {
    try {
      const prefs: preferences.Preferences = await this.getPrefs();
      await prefs.put('serverHost', this.serverHost);
      await prefs.put('serverPort', this.serverPort);
      await prefs.put('clientAddress', this.clientAddress);
      await prefs.put('dnsServer', this.dnsServer);
      await prefs.put('clientPrivateKey', this.clientPrivateKey);
      await prefs.put('serverPublicKey', this.serverPublicKey);
      await prefs.put('presharedKey', this.presharedKey);
      await prefs.flush();
      this.appendLog('💾 配置已保存');
    } catch (e) {
      // ignore save error
    }
  }

  private async loadConfig(): Promise<void> {
    try {
      const prefs: preferences.Preferences = await this.getPrefs();
      const host: string = await prefs.get('serverHost', '') as string;
      if (!host) return;
      this.serverHost = host;
      this.serverPort = await prefs.get('serverPort', '51820') as string;
      this.clientAddress = await prefs.get('clientAddress', '10.0.0.2') as string;
      this.dnsServer = await prefs.get('dnsServer', '114.114.114.114') as string;
      this.clientPrivateKey = await prefs.get('clientPrivateKey', '') as string;
      this.serverPublicKey = await prefs.get('serverPublicKey', '') as string;
      this.presharedKey = await prefs.get('presharedKey', '') as string;
      this.appendLog('📂 已加载保存的配置: ' + host + ':' + this.serverPort);
    } catch (e) {
      // ignore load error
    }
  }
}
