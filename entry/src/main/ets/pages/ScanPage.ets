/**
 * QR 码扫描页面
 * 支持：从图库选择图片解码二维码
 *
 * 使用方式：
 *   router.pushUrl({ url: 'pages/ScanPage' })
 *   扫码结果通过 AppStorage 传回 Index 页面
 */

import { common } from '@kit.AbilityKit';
import { image } from '@kit.ImageKit';
import { fileIo } from '@kit.CoreFileKit';
import { picker } from '@kit.CoreFileKit';
import { router } from '@kit.ArkUI';
import { decodeQrCode, PixelData } from '../utils/QrDecoder';

interface ScanResult {
  text: string;
  success: boolean;
}

@Entry
@Component
struct ScanPage {
  @State scanResult: string = '';
  @State statusMsg: string = '选择扫码方式';
  @State decoded: boolean = false;

  build() {
    Column() {
      // ── 顶部导航栏 ──
      Row() {
        Button('< 返回')
          .fontSize(16)
          .fontColor('#e2e8f0')
          .backgroundColor('transparent')
          .onClick(() => { this.goBack(); })
        Text('二维码扫描').fontSize(18).fontWeight(700).fontColor('#ffffff')
          .layoutWeight(1).textAlign(TextAlign.Center)
        Blank().width(60)
      }
      .width('100%')
      .padding({ top: 12, bottom: 8, left: 8, right: 8 })

      // ── 扫码预览区域 ──
      Column() {
        Column()
          .width(240)
          .height(240)
          .border({ width: { top: 3, bottom: 3, left: 3, right: 3 }, color: '#48bb78' })
          .borderRadius(12)
          .backgroundColor('#1a202c')
          .justifyContent(FlexAlign.Center)
          .alignItems(HorizontalAlign.Center)

        Text(this.statusMsg)
          .fontSize(15)
          .fontColor('#e2e8f0')
          .margin({ top: 16 })
          .textAlign(TextAlign.Center)
          .width('100%')
      }
      .width('100%')
      .height(320)
      .justifyContent(FlexAlign.Center)
      .alignItems(HorizontalAlign.Center)
      .backgroundColor('#0d1117')

      // ── 解码结果 ──
      if (this.scanResult) {
        Column() {
          Text('✅ 解码成功').fontSize(14).fontColor('#48bb78').margin({ bottom: 8 })
          Text(this.scanResult)
            .fontSize(11)
            .fontColor('#a0aec0')
            .width('100%')
            .maxLines(8)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .backgroundColor('#161b22')
            .borderRadius(8)
            .padding(10)
        }
        .width('100%')
        .margin({ top: 8 })
        .padding({ left: 16, right: 16 })
      }

      // ── 操作按钮 ──
      Column() {
        Button('🖼 从相册选择二维码图片')
          .width('100%')
          .height(48)
          .fontSize(16)
          .fontColor('#ffffff')
          .backgroundColor('#3b7bbf')
          .borderRadius(10)
          .margin({ top: 8 })
          .onClick(() => { this.pickFromAlbum(); })

        if (this.scanResult) {
          Button('✅ 使用此配置')
            .width('100%')
            .height(48)
            .fontSize(16)
            .fontColor('#ffffff')
            .backgroundColor('#48bb78')
            .borderRadius(10)
            .margin({ top: 8 })
            .onClick(() => { this.useResult(); })
        }
      }
      .width('100%')
      .padding({ left: 16, right: 16, bottom: 16 })
      .layoutWeight(1)
      .backgroundColor('#0d1117')
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#0d1117')
  }

  // ── 相册选图扫码 ──

  private async pickFromAlbum(): Promise<void> {
    try {
      const context: common.UIAbilityContext = getContext(this) as common.UIAbilityContext;
      const docPicker: picker.DocumentViewPicker = new picker.DocumentViewPicker(context);
      const docOptions: picker.DocumentSelectOptions = {
        fileSuffixFilters: ['.jpg', '.jpeg', '.png', '.bmp'],
        maxSelectNumber: 1,
      };

      const uris: string[] = await docPicker.select(docOptions);
      if (!uris || uris.length === 0) {
        this.statusMsg = '已取消选择';
        return;
      }

      this.statusMsg = '正在解码 QR 码...';

      const uri: string = uris[0];
      const imageSource: image.ImageSource = image.createImageSource(uri);
      const pixelMap: image.PixelMap = await imageSource.createPixelMap({
        desiredPixelFormat: image.PixelMapFormat.RGBA_8888,
        desiredSize: { width: 800, height: 800 },
      });

      // 读取像素数据（使用创建时指定的尺寸）
      const pxWidth: number = 800;
      const pxHeight: number = 800;
      const bufferSize: number = pxWidth * pxHeight * 4;
      const dst: ArrayBuffer = new ArrayBuffer(bufferSize);

      await pixelMap.readPixelsToBuffer(dst);
      const pixelArr: Uint8Array = new Uint8Array(dst);

      const pixelDataStruct: PixelData = {
        width: pxWidth,
        height: pxHeight,
        data: pixelArr,
      };

      const qrResult = decodeQrCode(pixelDataStruct);
      pixelMap.release();
      imageSource.release();

      if (qrResult.success) {
        this.scanResult = qrResult.text;
        this.statusMsg = '✅ QR 码解码成功！';
        this.decoded = true;
      } else {
        this.statusMsg = '❌ 解码失败：' + (qrResult.error || '图片中未找到有效 QR 码');
      }
    } catch (err) {
      this.statusMsg = '解码失败：' + JSON.stringify(err);
    }
  }

  // ── 导航 ──

  private goBack(): void {
    router.back();
  }

  private useResult(): void {
    // 将结果存入 AppStorage，Index 的 aboutToAppear 会读取
    AppStorage.setOrCreate<string>('scanResult', this.scanResult);
    router.back();
  }
}
