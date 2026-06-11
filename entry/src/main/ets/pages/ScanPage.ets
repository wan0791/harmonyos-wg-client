/**
 * QR 码扫描页面
 * - 系统原生相机扫码（ScanKit startScanForResult）
 * - 相册选图扫码
 */

import { common } from '@kit.AbilityKit';
import { image } from '@kit.ImageKit';
import { picker } from '@kit.CoreFileKit';
import { router } from '@kit.ArkUI';
import { scanBarcode, scanCore } from '@kit.ScanKit';
import { decodeQrCode, PixelData } from '../utils/QrDecoder';
import { BusinessError } from '@kit.BasicServicesKit';

@Entry
@Component
struct ScanPage {
  @State statusMsg: string = '选择扫码方式';
  @State scanResult: string = '';
  @State decoded: boolean = false;

  private scanOptions: scanBarcode.ScanOptions = {
    scanTypes: [scanCore.ScanType.ALL],
    enableMultiMode: false,
    enableAlbum: false,
  };

  build() {
    Column() {
      Row() {
        Button('< 返回')
          .fontSize(16).fontColor('#e2e8f0').backgroundColor('transparent')
          .onClick(() => { router.back(); })
        Text('二维码扫描').fontSize(18).fontWeight(700).fontColor('#ffffff')
          .layoutWeight(1).textAlign(TextAlign.Center)
        Blank().width(60)
      }
      .width('100%').padding({ top: 12, bottom: 8, left: 8, right: 8 })

      // 预览区
      Column() {
        Column()
          .width(260).height(260)
          .border({ width: 3, color: this.decoded ? '#48bb78' : '#3b7bbf' })
          .borderRadius(16).backgroundColor('#1a202c')
          .justifyContent(FlexAlign.Center)
        Text(this.statusMsg)
          .fontSize(13).fontColor('#e2e8f0').margin({ top: 16 })
          .textAlign(TextAlign.Center)
      }
      .width('100%').height(330)
      .justifyContent(FlexAlign.Center).alignItems(HorizontalAlign.Center)
      .backgroundColor('#0d1117')

      // 解码结果
      if (this.scanResult) {
        Column() {
          Text('✅ 解码成功').fontSize(14).fontColor('#48bb78').margin({ bottom: 8 })
          Text(this.scanResult)
            .fontSize(11).fontColor('#a0aec0').width('100%').maxLines(8)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .backgroundColor('#161b22').borderRadius(8).padding(10)
        }
        .width('100%').margin({ top: 8 }).padding({ left: 16, right: 16 })
      }

      // 按钮
      Column() {
        Button('📷 相机扫码')
          .width('100%').height(48).fontSize(16)
          .fontColor('#ffffff').backgroundColor('#3b7bbf').borderRadius(10)
          .margin({ top: 8 })
          .onClick(() => { this.startScan(); })

        Button('🖼 从相册选择')
          .width('100%').height(48).fontSize(16)
          .fontColor('#ffffff').backgroundColor('#2d3748').borderRadius(10)
          .margin({ top: 8 })
          .onClick(() => { this.pickFromAlbum(); })

        if (this.scanResult) {
          Button('✅ 使用此配置')
            .width('100%').height(48).fontSize(16)
            .fontColor('#ffffff').backgroundColor('#48bb78').borderRadius(10)
            .margin({ top: 8 })
            .onClick(() => {
              AppStorage.setOrCreate<string>('scanResult', this.scanResult);
              router.back();
            })
        }
      }
      .width('100%').padding({ left: 16, right: 16, bottom: 16 })
      .layoutWeight(1).backgroundColor('#0d1117')
    }
    .width('100%').height('100%').backgroundColor('#0d1117')
  }

  // ── 系统原生相机扫码 ──

  private async startScan(): Promise<void> {
    try {
      this.statusMsg = '正在打开扫码...';
      const context: common.UIAbilityContext = getContext(this) as common.UIAbilityContext;
      const result: scanBarcode.ScanResult =
        await scanBarcode.startScanForResult(context, this.scanOptions);

      this.scanResult = result.originalValue;
      this.statusMsg = '✅ 扫码成功！';
      this.decoded = true;
    } catch (err) {
      const bizErr: BusinessError = err as BusinessError;
      if (bizErr.code === 1000500002) {
        this.statusMsg = '扫码已取消';
      } else {
        this.statusMsg = '扫码失败，请用相册选图';
      }
    }
  }

  // ── 相册选图扫码 ──

  private async pickFromAlbum(): Promise<void> {
    try {
      const context: common.UIAbilityContext = getContext(this) as common.UIAbilityContext;
      const docPicker: picker.DocumentViewPicker = new picker.DocumentViewPicker(context);
      const uris: string[] = await docPicker.select({
        fileSuffixFilters: ['.jpg', '.jpeg', '.png', '.bmp'],
        maxSelectNumber: 1,
      });

      if (!uris || uris.length === 0) {
        this.statusMsg = '已取消选择';
        return;
      }

      this.statusMsg = '正在解码...';
      await this.decodeImage(uris[0]);
    } catch (err) {
      this.statusMsg = '选图失败';
    }
  }

  private async decodeImage(uri: string): Promise<void> {
    try {
      const imageSource: image.ImageSource = image.createImageSource(uri);
      const pixelMap: image.PixelMap = await imageSource.createPixelMap({
        desiredPixelFormat: image.PixelMapFormat.RGBA_8888,
        desiredSize: { width: 800, height: 800 },
      });

      const info: image.ImageInfo = await pixelMap.getImageInfo();
      const bufferSize: number = info.size.width * info.size.height * 4;
      const dst: ArrayBuffer = new ArrayBuffer(bufferSize);
      await pixelMap.readPixelsToBuffer(dst);

      const pixelData: PixelData = {
        width: info.size.width,
        height: info.size.height,
        data: new Uint8Array(dst),
      };

      const qrResult = decodeQrCode(pixelData);
      pixelMap.release();
      imageSource.release();

      if (qrResult.success) {
        this.scanResult = qrResult.text;
        this.statusMsg = '✅ QR 码解码成功！';
        this.decoded = true;
      } else {
        this.statusMsg = '❌ ' + (qrResult.error || '未找到有效 QR 码');
      }
    } catch (err) {
      this.statusMsg = '解码失败';
    }
  }
}
