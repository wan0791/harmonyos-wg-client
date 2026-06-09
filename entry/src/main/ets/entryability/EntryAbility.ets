import { AbilityConstant, UIAbility, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { window } from '@kit.ArkUI';

const DOMAIN = 0x0000;

export default class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(DOMAIN, 'WgClient', 'Ability onCreate');
  }

  onDestroy(): void {
    hilog.info(DOMAIN, 'WgClient', 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    hilog.info(DOMAIN, 'WgClient', 'Ability onWindowStageCreate');
    windowStage.loadContent('pages/Index');
  }

  onWindowStageDestroy(): void {
    hilog.info(DOMAIN, 'WgClient', 'Ability onWindowStageDestroy');
  }

  onForeground(): void {
    hilog.info(DOMAIN, 'WgClient', 'Ability onForeground');
  }

  onBackground(): void {
    hilog.info(DOMAIN, 'WgClient', 'Ability onBackground');
  }
}
