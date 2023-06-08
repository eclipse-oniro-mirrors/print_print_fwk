/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * class of print extensionAbility.
 *
 * @systemapi Hide this for inner system use.
 * @since 9
 * @syscap SystemCapability.Print.PrintFramework
 * @StageModelOnly
 */
import Want from './@ohos.application.Want';
import print from "./@ohos.print";


export default class PrintExtensionAbility {

  /**
   * Called once to initialize the extensionAbility.
   *
   * @systemapi Hide this for inner system use.
   * @since 9
   * @syscap SystemCapability.Print.PrintFramework
   * @return -
   * @StageModelOnly
   */
  onCreate(want: Want): void;

  /**
   * Called once to start to discover the printers connected with the device.
   *
   * @systemapi Hide this for inner system use.
   * @since 9
   * @syscap SystemCapability.Print.PrintFramework
   * @return -
   * @StageModelOnly
   */
  onStartDiscoverPrinter(): void;

  /**
   * Called once to stop discovering the printer.
   *
   * @systemapi Hide this for inner system use.
   * @since 9
   * @syscap SystemCapability.Print.PrintFramework
   * @return -
   * @StageModelOnly
   */
  onStopDiscoverPrinter(): void;

  /**
   * Called once to connect to the specific printer.
   *
   * @systemapi Hide this for inner system use.
   * @since 9
   * @syscap SystemCapability.Print.PrintFramework
   * @return -
   * @StageModelOnly
   */
  onConnectPrinter(printerId: number): void;

  /**
   * Called once to disconnect the specific printer.
   *
   * @systemapi Hide this for inner system use.
   * @since 9
   * @syscap SystemCapability.Print.PrintFramework
   * @return -
   * @StageModelOnly
   */
  onDisconnectPrinter(printerId: number): void;

  /**
   * Called once to start print job.
   *
   * @systemapi Hide this for inner system use.
   * @since 9
   * @syscap SystemCapability.Print.PrintFramework
   * @return -
   * @StageModelOnly
   */
  onStartPrintJob(jobInfo: print.PrintJob): void;

  /**
   * Called once to remove the print job has been started.
   *
   * @systemapi Hide this for inner system use.
   * @since 9
   * @syscap SystemCapability.Print.PrintFramework
   * @return -
   * @StageModelOnly
   */
  onCancelPrintJob(jobInfo: print.PrintJob): void;

  /**
   * Called once to request the capability of the printer.
   *
   * @systemapi Hide this for inner system use.
   * @since 9
   * @syscap SystemCapability.Print.PrintFramework
   * @return -
   * @StageModelOnly
   */
  onRequestPrinterCapability(printerId: number): print.PrinterCapability;

  /**
   * Called once to request preview and send result to Print SA.
   *
   * @systemapi Hide this for inner system use.
   * @since 9
   * @syscap SystemCapability.Print.PrintFramework
   * @return -
   * @StageModelOnly
   */
  onRequestPreview(jobInfo: print.PrintJob): string;

  /**
   * Called once to finalize the extensionAbility.
   *
   * @systemapi Hide this for inner system use.
   * @since 9
   * @syscap SystemCapability.Print.PrintFramework
   * @return -
   * @StageModelOnly
   */
  onDestroy(): void;
}