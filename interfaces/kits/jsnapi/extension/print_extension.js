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

class PrintExtension {
  onCreated(want) {
    console.log('onCreated, want:' + want.abilityName);
  }

  onStartDiscoverPrinter() {
    console.log('onStartDiscoverPrinter');
  }

  onStopDiscoverPrinter() {
    console.log('onStopDiscoverPrinter');
  }

  onConnectPrinter(printerId) {
    console.log('onConnectPrinter:' + printerId);
  }

  onDisconnectPrinter(printerId) {
    console.log('onDisconnectPrinter');
  }

  onStartPrintJob(jobInfo) {
    console.log('onStartPrintJob');
  }

  onCancelPrintJob(jobInfo) {
    console.log('onCancelPrintJob');
  }

  onRequestPrinterCapability(printerId) {
    console.log('onRequestPrinterCapability:' + printerId);
  }

  onRequestPreview(jobInfo) {
    console.log('onRequestPreview');
  }

  onDestroy() {
    console.log('onDestroy');
  }
}

export default PrintExtension;
