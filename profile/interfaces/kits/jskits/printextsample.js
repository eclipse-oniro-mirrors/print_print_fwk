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

import Extension from '@ohos.PrintExtensionAbility'
import print from '@ohos.print'

let MODULE_TAG = "hwprintext"
export default class PrintExtAbility extends Extension {
	Array<PrinterInfo> printerList；
    onCreated(want) {
        console.info(MODULE_TAG + 'ability on created start');
    }

    onStartDiscoverPrinter() {
        console.info(MODULE_TAG + "ability start to discover printer";
        if (hasFoundDevice) {
			print.addPrinters(printerList);
        }
    }
	
    onStopDiscoverPrinter() {
        console.info(MODULE_TAG + 'ability stop discovering printer');
    }	

    onDestroy() {
        console.info(MODULE_TAG + 'ability on destroy');
    }
	
	onConnectPrinter(printerId) {
		console.info(MODULE_TAG + 'ability connect the speci1 printer');
	}
	
	onDisconnectPrinter(printerId) {
		console.info(MODULE_TAG + 'ability disconnect the speci1 printer');
	}	
	
	onStartPrintJob(jobInfo) {
        console.info(MODULE_TAG + 'ability start Print Job');		
	}
	
	onCancelPrintJob(jobInfo) {
        console.info(MODULE_TAG + 'ability cancel Print Job');		
	}
	
	onRequestPrinterCapability(printerId) {
		console.info(MODULE_TAG + 'ability request printer capability');
		var capability = GetDeviceCapability(printerId);
		return capability;
	}
	
	onRequestPreview(jobInfo) {
		console.info(MODULE_TAG + 'ability request printer preview');
		FileDescriptor fd = print.OpenFile(jobInfo.preview.result);
		SavePreviewToFile(fd);
		return jobInfo.preview.result;
	}
};