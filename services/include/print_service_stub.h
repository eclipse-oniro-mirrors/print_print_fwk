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

#ifndef PRINT_SERVICE_STUB_H
#define PRINT_SERVICE_STUB_H

#include "iprint_service.h"
#include "iremote_stub.h"

namespace OHOS::Print {
class PrintServiceStub : public IRemoteStub<IPrintService> {
public:
    explicit PrintServiceStub();
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    bool OnStartPrint(MessageParcel &data, MessageParcel &reply);
    bool OnStopPrint(MessageParcel &data, MessageParcel &reply);
    bool OnEventOn(MessageParcel &data, MessageParcel &reply);
    bool OnEventOff(MessageParcel &data, MessageParcel &reply);
    bool OnFindPrinterExtension(MessageParcel &data, MessageParcel &reply);
    bool OnRegisterEvent(MessageParcel &data, MessageParcel &reply);
    bool OnQueryAllExtension(MessageParcel &data, MessageParcel &reply);
    bool OnLoadExtension(MessageParcel &data, MessageParcel &reply);
    bool OnStartDiscoverPrinter(MessageParcel &data, MessageParcel &reply);
    bool OnStopDiscoverPrint(MessageParcel &data, MessageParcel &reply);
    bool OnAddPrinters(MessageParcel &data, MessageParcel &reply);
    bool OnRemovePrinters(MessageParcel &data, MessageParcel &reply);
    bool OnUpdatePrinters(MessageParcel &data, MessageParcel &reply);
    bool OnConnectPrinter(MessageParcel &data, MessageParcel &reply);
    bool OnDisconnectPrinter(MessageParcel &data, MessageParcel &reply);
    bool OnRequestCapability(MessageParcel &data, MessageParcel &reply);
    bool OnStartPrintJob(MessageParcel &data, MessageParcel &reply);
    bool OnCancelPrintJob(MessageParcel &data, MessageParcel &reply);
    bool OnUpdatePrinterState(MessageParcel &data, MessageParcel &reply);
    bool OnUpdatePrintJobState(MessageParcel &data, MessageParcel &reply);
    bool OnUpdateExtensionInfo(MessageParcel &data, MessageParcel &reply);
    bool OnRequestPreview(MessageParcel &data, MessageParcel &reply);
    bool OnQueryPrinterCapability(MessageParcel &data, MessageParcel &reply);
    bool OnRegisterExtCallback(MessageParcel &data, MessageParcel &reply);
    bool OnUnregisterAllExtCallback(MessageParcel &data, MessageParcel &reply);
    bool OnLoadExtSuccess(MessageParcel &data, MessageParcel &reply);
    bool OnQueryAllPrintJob(MessageParcel &data, MessageParcel &reply);
    bool OnQueryPrintJobById(MessageParcel &data, MessageParcel &reply);
    bool OnAddPrinterToCups(MessageParcel &data, MessageParcel &reply);
    bool OnQueryPrinterCapabilityByUri(MessageParcel &data, MessageParcel &reply);
    bool OnPrintByAdapter(MessageParcel &data, MessageParcel &reply);
    bool OnStartGetPrintFile(MessageParcel &data, MessageParcel &reply);
    bool OnNotifyPrintService(MessageParcel &data, MessageParcel &reply);

private:
    using PrintCmdHandler = bool (PrintServiceStub::*)(MessageParcel &, MessageParcel &);
    std::map<uint32_t, PrintCmdHandler> cmdMap_;
};
} // namespace OHOS::Print
#endif // PRINT_SERVICE_STUB_H
