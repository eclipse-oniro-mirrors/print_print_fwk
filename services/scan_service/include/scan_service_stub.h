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

#ifndef SCAN_SERVICE_STUB_H
#define SCAN_SERVICE_STUB_H

#include "iscan_service.h"
#include "iremote_stub.h"

namespace OHOS::Scan {
class ScanServiceStub : public IRemoteStub<IScanService> {
public:
    explicit ScanServiceStub();
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    bool OnInitScan(MessageParcel &data, MessageParcel &reply);
    bool OnExitScan(MessageParcel &data, MessageParcel &reply);
    bool OnGetScannerList(MessageParcel &data, MessageParcel &reply);
    bool OnStopDiscover(MessageParcel &data, MessageParcel &reply);
    bool OnOpenScanner(MessageParcel &data, MessageParcel &reply);
    bool OnCloseScanner(MessageParcel &data, MessageParcel &reply);
    bool OnGetScanOptionDesc(MessageParcel &data, MessageParcel &reply);
    bool OnOpScanOptionValue(MessageParcel &data, MessageParcel &reply);
    bool OnGetScanParameters(MessageParcel &data, MessageParcel &reply);
    bool OnStartScan(MessageParcel &data, MessageParcel &reply);
    bool OnGetSingleFrameFD(MessageParcel &data, MessageParcel &reply);
    bool OnCancelScan(MessageParcel &data, MessageParcel &reply);
    bool OnSetScanIOMode(MessageParcel &data, MessageParcel &reply);
    bool OnGetScanSelectFd(MessageParcel &data, MessageParcel &reply);
    bool OnGetScannerState(MessageParcel &data, MessageParcel &reply);
    bool OnGetScanProgress(MessageParcel &data, MessageParcel &reply);
    bool OnConnectScanner(MessageParcel &data, MessageParcel &reply);
    bool OnDisConnectScanner(MessageParcel &data, MessageParcel &reply);
    bool OnGetConnectedScanner(MessageParcel &data, MessageParcel &reply);
    bool OnUpdateScannerName(MessageParcel &data, MessageParcel &reply);

    bool OnEventOn(MessageParcel &data, MessageParcel &reply);
    bool OnEventOff(MessageParcel &data, MessageParcel &reply);

private:
    using ScanCmdHandler = bool (ScanServiceStub::*)(MessageParcel &, MessageParcel &);
    std::map<uint32_t, ScanCmdHandler> cmdMap_;
    bool isSaneInit_ = false;
    std::mutex lock_;
};
} // namespace OHOS::Scan
#endif // SCAN_SERVICE_STUB_H
