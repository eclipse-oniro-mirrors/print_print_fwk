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

#ifndef SCAN_CALLBACK_STUB_H
#define SCAN_CALLBACK_STUB_H
#define TDD_ENABLE 1

#include "iscan_callback.h"
#include "iremote_stub.h"
#include <map>

namespace OHOS::Scan {
class ScanCallbackStub : public IRemoteStub<IScanCallback> {
public:
    ScanCallbackStub();
    virtual ~ScanCallbackStub() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

#ifndef TDD_ENABLE
private:
#endif
    bool HandleDeviceInfoTcpEvent(MessageParcel &data, MessageParcel &reply);
    bool HandleDeviceInfoEvent(MessageParcel &data, MessageParcel &reply);
    bool HandleDeviceInfoSyncEvent(MessageParcel &data, MessageParcel &reply);
    bool HandleGetFrameResEvent(MessageParcel &data, MessageParcel &reply);
    bool HandleScanInitEvent(MessageParcel &data, MessageParcel &reply);
    bool HandleSendSearchMessage(MessageParcel &data, MessageParcel &reply);
    bool HandleSendDeviceList(MessageParcel &data, MessageParcel &reply);
#ifndef TDD_ENABLE
private:
#endif
    using SCAN_EVENT_HANDLER = bool (ScanCallbackStub::*)(MessageParcel &, MessageParcel &);
    std::map<uint32_t, SCAN_EVENT_HANDLER> cmdMap_;
};
} // namespace OHOS::Scan
#endif // SCAN_CALLBACK_STUB_H
