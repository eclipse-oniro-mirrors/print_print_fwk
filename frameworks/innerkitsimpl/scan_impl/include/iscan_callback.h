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

#ifndef ISCAN_CALLBACK_H
#define ISCAN_CALLBACK_H

#include "iremote_broker.h"
#include "iremote_object.h"
#include "scanner_info.h"

namespace OHOS::Scan {
class IScanCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Scan.IScanCallback");
    virtual bool OnCallback(uint32_t state, const ScanDeviceInfo &info) = 0;
    virtual bool OnCallbackSync(uint32_t state, const ScanDeviceInfoSync &info) = 0;
    virtual bool OnGetDevicesList(std::vector<ScanDeviceInfo> &info) = 0;
};

enum {
    SCAN_CALLBACK_DEVICE,
    SCAN_CALLBACK_DEVICE_SYNC,
    SCAN_CALLBACK_DEVICE_LIST,
};
} // namespace OHOS::Scan
#endif // ISCAN_CALLBACK_H
