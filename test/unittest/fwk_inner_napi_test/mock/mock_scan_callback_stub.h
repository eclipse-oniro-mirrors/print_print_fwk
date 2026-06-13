/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef MOCK_SCAN_CALLBACK_STUB_H
#define MOCK_SCAN_CALLBACK_STUB_H

#include <gmock/gmock.h>
#include "scan_callback_stub.h"

namespace OHOS::Scan {
class DummyScanCallbackStub : public ScanCallbackStub {
public:
    bool OnCallback(uint32_t state, const ScanDeviceInfo &info) override
    {
        return true;
    }
    bool OnCallbackSync(uint32_t state, const ScanDeviceInfoSync &info) override
    {
        return true;
    }
    bool OnGetDevicesList(std::vector<ScanDeviceInfo> &infos) override
    {
        return true;
    }
};

class MockScanCallbackStub final : public DummyScanCallbackStub {
public:
    MOCK_METHOD2(OnCallback, bool(uint32_t, const ScanDeviceInfo &));
    MOCK_METHOD2(OnCallbackSync, bool(uint32_t, const ScanDeviceInfoSync &));
    MOCK_METHOD1(OnGetDevicesList, bool(std::vector<ScanDeviceInfo> &));
};
}  // namespace OHOS::Scan
#endif  // MOCK_SCAN_CALLBACK_STUB_H