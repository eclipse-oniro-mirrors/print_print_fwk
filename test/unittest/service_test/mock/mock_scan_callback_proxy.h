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

#ifndef MOCK_SCAN_CALLBACK_PROXY_H
#define MOCK_SCAN_CALLBACK_PROXY_H

#include <gmock/gmock.h>
#include "scan_callback_proxy.h"

namespace OHOS {
namespace Scan {
class MockScanCallbackProxy final : public ScanCallbackProxy {
public:
    MockScanCallbackProxy() : ScanCallbackProxy(nullptr) {}
    MOCK_METHOD2(OnCallback, bool(uint32_t, const ScanDeviceInfo &));
};
}  // namespace Print
}  // namespace OHOS
#endif  // MOCK_PRINT_CALLBACK_PROXY_H
