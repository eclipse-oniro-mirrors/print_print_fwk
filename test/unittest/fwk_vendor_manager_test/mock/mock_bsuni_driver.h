/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef MOCK_BSUNI_DRIVER_H
#define MOCK_BSUNI_DRIVER_H

#include <gmock/gmock.h>
#include "vendor_bsuni_driver.h"

namespace OHOS {
namespace Print {
class MockBsuniDriver {
public:
    MOCK_METHOD2(OnCreate, int32_t(const Print_ServiceAbility *, const char *cupsPath));
    MOCK_METHOD0(OnDestroy, int32_t());
    MOCK_METHOD0(OnStartDiscovery, int32_t());
    MOCK_METHOD0(OnStopDiscovery, int32_t());
    MOCK_METHOD1(OnConnectPrinter, int32_t(const char *));
    MOCK_METHOD1(OnDisconnectPrinter, int32_t(const char *));
    MOCK_METHOD1(OnQueryCapability, int32_t(const char *));
    MOCK_METHOD2(OnQueryCapabilityByIp, int32_t(const char *, const char *protocol));
    MOCK_METHOD2(OnQueryProperties, int32_t(const char *, const Print_StringList *));
};
}  // namespace Print
}  // namespace OHOS
#endif  // MOCK_BSUNI_DRIVER_H
