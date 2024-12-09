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

#ifndef MOCK_VENDOR_PPD_DRIVER_H
#define MOCK_VENDOR_PPD_DRIVER_H

#include <gmock/gmock.h>
#include "vendor_ppd_driver.h"

namespace OHOS {
namespace Print {
class MockVendorPpdDriver {
public:
    MOCK_METHOD2(OnQueryCapability, bool(const std::string &, int));
    MOCK_METHOD2(OnQueryProperties, bool(const std::string &, const std::vector<std::string> &));
};
}  // namespace Print
}  // namespace OHOS
#endif  // MOCK_VENDOR_PPD_DRIVER_H
