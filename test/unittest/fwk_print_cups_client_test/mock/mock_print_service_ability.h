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

#ifndef MOCK_PRINT_SERVICE_ABILITY_H
#define MOCK_PRINT_SERVICE_ABILITY_H

#include <gmock/gmock.h>
#include "print_service_ability.h"

namespace OHOS {
namespace Print {
class MockPrintServiceAbility final : public PrintServiceAbility {
public:
    MOCK_METHOD1(QueryDiscoveredPrinterInfoById, std::shared_ptr<PrinterInfo>(const std::string &));
};
}  // namespace Print
}  // namespace OHOS
#endif  // MOCK_PRINT_SERVICE_ABILITY_H
