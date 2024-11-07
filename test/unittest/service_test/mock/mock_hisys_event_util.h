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

#ifndef MOCK_HISYS_EVENT_UTIL_H
#define MOCK_HISYS_EVENT_UTIL_H

#include <gmock/gmock.h>
#include "hisys_event_util.h"

namespace OHOS {
namespace Print {
class MockHisysEventUtil {
public:
    MOCK_METHOD3(reportBehaviorEvent, void (std::string name, int behaviorCode, const std::string &msg));
    MOCK_METHOD4(reportFaultEvent, void (std::string name, int faultCode, std::string scene, std::string msg));
};
}  // namespace Print
}  // namespace OHOS
#endif  // MOCK_HISYS_EVENT_UTIL_H