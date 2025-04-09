/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef HISYS_EVENT_UTIL_H
#define HISYS_EVENT_UTIL_H

#include <string>
#include "print_job.h"

namespace OHOS::Print {
    class HisysEventUtil {
    public:
        static void reportBehaviorEvent(std::string name, int behaviorCode, const std::string &msg);

        static constexpr char HW_PRINT_SPOOLER[] = "PRINT_UE";
        static constexpr char BEHAVIOR_DESCRIPTION[] = "ACTION_TIME";
        static constexpr char DEVICE_TYPE[] = "PRINTER";
        static constexpr char INACTIVE[] = "0";
        static const int SEND_TASK = 1007;
    };
}   // namespace OHOS::Print
#endif // HISYS_EVENT_UTIL_H