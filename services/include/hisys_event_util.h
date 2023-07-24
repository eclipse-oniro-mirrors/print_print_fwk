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

namespace OHOS::Print {
    class HisysEventUtil {
    public:
        static void reportPrintSuccess(const std::string &msg);

        static void faultPrint(std::string scene, std::string msg);

    private:
        static constexpr char HW_PRINT_SPOOLER[] = "PRINT";
        static const int PRINT_SUCCESS = 1003;
        static const int FAULT_PRINT = 3002;

        static void reportBehaviorEvent(std::string name, int behaviorCode, const std::string &msg);

        static void reportFaultEvent(std::string name, int faultCode, std::string scene, std::string msg);
    };
}   // namespace OHOS::Print
#endif // HISYS_EVENT_UTIL_H