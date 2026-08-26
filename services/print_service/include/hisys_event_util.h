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
#include <cstdint>
#include "print_job.h"

namespace OHOS::Print {

    enum class HisysEventType {
        PRINT_FAILURE,
        CONNECT_FAILURE
    };

    struct HisysEventParams {
        HisysEventType eventType;
        std::string resourceKey;
        uint32_t subState = 0;
        std::string printerModel;
    };

    class HisysEventUtil {
    public:
        static void reportBehaviorEvent(std::string name, int behaviorCode, const std::string &msg);
        static void ReportFailureEvent(const HisysEventParams &params);
        static const int SEND_TASK = 1007;
    private:
        static void ReportPrintFailure(uint32_t subState, const std::string &resourceKey);
        static void ReportConnectFailure(const std::string &resourceKey, const std::string &printerModel = "");
        static constexpr char HW_PRINT_SPOOLER[] = "PRINT_UE";
        static constexpr char BEHAVIOR_DESCRIPTION[] = "ACTION_TIME";
        static constexpr char DEVICE_TYPE_VALUE[] = "PRINTER";
        static constexpr char INACTIVE[] = "0";
        static constexpr char CONNECT_EXCEPTION_FAULT_EVENT[] = "CONNECT_EXCEPTION";
        static constexpr char PRINT_DOMAIN[] = "PRINT";
        static constexpr char PRINT_EXCEPTION_FAULT_EVENT[] = "PRINT_EXCEPTION";
        static constexpr char PACKAGE_NAME[] = "PACKAGE_NAME";
        static constexpr char PROCESS_NAME[] = "PROCESS_NAME";
        static constexpr char BEHAVIOR_CODE[] = "BEHAVIOR_CODE";
        static constexpr char DEVICE_TYPE[] = "DEVICE_TYPE";
        static constexpr char ACTION[] = "ACTION";
        static constexpr char START_TIME[] = "START_TIME";
        static constexpr char END_TIME[] = "END_TIME";
        static constexpr char MSG[] = "MSG";
        static constexpr char PVERSIONID[] = "PVERSIONID";
        static constexpr char FAULT_CODE[] = "FAULT_CODE";
    };
}   // namespace OHOS::Print
#endif // HISYS_EVENT_UTIL_H