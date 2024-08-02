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

#include "hisysevent.h"
#include "print_log.h"
#include "hisys_event_util.h"

namespace OHOS::Print {
    using namespace OHOS::HiviewDFX;

    void HisysEventUtil::reportBehaviorEvent(std::string name, int behaviorCode, const std::string &msg)
    {
        HiSysEventWrite(
            HW_PRINT_SPOOLER,
            name,
            HiSysEvent::EventType::BEHAVIOR,
            "PACKAGE_NAME", "com.ohos.spooler",
            "PROCESS_NAME", "hwPrintSpooler",
            "BEHAVIOR_CODE", behaviorCode,
            "MSG", msg);
    }

    void HisysEventUtil::reportFaultEvent(std::string name, int faultCode, std::string scene, std::string msg)
    {
        HiSysEventWrite(
            HW_PRINT_SPOOLER,
            name,
            HiSysEvent::EventType::FAULT,
            "PACKAGE_NAME", "com.ohos.spooler",
            "PROCESS_NAME", "hwPrintSpooler",
            "FAULT_CODE", faultCode,
            "SCENE", scene,
            "MSG", msg);
    }

    void HisysEventUtil::reportPrintSuccess(const std::string &msg)
    {
        reportBehaviorEvent("PRINT_SUCCESS", PRINT_SUCCESS, msg);
    }

    void HisysEventUtil::faultPrint(std::string scene, std::string msg)
    {
        reportFaultEvent("PRINT_EXCEPTION", FAULT_PRINT, scene, msg);
    }
}