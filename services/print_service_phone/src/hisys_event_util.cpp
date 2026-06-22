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
#include "print_job.h"

namespace OHOS::Print {
    using namespace OHOS::HiviewDFX;

    void HisysEventUtil::reportBehaviorEvent(std::string packageName, int behaviorCode, const std::string &msg)
    {
        HiSysEventWrite(
            HW_PRINT_SPOOLER,
            BEHAVIOR_DESCRIPTION,
            HiSysEvent::EventType::BEHAVIOR,
            PACKAGE_NAME, packageName,
            PROCESS_NAME, packageName,
            BEHAVIOR_CODE, behaviorCode,
            DEVICE_TYPE, DEVICE_TYPE_VALUE,
            ACTION, behaviorCode,
            START_TIME, INACTIVE,
            END_TIME, INACTIVE,
            START_TIME, INACTIVE,
            MSG, msg);
    }

    void HisysEventUtil::ReportFailureEvent(const HisysEventParams &params)
    {
        switch (params.eventType) {
            case HisysEventType::PRINT_FAILURE:
                ReportPrintFailure(params.subState, params.resourceKey);
                break;
            case HisysEventType::CONNECT_FAILURE:
                ReportConnectFailure(params.resourceKey, params.printerModel);
                break;
            default:
                break;
        }
    }

    void HisysEventUtil::ReportConnectFailure(const std::string &resourceKey, const std::string &printerModel)
    {
        if (!resourceKey.empty()) {
            HiSysEventWrite(
                PRINT_DOMAIN,
                CONNECT_EXCEPTION_FAULT_EVENT,
                HiSysEvent::EventType::FAULT,
                MSG, resourceKey,
                PVERSIONID, printerModel.empty() ? "unknown" : printerModel
            );
        }
    }

    void HisysEventUtil::ReportPrintFailure(uint32_t subState, const std::string &resourceKey)
    {
        if (!resourceKey.empty()) {
            HiSysEventWrite(
                PRINT_DOMAIN,
                PRINT_EXCEPTION_FAULT_EVENT,
                HiSysEvent::EventType::FAULT,
                MSG, resourceKey,
                FAULT_CODE, static_cast<int32_t>(subState)
            );
        }
    }
}