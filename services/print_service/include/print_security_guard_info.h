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

#ifndef PRINT_SECURITY_GUARD_INFO_H
#define PRINT_SECURITY_GUARD_INFO_H

#include <string>
#include <vector>

#include <json/json.h>

#ifdef SECURITY_GUARDE_ENABLE
#include "sg_collect_client.h"
#include "time_service_client.h"
#include "event_info.h"
#endif

#include "print_security_guard_util.h"
#include "printer_info.h"
#include "print_job.h"
#include "print_constant.h"
#include "print_json_util.h"

namespace OHOS::Print {
class PrintSecurityGuardInfo {
struct PrintTypeInfo {
    int32_t port = 631;
    int32_t copyNumber = 1;
    int32_t printPages = 1;
    std::string ip;
    std::string mac;
    std::string domain;
    std::string name;
};

public:
    PrintSecurityGuardInfo(const std::string callPkg, const std::vector<std::string> &fileList);
    std::string ToJsonStr();
    void SetPrintTypeInfo(const PrinterInfo &printerInfo, const PrintJob &printJob);

private:
    int32_t subType_{};
    std::string caller_{};
    std::string objectInfo_{};
    std::string outcome_{};
    std::string bootTime_{};
    std::string wallTime_{};
    std::string targetInfo_{};
    std::string sourceInfo_{};
    std::string extra_{};
    std::string jobName_{};
    PrintTypeInfo printTypeInfo_;

    Json::Value ToJson();
};
} // namespace OHOS::Print

#endif // PRINT_SECURITY_GUARD_INFO_H