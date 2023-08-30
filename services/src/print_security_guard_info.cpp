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

#include "print_security_guard_manager.h"
#include "print_log.h"

namespace OHOS::Print {
using json = nlohmann::json;
static const int32_t SPLIT_INDEX = 2;

PrintSecurityGuardInfo::PrintSecurityGuardInfo(const std::string callPkg, const std::vector<std::string> &fileList)
{
    caller_ = callPkg;
    objectInfo_ = PrintUtil::ParseListToString(fileList);
#ifdef SECURITY_GUARDE_ENABLE
    OHOS::MiscServices::TimeServiceClient *tsc = OHOS::MiscServices::TimeServiceClient::GetInstance();
    if (tsc != nullptr) {
        wallTime_ = std::to_string(tsc->GetWallTimeNs());
        bootTime_ = std::to_string(tsc->GetBootTimeNs());
        PRINT_HILOGI("PrintSecurityGuardInfo wallTime_:%{public}s bootTime_:%{public}s", wallTime_.c_str(),
            bootTime_.c_str());
    }
#endif
}

void PrintSecurityGuardInfo::setPrintTypeInfo(const PrinterInfo &printerInfo, const PrintJob &printJob)
{
    std::string printerId = printerInfo.GetPrinterId();
    std::string description = printerInfo.GetDescription();
    printTypeInfo_.ip = PrintUtil::SplitStr(description, '&', SPLIT_INDEX);
    printTypeInfo_.mac = PrintUtil::SplitStr(printerId, '/', SPLIT_INDEX);
    subType_ = PrintSecurityGuardUtil::GetPrinterType(printerId);
    printTypeInfo_.domain = "";
    if (subType_ == FROM_EPRINT) {
        if (json::accept(printerInfo.GetOption())) {
            json optionJson = json::parse(printerInfo.GetOption());
            if (optionJson.contains("ePrintUrl") && optionJson["ePrintUrl"].is_string()) {
                printTypeInfo_.domain = optionJson["ePrintUrl"].get<std::string>();
            }
        }
    }

    uint32_t subState = printJob.GetSubState();
    switch (subState) {
        case PRINT_JOB_COMPLETED_SUCCESS:
            outcome_ = "success";
            break;
        case PRINT_JOB_COMPLETED_CANCELLED:
            outcome_ = "canceled";
            break;
        case PRINT_JOB_COMPLETED_FAILED:
            outcome_ = "failed";
            break;
        default:
            break;
    }
}

nlohmann::json PrintSecurityGuardInfo::ToJson()
{
    nlohmann::json printTypeInfoJson;
    printTypeInfoJson["ip"] = printTypeInfo_.ip;
    printTypeInfoJson["port"] = printTypeInfo_.port;
    printTypeInfoJson["mac"] = printTypeInfo_.mac;
    printTypeInfoJson["domain"] = printTypeInfo_.domain;
    printTypeInfoJson["name"] = printTypeInfo_.name;
    targetInfo_ = printTypeInfoJson.dump();

    nlohmann::json securityGuardInfoJson;
    securityGuardInfoJson["type"] = 0;
    securityGuardInfoJson["subType"] = subType_;
    securityGuardInfoJson["caller"] = caller_;
    securityGuardInfoJson["objectInfo"] = objectInfo_;
    securityGuardInfoJson["bootTime"] = bootTime_;
    securityGuardInfoJson["wallTime"] = wallTime_;
    securityGuardInfoJson["outcome"] = outcome_;
    securityGuardInfoJson["sourceInfo"] = sourceInfo_;
    securityGuardInfoJson["targetInfo"] = targetInfo_;
    securityGuardInfoJson["extra"] = extra_;
    return securityGuardInfoJson;
}

std::string PrintSecurityGuardInfo::ToJsonStr()
{
    return ToJson().dump();
}
} // namespace OHOS::Print

