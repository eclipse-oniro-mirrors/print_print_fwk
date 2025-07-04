/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "print_entry.h"
#include "print_log.h"
#include "print_constant.h"
#include "print_manager_client.h"
#include "print_utils.h"
#include "ability.h"
#include "ui_ability_thread.h"

namespace OHOS::Print {
static const std::string SPOOLER_BUNDLE_NAME = "com.ohos.spooler";
static const std::string SPOOLER_PREVIEW_ABILITY_NAME = "PrintServiceExtAbility";
static const std::string LAUNCH_PARAMETER_JOB_ID = "jobId";
static const std::string LAUNCH_PARAMETER_FILE_LIST = "fileList";
static const std::string UI_EXTENSION_TYPE_NAME = "ability.want.params.uiExtensionType";
static const std::string PRINT_UI_EXTENSION_TYPE = "sysDialog/print";
static const std::string CALLER_PKG_NAME = "caller.pkgName";
static const std::string ABILITY_PARAMS_STREAM = "ability.params.stream";

PrintEntry::PrintEntry() {}

PrintEntry::~PrintEntry() {}

std::shared_ptr<PrintEntry> PrintEntry::GetInstance()
{
    static std::shared_ptr<PrintEntry> instance = std::make_shared<PrintEntry>();
    return instance;
}

int32_t PrintEntry::StartPrint(const std::vector<std::string>& files)
{
    std::vector<uint32_t> fdList;
    if (files.empty()) {
        PRINT_HILOGE("fileList and fdList are both empty");
        return E_PRINT_INVALID_PARAMETER;
    }
    for (auto file : files) {
        int32_t fd = PrintUtils::OpenFile(file);
        if (fd < 0) {
            PRINT_HILOGE("file[%{private}s] is invalid", file.c_str());
            return E_PRINT_INVALID_PARAMETER;
        }
        fdList.emplace_back(fd);
    }

    PRINT_HILOGI("call client's StartPrint interface.");
    std::string jobId = PrintUtils::GetPrintJobId();
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    adapterParam->isCheckFdList = true;
    adapterParam->jobId = jobId;
    int32_t ret = CallSpooler(adapterParam, files);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("CallSpooler error");
        return ret;
    }
    return PrintManagerClient::GetInstance()->StartPrint(files, fdList, jobId);
}

int32_t PrintEntry::On(const std::string& type)
{
    PRINT_HILOGI("PrintEntry On");
    return E_PRINT_NONE;
}

int32_t PrintEntry::Off(const std::string& type)
{
    PRINT_HILOGI("PrintEntry Off");
    return E_PRINT_NONE;
}

int32_t PrintEntry::CallSpooler(const std::shared_ptr<AdapterParam> &adapterParam,
    const std::vector<std::string>& files)
{
    PRINT_HILOGI("enter CallSpooler.");
    AAFwk::Want want;
    want.SetElementName(SPOOLER_BUNDLE_NAME, SPOOLER_PREVIEW_ABILITY_NAME);
    want.SetParam(LAUNCH_PARAMETER_JOB_ID, adapterParam->jobId);
    want.SetParam(LAUNCH_PARAMETER_FILE_LIST, files);
    PrintUtils::BuildAdapterParam(adapterParam, want);
    int32_t callerTokenId = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    int32_t callerUid = IPCSkeleton::GetCallingUid();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    std::string callerPkg = PrintUtils::GetBundleNameForUid(callerUid);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_TOKEN, callerTokenId);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_UID, callerUid);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_PID, callerPid);
    want.SetParam(CALLER_PKG_NAME, callerPkg);
    want.SetParam(UI_EXTENSION_TYPE_NAME, PRINT_UI_EXTENSION_TYPE);
    want.SetParam(ABILITY_PARAMS_STREAM, files);
    want.SetFlags(AAFwk::Want::FLAG_AUTH_READ_URI_PERMISSION);
    return E_PRINT_NONE;
}

} // namespace OHOS::Print
