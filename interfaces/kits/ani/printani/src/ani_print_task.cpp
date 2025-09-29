/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "accesstoken_kit.h"
#include "ani_print_task.h"
#include "print_log.h"
#include "print_manager_client.h"

namespace OHOS::Print {
using namespace Security::AccessToken;
static const std::string SPOOLER_BUNDLE_NAME = "com.ohos.spooler";
static const std::string SPOOLER_PREVIEW_ABILITY_NAME = "PrintServiceExtAbility";
static const std::string LAUNCH_PARAMETER_JOB_ID = "jobId";
static const std::string LAUNCH_PARAMETER_FILE_LIST = "fileList";
static const std::string UI_EXTENSION_TYPE_NAME = "ability.want.params.uiExtensionType";
static const std::string PRINT_UI_EXTENSION_TYPE = "sysDialog/print";
static const std::string CALLER_PKG_NAME = "caller.pkgName";
static const std::string ABILITY_PARAMS_STREAM = "ability.params.stream";
static const int32_t MAX_FILE_LIST_SIZE = 100;
AniPrintTask::AniPrintTask(ani_env *env)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is a nullptr");
        return;
    }
    ani_vm *vm = nullptr;
    env->GetVM(&vm);
    aniVm_ = vm;
    jobId_ = PrintUtils::GetPrintJobId();
}

AniPrintTask::~AniPrintTask()
{
    aniVm_ = nullptr;
}

int32_t AniPrintTask::StartPrint(const std::vector<std::string>& files)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to StartPrint");
        return E_PRINT_NO_PERMISSION;
    }
    if (files.empty()) {
        PRINT_HILOGE("fileList and fdList are both empty");
        return E_PRINT_INVALID_PARAMETER;
    }
    FdListWrapper fdList;
    if (files.begin()->find("fd://") == 0) {
        PRINT_HILOGD("list type: fdlist");
        for (auto fdPath : files) {
            uint32_t fd = PrintUtils::GetIdFromFdPath(fdPath);
            fdList.Add(fd);
        }
    } else if (files.begin()->find("file://") == 0) {
        PRINT_HILOGD("starts_with file://");
        return E_PRINT_INVALID_PARAMETER;
    } else {
        PRINT_HILOGD("list type: filelist");
        for (auto file : files) {
            int32_t fd = PrintUtils::OpenFile(file);
            if (fd < 0) {
                PRINT_HILOGE("file[%{private}s] is invalid", file.c_str());
                return E_PRINT_INVALID_PARAMETER;
            }
            fdList.Add(fd);
        }
    }
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    adapterParam->jobId = jobId_;
    adapterParam->documentName = "";
    adapterParam->isCheckFdList = true;
    return PrintManagerClient::GetInstance()->StartPrint(files, fdList.Get(), jobId_);
}

int32_t AniPrintTask::StartPrintWithContext(const std::vector<std::string>& files,
    std::shared_ptr<AbilityRuntime::Context> ctx)
{
    if (files.empty()) {
        PRINT_HILOGE("fileList and fdList are both empty");
        return E_PRINT_INVALID_PARAMETER;
    }
    FdListWrapper fdList;
    if (files.begin()->find("fd://") == 0) {
        PRINT_HILOGD("list type: fdlist");
        for (auto fdPath : files) {
            uint32_t fd = PrintUtils::GetIdFromFdPath(fdPath);
            fdList.Add(fd);
        }
    } else if (files.begin()->find("file://") == 0) {
        PRINT_HILOGD("starts_with file://");
    } else {
        PRINT_HILOGD("list type: filelist");
        for (auto file : files) {
            int32_t fd = PrintUtils::OpenFile(file);
            if (fd < 0) {
                PRINT_HILOGE("file[%{private}s] is invalid", file.c_str());
                return E_PRINT_INVALID_PARAMETER;
            }
            fdList.Add(fd);
        }
    }
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    adapterParam->jobId = jobId_;
    adapterParam->documentName = "";
    adapterParam->isCheckFdList = true;
    uint32_t ret = CallSpooler(adapterParam, files, ctx);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("CallSpooler fail");
        return ret;
    }
    return PrintManagerClient::GetInstance()->StartPrint(files, fdList.Get(), jobId_);
}

int32_t AniPrintTask::StartPrintWithAttributes(const std::string& jobName, std::shared_ptr<AbilityRuntime::Context> ctx,
    const PrintAttributes& attributes, const sptr<IPrintCallback> &listener)
{
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    adapterParam->documentName = jobName;
    adapterParam->isCheckFdList = false;
    adapterParam->printAttributes = attributes;
    adapterParam->jobId = jobId_;
    uint32_t ret = CallSpooler(adapterParam, {}, ctx);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("CallSpooler fail");
        return ret;
    }
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(ctx);
    if (abilityContext == nullptr) {
        PRINT_HILOGE("abilityContext is a nullptr");
        return E_PRINT_INVALID_PARAMETER;
    }
    sptr<IRemoteObject> callerToken = abilityContext->GetToken();
    return PrintManagerClient::GetInstance()->Print(
        jobName, listener, attributes, jobId_, callerToken);
}

uint32_t AniPrintTask::CallSpooler(const std::shared_ptr<AdapterParam>& adapterParam,
    const std::vector<std::string>& files, std::shared_ptr<AbilityRuntime::Context> ctx)
{
    PRINT_HILOGI("enter CallSpooler.");
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service, ErrorCode:[%{public}d]", E_PRINT_NO_PERMISSION);
        return E_PRINT_NO_PERMISSION;
    }
    if (adapterParam == nullptr || ctx == nullptr) {
        PRINT_HILOGE("Invalid parameters");
        return E_PRINT_INVALID_PARAMETER;
    }
    AAFwk::Want want;
    want.SetElementName(SPOOLER_BUNDLE_NAME, SPOOLER_PREVIEW_ABILITY_NAME);
    want.SetParam(LAUNCH_PARAMETER_JOB_ID, adapterParam->jobId);
    want.SetParam(LAUNCH_PARAMETER_FILE_LIST, files);
    if (!files.empty() && files.size() <= MAX_FILE_LIST_SIZE) {
        want.SetParam(LAUNCH_PARAMETER_FILE_LIST, files);
        want.SetParam(ABILITY_PARAMS_STREAM, files);
    }
    PrintUtils::BuildAdapterParam(adapterParam, want);
    int32_t callerTokenId = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_TOKEN, callerTokenId);
    want.SetParam(CALLER_PKG_NAME, PrintUtils::GetBundleNameForUid(IPCSkeleton::GetCallingUid()));
    want.SetParam(UI_EXTENSION_TYPE_NAME, PRINT_UI_EXTENSION_TYPE);
    want.SetFlags(AAFwk::Want::FLAG_AUTH_READ_URI_PERMISSION);
    OHOS::Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    auto uiContent = GetUIContent(ctx);
    if (uiContent == nullptr) {
        PRINT_HILOGE("GetUIContent failed");
        return E_PRINT_INVALID_PARAMETER;
    }
    auto callback = std::make_shared<PrintEtsUICallback>(uiContent);
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallbacks = {
        [callback](int32_t releaseCode) { callback->OnRelease(releaseCode); },
        [callback](int32_t resultCode, const OHOS::AAFwk::Want& result) {
            callback->OnResultForModal(resultCode, result);
        },
        [callback](const OHOS::AAFwk::WantParams& request) { callback->OnReceive(request); },
        [callback](int32_t code, const std::string& name, const std::string& message) {
            callback->OnError(code, name, message);
        }
    };
    int32_t sessionId = uiContent->CreateModalUIExtension(want, extensionCallbacks, config);
    callback->SetSessionId(sessionId);
    PRINT_HILOGD("Created session: %{public}d", sessionId);

    return E_PRINT_NONE;
}

OHOS::Ace::UIContent* AniPrintTask::GetUIContent(std::shared_ptr<OHOS::AbilityRuntime::Context> ctx)
{
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(ctx);
    if (abilityContext != nullptr) {
        return abilityContext->GetUIContent();
    }
    std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext> uiExtensionContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::UIExtensionContext>(ctx);
    if (uiExtensionContext != nullptr) {
        return uiExtensionContext->GetUIContent();
    }
    return nullptr;
}

int32_t AniPrintTask::On(std::string type, sptr<IPrintCallback> callback)
{
    int32_t ret = PrintManagerClient::GetInstance()->On(jobId_, type, callback);
    return ret;
}

int32_t AniPrintTask::Off(std::string type, sptr<IPrintCallback> callback)
{
    int32_t ret = PrintManagerClient::GetInstance()->Off(jobId_, type);
    return ret;
}

bool AniPrintTask::CheckPermission(const std::string &name)
{
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    TypeATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == TOKEN_INVALID) {
        PRINT_HILOGE("invalid token id %{public}d", tokenId);
        return false;
    }
    int result = AccessTokenKit::VerifyAccessToken(tokenId, name);
    if (result != PERMISSION_GRANTED) {
        PRINT_HILOGE("Current tokenId permission is %{public}d", result);
    }
    return result == PERMISSION_GRANTED;
}


} // namespace OHOS::Print