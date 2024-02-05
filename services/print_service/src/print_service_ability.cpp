/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "print_service_ability.h"

#include <cerrno>
#include <ctime>
#include <string>
#include <sys/time.h>
#include <thread>
#include <unistd.h>

#ifdef CUPS_ENABLE
#include "print_cups_client.h"
#endif // CUPS_ENABLE
#include "accesstoken_kit.h"
#include "array_wrapper.h"
#include "core_service_client.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "print_bms_helper.h"
#include "print_constant.h"
#include "print_log.h"
#include "printer_info.h"
#include "print_utils.h"
#include "string_wrapper.h"
#include "system_ability_definition.h"
#include "want_params_wrapper.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "print_security_guard_manager.h"
#include "hisys_event_util.h"
#include "nlohmann/json.hpp"

namespace OHOS::Print {
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;
using json = nlohmann::json;

const uint32_t ASYNC_CMD_DELAY = 10;
const int64_t INIT_INTERVAL = 5000L;

static const std::string SPOOLER_BUNDLE_NAME = "com.ohos.spooler";
static const std::string SPOOLER_ABILITY_NAME = "MainAbility";
static const std::string LAUNCH_PARAMETER_DOCUMENT_NAME = "documentName";
static const std::string LAUNCH_PARAMETER_JOB_ID = "jobId";
static const std::string LAUNCH_PARAMETER_FILE_LIST = "fileList";
static const std::string LAUNCH_PARAMETER_FD_LIST = "fdList";
static const std::string LAUNCH_PARAMETER_PRINT_ATTRIBUTE = "printAttributes";
static const std::string PERMISSION_NAME_PRINT = "ohos.permission.PRINT";
static const std::string PERMISSION_NAME_PRINT_JOB = "ohos.permission.MANAGE_PRINT_JOB";
static const std::string PRINTER_EVENT_TYPE = "printerStateChange";
static const std::string PRINTJOB_EVENT_TYPE = "jobStateChange";
static const std::string EXTINFO_EVENT_TYPE = "extInfoChange";
static const std::string PRINT_ADAPTER_EVENT_TYPE = "printCallback_adapter";
static const std::string PRINT_GET_FILE_EVENT_TYPE = "getPrintFileCallback_adapter";
static const std::string EVENT_BLOCK = "block";
static const std::string EVENT_SUCCESS = "succeed";
static const std::string EVENT_FAIL = "fail";
static const std::string EVENT_CANCEL = "cancel";
static const std::string CALLER_PKG_NAME = "caller.pkgName";

static const std::string FD = "FD";
static const std::string TYPE_PROPERTY = "type";
static const std::string VALUE_PROPERTY = "value";
static const std::string QUEUE_JOB_LIST_CHANGED = "queuedJobListChanged";
static const std::string ACTION_QUEUE_JOB_LIST_CHANGED = "action.printkit.queuedJobListChanged";
static const std::string QUEUE_JOB_LIST_PRINTING = "printing";
static const std::string QUEUE_JOB_LIST_COMPLETED = "completed";
static const std::string QUEUE_JOB_LIST_BLOCKED = "blocked";
static const std::string QUEUE_JOB_LIST_CLEAR_BLOCKED = "clear_blocked";
static const std::string SPOOLER_PREVIEW_ABILITY_NAME = "PrintServiceExtAbility";
static const std::string TOKEN_KEY = "ohos.ability.params.token";

static const std::string NOTIFY_INFO_SPOOLER_CLOSED_FOR_CANCELLED = "spooler_closed_for_cancelled";
static const std::string NOTIFY_INFO_SPOOLER_CLOSED_FOR_STARTED = "spooler_closed_for_started";

static bool g_publishState = false;

REGISTER_SYSTEM_ABILITY_BY_ID(PrintServiceAbility, PRINT_SERVICE_ID, true);

std::mutex PrintServiceAbility::instanceLock_;
sptr<PrintServiceAbility> PrintServiceAbility::instance_;
std::shared_ptr<AppExecFwk::EventHandler> PrintServiceAbility::serviceHandler_;
std::chrono::time_point<std::chrono::high_resolution_clock> PrintServiceAbility::startPrintTime_;
std::string PrintServiceAbility::ingressPackage;

PrintServiceAbility::PrintServiceAbility(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START),
    spoolerBundleName_(SPOOLER_BUNDLE_NAME), spoolerAbilityName_(SPOOLER_ABILITY_NAME), currentJobId_(0),
    helper_(nullptr), isJobQueueBlocked_(false)
{}

PrintServiceAbility::~PrintServiceAbility()
{
    PRINT_HILOGE("~PrintServiceAbility state_  is %{public}d.", static_cast<int>(state_));
}

sptr<PrintServiceAbility> PrintServiceAbility::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new PrintServiceAbility(PRINT_SERVICE_ID, true);
        }
    }
    return instance_;
}

int32_t PrintServiceAbility::Init()
{
    if (helper_ == nullptr) {
        helper_ = std::make_shared<PrintServiceHelper>();
    }
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(helper_);
    if (!g_publishState) {
        bool ret = Publish(PrintServiceAbility::GetInstance());
        if (!ret) {
            PRINT_HILOGE("PrintServiceAbility Publish failed.");
            return E_PRINT_SERVER_FAILURE;
        }
        g_publishState = true;
    }
    KillAllAbility();
    state_ = ServiceRunningState::STATE_RUNNING;
    PRINT_HILOGI("state_ is %{public}d.", static_cast<int>(state_));
    PRINT_HILOGI("Init PrintServiceAbility success.");
    return ERR_OK;
}

void PrintServiceAbility::OnStart()
{
    PRINT_HILOGI("PrintServiceAbility::Enter OnStart.");
    if (instance_ == nullptr) {
        instance_ = this;
    }
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        PRINT_HILOGI("PrintServiceAbility is already running.");
        return;
    }
    InitServiceHandler();
    int32_t ret = Init();
    if (ret != ERR_OK) {
        auto callback = [=]() { Init(); };
        serviceHandler_->PostTask(callback, INIT_INTERVAL);
        PRINT_HILOGE("PrintServiceAbility Init failed. Try again 5s later");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    return;
}

void PrintServiceAbility::InitServiceHandler()
{
    PRINT_HILOGI("InitServiceHandler started.");
    if (serviceHandler_ != nullptr) {
        PRINT_HILOGI("InitServiceHandler already init.");
        return;
    }
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("PrintServiceAbility");
    serviceHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    PRINT_HILOGI("InitServiceHandler succeeded.");
}

void PrintServiceAbility::ManualStart()
{
    if (state_ != ServiceRunningState::STATE_RUNNING) {
        PRINT_HILOGI("PrintServiceAbility restart.");
        OnStart();
    }
}

std::string PrintServiceAbility::GetPrintJobId()
{
    std::lock_guard<std::mutex> autoLock(instanceLock_);
    return std::to_string(currentJobId_++);
}

void PrintServiceAbility::OnStop()
{
    PRINT_HILOGI("OnStop started.");
    if (state_ != ServiceRunningState::STATE_RUNNING) {
        return;
    }
    serviceHandler_ = nullptr;
    state_ = ServiceRunningState::STATE_NOT_START;
    PRINT_HILOGI("OnStop end.");
}

void PrintServiceAbility::BuildFDParam(const std::vector<uint32_t> &fdList, AAFwk::Want &want)
{
    if (fdList.empty()) {
        return;
    }
    AAFwk::WantParams wantParams = want.GetParams();
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(fdList.size(), AAFwk::g_IID_IWantParams);
    if (ao == nullptr) {
        PRINT_HILOGE("fail to create param");
        return;
    }
    int32_t index = 0;
    for (auto fd : fdList) {
        AAFwk::WantParams wp;
        wp.SetParam(TYPE_PROPERTY, AAFwk::String::Box(FD));
        wp.SetParam(VALUE_PROPERTY, AAFwk::Integer::Box(fd));
        PRINT_HILOGD("fd[%{public}d] = %{public}d", index, fd);
        ao->Set(index++, AAFwk::WantParamWrapper::Box(wp));
    }
    wantParams.SetParam(LAUNCH_PARAMETER_FD_LIST, ao);
    want.SetParams(wantParams);
}

int32_t PrintServiceAbility::StartPrint(const std::vector<std::string> &fileList,
    const std::vector<uint32_t> &fdList, std::string &taskId)
{
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    CreateDefaultAdapterParam(adapterParam);
    return CallSpooler(fileList, fdList, taskId, adapterParam);
}

int32_t PrintServiceAbility::CallSpooler(const std::vector<std::string> &fileList,
    const std::vector<uint32_t> &fdList, std::string &taskId, const std::shared_ptr<AdapterParam> &adapterParam)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service, ErrorCode:[%{public}d]", E_PRINT_NO_PERMISSION);
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("PrintServiceAbility StartPrint started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (adapterParam->isCheckFdList && fileList.empty() && fdList.empty()) {
        PRINT_HILOGE("to be printed filelist and fdlist are empty");
        return E_PRINT_INVALID_PARAMETER;
    }
    std::string jobId = GetPrintJobId();
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetFdList(fdList);
    printJob->SetJobId(jobId);
    printJob->SetJobState(PRINT_JOB_PREPARED);
    AAFwk::Want want;
    want.SetElementName(SPOOLER_BUNDLE_NAME, SPOOLER_ABILITY_NAME);
    want.SetParam(LAUNCH_PARAMETER_JOB_ID, jobId);
    want.SetParam(LAUNCH_PARAMETER_FILE_LIST, fileList);
    BuildAdapterParam(adapterParam, want, jobId);
    BuildFDParam(fdList, want);
    int32_t callerTokenId = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    std::string callerPkg = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    ingressPackage = callerPkg;
    int32_t callerUid = IPCSkeleton::GetCallingUid();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_TOKEN, callerTokenId);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_UID, callerUid);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_PID, callerPid);
    want.SetParam(CALLER_PKG_NAME, callerPkg);
    if (!StartAbility(want)) {
        PRINT_HILOGE("Failed to start spooler ability");
        return E_PRINT_SERVER_FAILURE;
    }
    printJobList_.insert(std::make_pair(jobId, printJob));
    taskId = jobId;
    SendPrintJobEvent(*printJob);
    // save securityGuard base info
    securityGuardManager_.receiveBaseInfo(jobId, callerPkg, fileList);
#ifdef CUPS_ENABLE
    return DelayedSingleton<PrintCupsClient>::GetInstance()->InitCupsResources();
#endif // CUPS_ENABLE
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::StartPrint(const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList,
    std::string &taskId, const sptr<IRemoteObject> &token)
{
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    CreateDefaultAdapterParam(adapterParam);
    return CallSpooler(fileList, fdList, taskId, token, adapterParam);
}

int32_t PrintServiceAbility::CallSpooler(const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList,
    std::string &taskId, const sptr<IRemoteObject> &token, const std::shared_ptr<AdapterParam> &adapterParam)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service, ErrorCode:[%{public}d]", E_PRINT_NO_PERMISSION);
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("PrintServiceAbility StartPrint started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if ((adapterParam->isCheckFdList && fileList.empty() && fdList.empty()) || token == nullptr) {
        PRINT_HILOGE("to be printed filelist and fdlist are empty, or token is null.");
        return E_PRINT_INVALID_PARAMETER;
    }
    std::string jobId = GetPrintJobId();
    auto printJob = std::make_shared<PrintJob>();
    printJob->SetFdList(fdList);
    printJob->SetJobId(jobId);
    printJob->SetJobState(PRINT_JOB_PREPARED);
    AAFwk::Want want;
    want.SetElementName(SPOOLER_BUNDLE_NAME, SPOOLER_PREVIEW_ABILITY_NAME);
    want.SetParam(LAUNCH_PARAMETER_JOB_ID, jobId);
    want.SetParam(LAUNCH_PARAMETER_FILE_LIST, fileList);
    BuildAdapterParam(adapterParam, want, jobId);
    BuildFDParam(fdList, want);
    int32_t callerTokenId = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    std::string callerPkg = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    ingressPackage = callerPkg;
    int32_t callerUid = IPCSkeleton::GetCallingUid();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_TOKEN, callerTokenId);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_UID, callerUid);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_PID, callerPid);
    want.SetParam(CALLER_PKG_NAME, callerPkg);
    want.SetParam(TOKEN_KEY, token);
    curRequestCode_ = (curRequestCode_ == INT_MAX) ? 0 : (curRequestCode_ + 1);
    if (!StartPrintServiceExtension(want, curRequestCode_)) {
        PRINT_HILOGE("Failed to start spooler ability");
        return E_PRINT_SERVER_FAILURE;
    }
    printJobList_.insert(std::make_pair(jobId, printJob));
    taskId = jobId;
    SendPrintJobEvent(*printJob);

    // save securityGuard base info
    securityGuardManager_.receiveBaseInfo(jobId, callerPkg, fileList);
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::StopPrint(const std::string &taskId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGD("PrintServiceAbility StopPrint started.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::ConnectPrinter(const std::string &printerId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGD("ConnectPrinter started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (printerInfoList_.find(printerId) == printerInfoList_.end()) {
        PRINT_HILOGE("Invalid printer id");
        return E_PRINT_INVALID_PRINTER;
    }

    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CONNECT_PRINTER);
    if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
        PRINT_HILOGW("ConnectPrinter Not Register Yet!!!");
        return E_PRINT_SERVER_FAILURE;
    }

    auto cbFunc = extCallbackMap_[cid];
    auto callback = [=]() {
        if (cbFunc != nullptr) {
            cbFunc->OnCallback(printerId);
        }
    };
    if (helper_->IsSyncMode()) {
        callback();
    } else {
        serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    }
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::DisconnectPrinter(const std::string &printerId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGD("DisconnectPrinter started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (printerInfoList_.find(printerId) == printerInfoList_.end()) {
        PRINT_HILOGE("Invalid printer id");
        return E_PRINT_INVALID_PRINTER;
    }

    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_DISCONNECT_PRINTER);
    if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
        PRINT_HILOGW("DisconnectPrinter Not Register Yet!!!");
        return E_PRINT_SERVER_FAILURE;
    }

    auto cbFunc = extCallbackMap_[cid];
    auto callback = [=]() {
        if (cbFunc != nullptr) {
            cbFunc->OnCallback(printerId);
        }
    };
    if (helper_->IsSyncMode()) {
        callback();
    } else {
        serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    }
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::StartDiscoverPrinter(const std::vector<std::string> &extensionIds)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGD("StartDiscoverPrinter started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    printerInfoList_.clear();
    std::map<std::string, AppExecFwk::ExtensionAbilityInfo> abilityList;
    for (auto extensionId : extensionIds) {
        if (extensionList_.find(extensionId) != extensionList_.end()) {
            abilityList.insert(std::make_pair(extensionId, extensionList_[extensionId]));
        }
    }

    if (abilityList.empty() && extensionIds.size() > 0) {
        PRINT_HILOGW("No valid extension found");
        return E_PRINT_INVALID_EXTENSION;
    }

    if (extensionIds.empty()) {
        for (auto extension : extensionList_) {
            abilityList.insert(std::make_pair(extension.first, extension.second));
        }
    }

    if (abilityList.empty()) {
        PRINT_HILOGW("No extension found");
        return E_PRINT_INVALID_EXTENSION;
    }

    for (auto ability : abilityList) {
        AAFwk::Want want;
        want.SetElementName(ability.second.bundleName, ability.second.name);
        if (!StartAbility(want)) {
            PRINT_HILOGE("Failed to load extension %{public}s", ability.second.name.c_str());
            continue;
        }
        extensionStateList_[ability.second.bundleName] = PRINT_EXTENSION_LOADING;
    }

    PRINT_HILOGD("StartDiscoverPrinter end.");
    return E_PRINT_NONE;
}

bool PrintServiceAbility::DelayStartDiscovery(const std::string &extensionId)
{
    PRINT_HILOGD("DelayStartDiscovery started. %{public}s", extensionId.c_str());
    if (extensionStateList_.find(extensionId) == extensionStateList_.end()) {
        PRINT_HILOGE("invalid extension id");
        return false;
    }

    if (extensionStateList_[extensionId] != PRINT_EXTENSION_LOADED) {
        PRINT_HILOGE("invalid extension state");
        return false;
    }

    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_DISCOVERY);
    if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
        PRINT_HILOGE("StartDiscoverPrinter Not Register, BUT State is LOADED");
        return false;
    }

    int32_t ret = E_PRINT_SERVER_FAILURE;
    if (extCallbackMap_[cid]->OnCallback()) {
        ret = E_PRINT_NONE;
    }
    return ret == E_PRINT_NONE;
}

int32_t PrintServiceAbility::StopDiscoverPrinter()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("StopDiscoverPrinter started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    for (auto extension : extensionStateList_) {
        if (extension.second < PRINT_EXTENSION_LOADING) {
            continue;
        }
        extension.second = PRINT_EXTENSION_UNLOAD;
        std::string cid = PrintUtils::EncodeExtensionCid(extension.first, PRINT_EXTCB_STOP_DISCOVERY);
        if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
            PRINT_HILOGE("StopDiscoverPrinter Not Register, BUT State is LOADED");
            continue;
        }

        auto cbFunc = extCallbackMap_[cid];
        auto callback = [=]() {
            if (cbFunc != nullptr) {
                cbFunc->OnCallback();
            }
        };
        if (helper_->IsSyncMode()) {
            callback();
        } else {
            serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
        }
    }
    PRINT_HILOGW("StopDiscoverPrinter out.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("QueryAllExtension started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfo;
    if (!DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryExtensionInfos(extensionInfo)) {
        PRINT_HILOGE("Failed to query extension");
        return E_PRINT_SERVER_FAILURE;
    }

    extensionList_.clear();
    extensionStateList_.clear();
    for (auto extInfo : extensionInfo) {
        PRINT_HILOGD("bundleName = %{public}s", extInfo.bundleName.c_str());
        PRINT_HILOGD("moduleName = %{public}s", extInfo.moduleName.c_str());
        PRINT_HILOGD("name = %{public}s", extInfo.name.c_str());
        PrintExtensionInfo printExtInfo = ConvertToPrintExtensionInfo(extInfo);
        extensionInfos.emplace_back(printExtInfo);
        extensionList_.insert(std::make_pair(printExtInfo.GetExtensionId(), extInfo));
        extensionStateList_.insert(std::make_pair(printExtInfo.GetExtensionId(), PRINT_EXTENSION_UNLOAD));
    }
    PRINT_HILOGI("QueryAllExtension End.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryAllPrintJob(std::vector<PrintJob> &printJobs)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("QueryAllPrintJob started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    printJobs.clear();
    for (auto printJob : queuedJobList_) {
        printJobs.emplace_back(*printJob.second);
    }
    PRINT_HILOGE("QueryAllPrintJob End.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryPrintJobById(std::string &printJobId, PrintJob &printJob)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("QueryPrintJobById started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (printJobList_.empty()) {
        PRINT_HILOGD("printJobList is empty!");
        return E_PRINT_INVALID_PRINTJOB;
    }

    auto jobIt = printJobList_.find(printJobId);
    if (jobIt == printJobList_.end()) {
        PRINT_HILOGD("no print job exists");
        return E_PRINT_INVALID_PRINTJOB;
    } else {
        printJob = *jobIt->second;
    }
    PRINT_HILOGI("QueryPrintJobById End.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::AddPrinterToCups(const std::string &printerUri, const std::string &printerName,
    const std::string &printerMake)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("AddPrinterToCups started.");
#ifdef CUPS_ENABLE
    DelayedSingleton<PrintCupsClient>::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
#endif // CUPS_ENABLE
    PRINT_HILOGD("AddPrinterToCups End.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryPrinterCapabilityByUri(const std::string &printerUri, const std::string &printerId,
    PrinterCapability &printerCaps)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("QueryPrinterCapabilityByUri started.");
#ifdef CUPS_ENABLE
    DelayedSingleton<PrintCupsClient>::GetInstance()->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
#endif // CUPS_ENABLE
    PRINT_HILOGD("QueryPrinterCapabilityByUri End.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::StartPrintJob(const PrintJob &jobInfo)
{
    startPrintTime_ = std::chrono::high_resolution_clock::now();
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto jobId = jobInfo.GetJobId();
    auto printerId = jobInfo.GetPrinterId();
    auto extensionId = PrintUtils::GetExtensionId(printerId);
    auto jobIt = printJobList_.find(jobId);
    if (jobIt == printJobList_.end()) {
        PRINT_HILOGE("invalid job id");
        return E_PRINT_INVALID_PRINTJOB;
    }
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
    if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
        return E_PRINT_SERVER_FAILURE;
    }
    printJobList_.erase(jobIt);
    auto printJob = std::make_shared<PrintJob>();
    printJob->UpdateParams(jobInfo);
    UpdateQueuedJobList(jobId, printJob);
    printerJobMap_[printerId].insert(std::make_pair(jobId, true));
#ifdef CUPS_ENABLE
    if (cid.find(SPOOLER_BUNDLE_NAME) != string::npos) {
        DelayedSingleton<PrintCupsClient>::GetInstance()->AddCupsPrintJob(jobInfo);
        return E_PRINT_NONE;
    }
#endif // CUPS_ENABLE
    auto cbFunc = extCallbackMap_[cid];
    auto callback = [=]() {
        if (cbFunc != nullptr) {
            StartPrintJobCB(jobId, printJob);
            cbFunc->OnCallback(*printJob);
        }
    };
    if (helper_->IsSyncMode()) {
        callback();
    } else {
        serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    }
    return E_PRINT_NONE;
}

void PrintServiceAbility::UpdateQueuedJobList(const std::string &jobId, const std::shared_ptr<PrintJob> &printJob)
{
    if (queuedJobList_.find(jobId) != queuedJobList_.end()) {
        queuedJobList_[jobId] = printJob;
    } else {
        queuedJobList_.insert(std::make_pair(jobId, printJob));
    }
}

void PrintServiceAbility::StartPrintJobCB(const std::string &jobId, const std::shared_ptr<PrintJob> &printJob)
{
    PRINT_HILOGD("Start send task to Extension PrintJob %{public}s", jobId.c_str());
    NotifyAppJobQueueChanged(QUEUE_JOB_LIST_PRINTING);
    printJob->SetJobState(PRINT_JOB_QUEUED);
    UpdatePrintJobState(jobId, PRINT_JOB_QUEUED, PRINT_JOB_BLOCKED_UNKNOWN);
}

int32_t PrintServiceAbility::CancelPrintJob(const std::string &jobId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    auto jobIt = queuedJobList_.find(jobId);
    if (jobIt == queuedJobList_.end()) {
        PRINT_HILOGD("invalid job id");
        return E_PRINT_INVALID_PRINTJOB;
    }

    if (jobIt->second->GetJobState() >= PRINT_JOB_QUEUED) {
        std::string extensionId = PrintUtils::GetExtensionId(jobIt->second->GetPrinterId());
        std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CANCEL_PRINT);
        if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
            PRINT_HILOGW("CancelPrintJob Not Register Yet!!!");
            UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED, PRINT_JOB_COMPLETED_CANCELLED);
            return E_PRINT_SERVER_FAILURE;
        }
#ifdef CUPS_ENABLE
        if (cid.find(SPOOLER_BUNDLE_NAME) != string::npos) {
            DelayedSingleton<PrintCupsClient>::GetInstance()->CancelCupsJob(jobIt->second->GetJobId());
            return E_PRINT_NONE;
        }
#endif // CUPS_ENABLE

        auto cbFunc = extCallbackMap_[cid];
        auto tmpPrintJob = queuedJobList_[jobId];
        auto callback = [=]() {
            if (cbFunc != nullptr && cbFunc->OnCallback(*tmpPrintJob) == false) {
                UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED, PRINT_JOB_COMPLETED_CANCELLED);
            }
        };
        if (helper_->IsSyncMode()) {
            callback();
        } else {
            serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
        }
    } else {
        auto printJob = std::make_shared<PrintJob>(*jobIt->second);
        printJob->SetJobState(PRINT_JOB_COMPLETED);
        printJob->SetSubState(PRINT_JOB_COMPLETED_CANCELLED);
        printJobList_.insert(std::make_pair(jobId, printJob));

        UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED, PRINT_JOB_COMPLETED_CANCELLED);
    }
    return E_PRINT_NONE;
}

void PrintServiceAbility::SendQueuePrintJob(const std::string &printerId)
{
    if (printerJobMap_[printerId].empty()) {
        return;
    }

    auto jobId = printerJobMap_[printerId].begin()->first;
    auto jobIt = queuedJobList_.find(jobId);
    if (jobIt == queuedJobList_.end()) {
        PRINT_HILOGE("invalid print job, jobId:%{public}s", jobId.c_str());
        return;
    }

    if (jobIt->second->GetJobState() != PRINT_JOB_PREPARED) {
        PRINT_HILOGE("job state isn't prepared, jobId:%{public}s", jobId.c_str());
        return;
    }

    auto extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
#ifdef CUPS_ENABLE
    if (cid.find(SPOOLER_BUNDLE_NAME) != string::npos) {
        PRINT_HILOGD("default spooler extension, no need SendQueuePrintJob");
        return;
    }
#endif // CUPS_ENABLE

    auto cbFunc = extCallbackMap_[cid];
    auto printJob = jobIt->second;
    auto callback = [=]() {
        PRINT_HILOGD("Start Next Print Job %{public}s", jobId.c_str());
        if (cbFunc != nullptr && cbFunc->OnCallback(*printJob)) {
            printJob->SetJobState(PRINT_JOB_QUEUED);
            NotifyAppJobQueueChanged(QUEUE_JOB_LIST_PRINTING);
            UpdatePrintJobState(jobId, PRINT_JOB_QUEUED, PRINT_JOB_BLOCKED_UNKNOWN);
        }
    };
    if (helper_->IsSyncMode()) {
        callback();
    } else {
        serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    }
}

int32_t PrintServiceAbility::AddPrinters(const std::vector<PrinterInfo> &printerInfos)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("AddPrinters started. Total size is %{public}zd", printerInfoList_.size());

    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());

    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    for (auto info : printerInfos) {
        if (printerInfoList_.find(info.GetPrinterId()) != printerInfoList_.end()) {
            PRINT_HILOGE("duplicate printer id, ingore it");
            continue;
        }
        auto printerInfo = std::make_shared<PrinterInfo>(info);
        printerInfo->SetPrinterId(PrintUtils::GetGlobalId(extensionId, printerInfo->GetPrinterId()));
        printerInfo->SetPrinterState(PRINTER_ADDED);
        printerInfoList_.insert(std::make_pair(printerInfo->GetPrinterId(), printerInfo));
        SendPrinterEvent(*printerInfo);
        SendQueuePrintJob(printerInfo->GetPrinterId());
    }
    PRINT_HILOGD("AddPrinters end. Total size is %{public}zd", printerInfoList_.size());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::RemovePrinters(const std::vector<std::string> &printerIds)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    auto count = printerInfoList_.size();
    PRINT_HILOGD("RemovePrinters started. Total size is %{public}zd", count);
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());

    for (auto printerId : printerIds) {
        printerId = PrintUtils::GetGlobalId(extensionId, printerId);
        auto printerIt = printerInfoList_.find(printerId);
        if (printerIt == printerInfoList_.end()) {
            PRINT_HILOGE("invalid printer id, ingore it");
            continue;
        }
        PrinterInfo info = *printerIt->second;
        info.SetPrinterState(PRINTER_REMOVED);
        SendPrinterEvent(info);
        printerInfoList_.erase(printerIt);
    }
    if (count == printerInfoList_.size()) {
        PRINT_HILOGE("Invalid printer ids");
        return E_PRINT_INVALID_PARAMETER;
    }
    PRINT_HILOGD("RemovePrinters end. Total size is %{public}zd", printerInfoList_.size());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::UpdatePrinters(const std::vector<PrinterInfo> &printerInfos)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGD("UpdatePrinters started. Total size is %{public}zd", printerInfoList_.size());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());

    bool isChanged = false;
    for (auto info : printerInfos) {
        std::string printExtId = PrintUtils::GetGlobalId(extensionId, info.GetPrinterId());
        auto printerIt = printerInfoList_.find(printExtId);
        if (printerIt == printerInfoList_.end()) {
            PRINT_HILOGE("invalid printer id, ingore it");
            continue;
        }
        *printerIt->second = info;
        printerIt->second->SetPrinterState(PRINTER_UPDATE_CAP);
        printerIt->second->SetPrinterId(printExtId);
        SendPrinterEvent(*printerIt->second);
        isChanged = true;
    }
    if (!isChanged) {
        return E_PRINT_INVALID_PARAMETER;
    }
    PRINT_HILOGD("UpdatePrinters end. Total size is %{private}zd", printerInfoList_.size());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::UpdatePrinterState(const std::string &printerId, uint32_t state)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    if (state > PRINTER_UNKNOWN) {
        return E_PRINT_INVALID_PARAMETER;
    }

    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());
    std::string printerExtId = PrintUtils::GetGlobalId(extensionId, printerId);
    PRINT_HILOGD("UpdatePrinterState started. %{private}s, state [%{public}d]", printerExtId.c_str(), state);
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (printerInfoList_.find(printerExtId) == printerInfoList_.end()) {
        PRINT_HILOGD("Invalid printer id");
        return E_PRINT_INVALID_PRINTER;
    }

    printerInfoList_[printerExtId]->SetPrinterState(state);
    SendPrinterEvent(*printerInfoList_[printerExtId]);
    PRINT_HILOGD("UpdatePrinterState end.");
    return E_PRINT_NONE;
}

bool PrintServiceAbility::checkJobState(uint32_t state, uint32_t subState)
{
    if (state > PRINT_JOB_UNKNOWN) {
        return false;
    }
    if (state == PRINT_JOB_BLOCKED && (subState < PRINT_JOB_BLOCKED_OFFLINE || subState > PRINT_JOB_BLOCKED_UNKNOWN)) {
        return false;
    }
    if (state == PRINT_JOB_COMPLETED && subState > PRINT_JOB_COMPLETED_FILE_CORRUPT) {
        return false;
    }

    return true;
}

int32_t PrintServiceAbility::UpdatePrintJobState(const std::string &jobId, uint32_t state, uint32_t subState)
{
    ManualStart();
    if (state == PRINT_JOB_CREATE_FILE_COMPLETED) {
        return AdapterGetFileCallBack(jobId, state, subState);
    }
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    if (!checkJobState(state, subState)) {
        return E_PRINT_INVALID_PARAMETER;
    }

    PRINT_HILOGI("UpdatePrintJobState started jobId:%{public}s, state:[%{public}d %{public}s], subState[%{public}d]",
        jobId.c_str(), state, PrintUtils::GetJobStateChar(state).c_str(), subState);
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    return CheckAndSendQueuePrintJob(jobId, state, subState);
}

int32_t PrintServiceAbility::AdapterGetFileCallBack(const std::string &jobId, uint32_t state, uint32_t subState)
{
    if (state != PRINT_JOB_CREATE_FILE_COMPLETED) {
        return E_PRINT_NONE;
    }
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    auto eventIt = registeredListeners_.find(PRINT_GET_FILE_EVENT_TYPE);
    if (eventIt != registeredListeners_.end()) {
        PRINT_HILOGI("print job adapter file created subState[%{public}d]", subState);
        uint32_t fileCompletedState = subState;
        if (subState == PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS) {
            fileCompletedState = PRINT_FILE_CREATED_SUCCESS;
        } else if (subState == PRINT_JOB_CREATE_FILE_COMPLETED_FAILED) {
            fileCompletedState = PRINT_FILE_CREATED_FAIL;
        }
        eventIt->second->OnCallbackAdapterGetFile(fileCompletedState);
    }
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::CheckAndSendQueuePrintJob(const std::string &jobId, uint32_t state, uint32_t subState)
{
    auto jobIt = queuedJobList_.find(jobId);
    bool jobInQueue = true;
    if (jobIt == queuedJobList_.end()) {
        jobInQueue = false;
        jobIt = printJobList_.find(jobId);
        if (jobIt == printJobList_.end()) {
            PRINT_HILOGD("Invalid print job id");
            return E_PRINT_INVALID_PRINTJOB;
        }
    }

    jobIt->second->SetJobState(state);
    jobIt->second->SetSubState(subState);
    SendPrintJobEvent(*jobIt->second);
    notifyAdapterJobChanged(jobId, state, subState);
    CheckJobQueueBlocked(*jobIt->second);

    auto printerId = jobIt->second->GetPrinterId();
    if (state == PRINT_JOB_BLOCKED) {
        ReportHisysEvent(jobIt->second, printerId, subState);
    }
    if (state == PRINT_JOB_COMPLETED) {
        if (jobInQueue) {
            printerJobMap_[printerId].erase(jobId);
            queuedJobList_.erase(jobIt);
        }
        if (printerJobMap_[printerId].empty()) {
            ReportCompletedPrint(printerId);
        }
        SendQueuePrintJob(printerId);
    }

    PRINT_HILOGD("CheckAndSendQueuePrintJob end.");
    return E_PRINT_NONE;
}

void PrintServiceAbility::ReportCompletedPrint(const std::string &printerId)
{
    NotifyAppJobQueueChanged(QUEUE_JOB_LIST_COMPLETED);
    PRINT_HILOGD("no print job exists, destroy extension");
    DestroyExtension(printerId);
    json msg;
    auto endPrintTime = std::chrono::high_resolution_clock::now();
    auto printTime = std::chrono::duration_cast<std::chrono::milliseconds>(endPrintTime - startPrintTime_);
    msg["PRINT_TIME"] = printTime.count();
    msg["INGRESS_PACKAGE"] = ingressPackage;
    msg["STATUS"] = 0;
    HisysEventUtil::reportPrintSuccess(msg.dump());
}

void PrintServiceAbility::ReportHisysEvent(const std::shared_ptr<PrintJob> &jobInfo,
                                           const std::string &printerId, uint32_t subState)
{
    json msg;
    auto endPrintTime = std::chrono::high_resolution_clock::now();
    auto printTime = std::chrono::duration_cast<std::chrono::milliseconds>(endPrintTime - startPrintTime_);
    msg["PRINT_TIME"] = printTime.count();
    msg["INGRESS_PACKAGE"] = ingressPackage;
    if (isEprint(printerId)) {
        msg["PRINT_TYPE"] = 1;
    } else {
        msg["PRINT_TYPE"] = 0;
    }
    auto printInfo = printerInfoList_.find(printerId);
    std::vector<uint32_t> fdList;
    jobInfo->GetFdList(fdList);
    msg["FILE_NUM"] = fdList.size();
    msg["PAGE_NUM"] = fdList.size();
    if (printInfo == printerInfoList_.end()) {
        msg["MODEL"] = "";
    } else {
        msg["MODEL"] = printInfo->second->GetPrinterName();
    }
    msg["COPIES_SETTING"] = jobInfo->GetCopyNumber();
    std::string option = jobInfo->GetOption();
    PRINT_HILOGI("option:%{public}s", option.c_str());
    std::string jobDescription = "";
    if (option != "") {
        if (json::accept(option)) {
            json optionJson = json::parse(option);
            PRINT_HILOGI("optionJson: %{public}s", optionJson.dump().c_str());
            if (optionJson.contains("jobDescription") && optionJson["jobDescription"].is_string()) {
                jobDescription = optionJson["jobDescription"].get<std::string>();
                PRINT_HILOGI("jobDescription: %{public}s", jobDescription.c_str());
            }
        }
    }
    msg["JOB_DESCRIPTION"] = jobDescription;
    msg["PRINT_STYLE_SETTING"] = jobInfo->GetDuplexMode();
    msg["FAIL_REASON_CODE"] = subState;
    HisysEventUtil::faultPrint("PRINT_JOB_BLOCKED", msg.dump());
}

void PrintServiceAbility::NotifyAppJobQueueChanged(const std::string &applyResult)
{
    PRINT_HILOGD("NotifyAppJobQueueChanged started. %{public}s ", applyResult.c_str());
    AAFwk::Want want;
    want.SetAction(ACTION_QUEUE_JOB_LIST_CHANGED);
    want.SetParam(QUEUE_JOB_LIST_CHANGED, applyResult);
    EventFwk::CommonEventData commonData { want };
    EventFwk::CommonEventManager::PublishCommonEvent(commonData);
    PRINT_HILOGD("NotifyAppJobQueueChanged end.");
}

bool PrintServiceAbility::isEprint(const std::string &printerId)
{
    if (printerId.length() <= 0) {
        return false;
    }
    std::string ePrintID = "ePrintID";
    if (printerId.length() < ePrintID.length()) {
        return false;
    }
    return std::equal(ePrintID.rbegin(), ePrintID.rend(), printerId.rbegin());
}

void PrintServiceAbility::DestroyExtension(const std::string &printerId)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (printerInfoList_.find(printerId) == printerInfoList_.end()) {
        PRINT_HILOGE("Invalid printer id");
        return;
    }

    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_DESTROY_EXTENSION);
    if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
        PRINT_HILOGW("DestroyExtension Not Register Yet!!!");
        return;
    }

    auto cbFunc = extCallbackMap_[cid];
    auto callback = [=]() {
        if (cbFunc != nullptr) {
            cbFunc->OnCallback();
        }
    };
    if (helper_->IsSyncMode()) {
        callback();
    } else {
        serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    }
}

int32_t PrintServiceAbility::UpdateExtensionInfo(const std::string &extInfo)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());

    PRINT_HILOGD("UpdateExtensionInfo started. %{public}s, extInfo [%{public}s]",
        extensionId.c_str(), extInfo.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (extensionList_.find(extensionId) == extensionList_.end()) {
        PRINT_HILOGD("Invalid extension id");
        return E_PRINT_INVALID_EXTENSION;
    }
    SendExtensionEvent(extensionId, extInfo);
    PRINT_HILOGD("UpdateExtensionInfo end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::RequestPreview(const PrintJob &jobInfo, std::string &previewResult)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("RequestPreview started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    auto jobId = jobInfo.GetJobId();
    auto printerId = jobInfo.GetPrinterId();
    auto extensionId = PrintUtils::GetExtensionId(printerId);

    auto jobIt = printJobList_.find(jobId);
    if (jobIt == printJobList_.end()) {
        PRINT_HILOGD("invalid job id");
        return E_PRINT_INVALID_PRINTJOB;
    }

    if (printJobList_[jobId]->GetJobState() < PRINT_JOB_QUEUED) {
        PRINT_HILOGD("invalid job state [%{public}d]", printJobList_[jobId]->GetJobState());
        return E_PRINT_INVALID_PRINTJOB;
    }

    if (printerInfoList_.find(printerId) == printerInfoList_.end()) {
        PRINT_HILOGD("invalid printer of the print job");
        return E_PRINT_INVALID_PRINTJOB;
    }

    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_REQUEST_PREVIEW);
    if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
        PRINT_HILOGW("RequestPreview Not Register Yet!!!");
        return E_PRINT_SERVER_FAILURE;
    }

    printJobList_[jobId]->UpdateParams(jobInfo);
    auto cbFunc = extCallbackMap_[cid];
    auto callback = [=]() { cbFunc->OnCallback(*printJobList_[jobId]); };
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryPrinterCapability(const std::string &printerId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("QueryPrinterCapability started %{private}s", printerId.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (printerInfoList_.find(printerId) == printerInfoList_.end()) {
        PRINT_HILOGE("Invalid printer id");
        return E_PRINT_INVALID_PRINTER;
    }

    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_REQUEST_CAP);
    if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
        PRINT_HILOGW("QueryPrinterCapability Not Register Yet!!!");
        return E_PRINT_SERVER_FAILURE;
    }

    auto cbFunc = extCallbackMap_[cid];
    auto callback = [=]() {
        if (cbFunc != nullptr) {
            cbFunc->OnCallback(printerId);
        }
    };
    if (helper_->IsSyncMode()) {
        callback();
    } else {
        serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    }
    return E_PRINT_NONE;
}

bool PrintServiceAbility::CheckPermission(const std::string &permissionName)
{
    if (helper_ == nullptr) {
        return false;
    }
    return helper_->CheckPermission(permissionName);
}

int32_t PrintServiceAbility::RegisterExtCallback(const std::string &extensionCID,
    const sptr<IPrintExtensionCallback> &listener)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::string extensionId = "";
    uint32_t callbackId = 0;
    if (!PrintUtils::DecodeExtensionCid(extensionCID, extensionId, callbackId)) {
        PRINT_HILOGE("Failed to decode extension");
        return E_PRINT_INVALID_PARAMETER;
    }

    PRINT_HILOGD("extensionCID = %{public}s, extensionId = %{public}s", extensionCID.c_str(), extensionId.c_str());

    auto extensionStateIt = extensionStateList_.find(extensionId);
    if (extensionStateIt == extensionStateList_.end()) {
        PRINT_HILOGE("Invalid extension id");
        return E_PRINT_INVALID_EXTENSION;
    }

    if (extensionStateIt->second != PRINT_EXTENSION_LOADING) {
        PRINT_HILOGE("Invalid Extension State [%{public}d]", extensionStateIt->second);
        return E_PRINT_INVALID_EXTENSION;
    }

    PRINT_HILOGD("PrintServiceAbility::RegisterExtCallback started.");
    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d]", callbackId);
        return E_PRINT_INVALID_PARAMETER;
    }

    if (listener == nullptr) {
        PRINT_HILOGE("Invalid listener");
        return E_PRINT_INVALID_PARAMETER;
    }

    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (extCallbackMap_.find(extensionCID) == extCallbackMap_.end()) {
        extCallbackMap_.insert(std::make_pair(extensionCID, listener));
    } else {
        PRINT_HILOGD("PrintServiceAbility::RegisterExtCallback Replace listener.");
        extCallbackMap_[extensionCID] = listener;
    }

    PRINT_HILOGD("PrintServiceAbility::RegisterExtCallback end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::UnregisterAllExtCallback(const std::string &extensionId)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGD("PrintServiceAbility::UnregisterAllExtCallback started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    for (uint32_t callbackId = PRINT_EXTCB_START_DISCOVERY; callbackId < PRINT_EXTCB_MAX; callbackId++) {
        std::string cid = PrintUtils::EncodeExtensionCid(extensionId, callbackId);
        auto callbackIt = extCallbackMap_.find(cid);
        if (callbackIt != extCallbackMap_.end()) {
            extCallbackMap_.erase(callbackIt);
        }
    }
    PRINT_HILOGD("PrintServiceAbility::UnregisterAllExtCallback end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::LoadExtSuccess(const std::string &extensionId)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGD("PrintServiceAbility::LoadExtSuccess started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (extensionStateList_.find(extensionId) == extensionStateList_.end()) {
        PRINT_HILOGE("Invalid extension id");
        return E_PRINT_INVALID_EXTENSION;
    }

    if (extensionStateList_[extensionId] != PRINT_EXTENSION_LOADING) {
        PRINT_HILOGE("Invalid Extension State");
        return E_PRINT_INVALID_EXTENSION;
    }
    extensionStateList_[extensionId] = PRINT_EXTENSION_LOADED;

    PRINT_HILOGD("Auto Stat Printer Discovery");
    auto callback = [=]() { DelayStartDiscovery(extensionId); };
    if (helper_->IsSyncMode()) {
        callback();
    } else {
        serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    }
    PRINT_HILOGD("PrintServiceAbility::LoadExtSuccess end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::On(const std::string taskId, const std::string &type, const sptr<IPrintCallback> &listener)
{
    std::string permission = PERMISSION_NAME_PRINT_JOB;
    std::string eventType = type;
    if (taskId != "") {
        permission = PERMISSION_NAME_PRINT;
        eventType = PrintUtils::GetTaskEventId(taskId, type);
    }

    if (type == PRINT_CALLBACK_ADAPTER) {
        permission = PERMISSION_NAME_PRINT;
        eventType = type;
    }

    if (!CheckPermission(permission)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    if (eventType == "") {
        PRINT_HILOGE("Invalid event type");
        return E_PRINT_INVALID_PARAMETER;
    }

    if (listener == nullptr) {
        PRINT_HILOGE("Invalid listener");
        return E_PRINT_INVALID_PARAMETER;
    }

    PRINT_HILOGD("PrintServiceAbility::On started. type=%{public}s", eventType.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (registeredListeners_.find(eventType) == registeredListeners_.end()) {
        registeredListeners_.insert(std::make_pair(eventType, listener));
    } else {
        PRINT_HILOGD("PrintServiceAbility::On Replace listener.");
        registeredListeners_[eventType] = listener;
    }
    PRINT_HILOGD("PrintServiceAbility::On end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::Off(const std::string taskId, const std::string &type)
{
    std::string permission = PERMISSION_NAME_PRINT_JOB;
    std::string eventType = type;
    if (taskId != "") {
        permission = PERMISSION_NAME_PRINT;
        eventType = PrintUtils::GetTaskEventId(taskId, type);
    }
    if (!CheckPermission(permission)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    if (eventType == "") {
        PRINT_HILOGE("Invalid event type");
        return E_PRINT_INVALID_PARAMETER;
    }

    PRINT_HILOGD("PrintServiceAbility::Off started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto iter = registeredListeners_.find(eventType);
    if (iter != registeredListeners_.end()) {
        PRINT_HILOGD("PrintServiceAbility::Off delete type=%{public}s object message.", eventType.c_str());
        registeredListeners_.erase(iter);
        return E_PRINT_NONE;
    }
    return E_PRINT_INVALID_PARAMETER;
}

bool PrintServiceAbility::StartAbility(const AAFwk::Want &want)
{
    if (helper_ == nullptr) {
        return false;
    }
    return helper_->StartAbility(want);
}

bool PrintServiceAbility::KillAbility(const std::string bundleName)
{
    if (helper_ == nullptr) {
        return false;
    }
    return helper_->KillAbility(bundleName);
}

void PrintServiceAbility::KillAllAbility()
{
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfo;
    if (!DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryExtensionInfos(extensionInfo)) {
        PRINT_HILOGE("Failed to query extension");
    }

    for (auto extInfo : extensionInfo) {
        KillAbility(extInfo.bundleName.c_str());
    }
}

bool PrintServiceAbility::StartPrintServiceExtension(const AAFwk::Want &want, int32_t curRequestCode_)
{
    if (helper_ == nullptr) {
        return false;
    }
    PRINT_HILOGI("StartPrintServiceExtension curRequestCode_ [%{public}d]", curRequestCode_);
    return helper_->StartPrintServiceExtension(want, curRequestCode_);
}

PrintExtensionInfo PrintServiceAbility::ConvertToPrintExtensionInfo(const AppExecFwk::ExtensionAbilityInfo &extInfo)
{
    PrintExtensionInfo printExtInfo;
    printExtInfo.SetExtensionId(extInfo.bundleName);
    printExtInfo.SetVendorId(extInfo.bundleName);
    printExtInfo.SetVendorName(extInfo.bundleName);
    printExtInfo.SetVendorIcon(0);
    printExtInfo.SetVersion("1.0.0");
    return printExtInfo;
}

void PrintServiceAbility::SendPrinterEvent(const PrinterInfo &info)
{
    PRINT_HILOGD("PrintServiceAbility::SendPrinterEvent type %{private}s, %{public}d",
        info.GetPrinterId().c_str(), info.GetPrinterState());
    auto eventIt = registeredListeners_.find(PRINTER_EVENT_TYPE);
    if (eventIt != registeredListeners_.end()) {
        eventIt->second->OnCallback(info.GetPrinterState(), info);
    }
}

void PrintServiceAbility::SendPrintJobEvent(const PrintJob &jobInfo)
{
    PRINT_HILOGD("PrintServiceAbility::SendPrintJobEvent jobId: %{public}s, state: %{public}d, subState: %{public}d",
        jobInfo.GetJobId().c_str(), jobInfo.GetJobState(), jobInfo.GetSubState());
    auto eventIt = registeredListeners_.find(PRINTJOB_EVENT_TYPE);
    if (eventIt != registeredListeners_.end()) {
        eventIt->second->OnCallback(jobInfo.GetJobState(), jobInfo);
    }

    // notify securityGuard
    if (jobInfo.GetJobState() == PRINT_JOB_COMPLETED) {
        std::shared_ptr<PrinterInfo> printerInfo = getPrinterInfo(jobInfo.GetPrinterId());
        if (printerInfo != nullptr) {
            securityGuardManager_.receiveJobStateUpdate(jobInfo.GetJobId(), *printerInfo, jobInfo);
        } else {
            PRINT_HILOGD("receiveJobStateUpdate printer is empty");
        }
    }

    std::string stateInfo = "";
    if (jobInfo.GetJobState() == PRINT_JOB_BLOCKED) {
        stateInfo = EVENT_BLOCK;
    } else if (jobInfo.GetJobState() == PRINT_JOB_COMPLETED) {
        switch (jobInfo.GetSubState()) {
            case PRINT_JOB_COMPLETED_SUCCESS:
                stateInfo = EVENT_SUCCESS;
                break;

            case PRINT_JOB_COMPLETED_FAILED:
                stateInfo = EVENT_FAIL;
                break;

            case PRINT_JOB_COMPLETED_CANCELLED:
                stateInfo = EVENT_CANCEL;
                break;
            default:
                break;
        }
    }
    if (stateInfo != "") {
        std::string taskEvent = PrintUtils::GetTaskEventId(jobInfo.GetJobId(), stateInfo);
        auto taskEventIt = registeredListeners_.find(taskEvent);
        if (taskEventIt != registeredListeners_.end()) {
            taskEventIt->second->OnCallback();
        }
    }
}

void PrintServiceAbility::SendExtensionEvent(const std::string &extensionId, const std::string &extInfo)
{
    PRINT_HILOGD("PrintServiceAbility::SendExtensionEvent type %{public}s", extInfo.c_str());
    auto eventIt = registeredListeners_.find(EXTINFO_EVENT_TYPE);
    if (eventIt != registeredListeners_.end()) {
        eventIt->second->OnCallback(extensionId, extInfo);
    }
}

std::shared_ptr<PrinterInfo> PrintServiceAbility::getPrinterInfo(const std::string printerId)
{
    auto printerIt = printerInfoList_.find(printerId);
    if (printerIt != printerInfoList_.end()) {
        return printerIt ->second;
    }
    return nullptr;
}

void PrintServiceAbility::SetHelper(const std::shared_ptr<PrintServiceHelper> &helper)
{
    helper_ = helper;
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(helper_);
}

void PrintServiceAbility::CheckJobQueueBlocked(const PrintJob &jobInfo)
{
    PRINT_HILOGD("CheckJobQueueBlocked started,isJobQueueBlocked_=%{public}s", isJobQueueBlocked_ ? "true" : "false");
    PRINT_HILOGD("CheckJobQueueBlocked %{public}s, %{public}d", jobInfo.GetJobId().c_str(), jobInfo.GetJobState());
    if (!isJobQueueBlocked_ && jobInfo.GetJobState() == PRINT_JOB_BLOCKED) {
        // going blocked
        isJobQueueBlocked_ = true;
        NotifyAppJobQueueChanged(QUEUE_JOB_LIST_BLOCKED);
    }

    if (isJobQueueBlocked_ && jobInfo.GetJobState() != PRINT_JOB_BLOCKED) {
        bool hasJobBlocked = false;
        for (auto printJob : queuedJobList_) {
            if (printJob.second -> GetJobState() == PRINT_JOB_BLOCKED) {
                hasJobBlocked = true;
                break;
            }
        }
        if (!hasJobBlocked) {
            // clear blocked
            isJobQueueBlocked_ = false;
            NotifyAppJobQueueChanged(QUEUE_JOB_LIST_CLEAR_BLOCKED);
        }
    }
    PRINT_HILOGD("CheckJobQueueBlocked end,isJobQueueBlocked_=%{public}s", isJobQueueBlocked_ ? "true" : "false");
}

int32_t PrintServiceAbility::PrintByAdapter(const std::string jobName, const PrintAttributes &printAttributes,
    std::string &taskId, const sptr<IRemoteObject> &token)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("PrintServiceAbility::PrintByAdapter start");
    // 拉起打印预览页面
    std::vector<std::string> fileList;
    std::vector<uint32_t> fdList;
    std::shared_ptr<AdapterParam> adapterParam = std::make_shared<AdapterParam>();
    adapterParam->documentName = jobName;
    adapterParam->isCheckFdList = false;
    adapterParam->printAttributes = printAttributes;
    int32_t ret = E_PRINT_NONE;
    if (token == nullptr) {
        ret = CallSpooler(fileList, fdList, taskId, adapterParam);
    } else {
        ret = CallSpooler(fileList, fdList, taskId, token, adapterParam);
    }
    PRINT_HILOGI("PrintServiceAbility::PrintByAdapter end");
    return ret;
}

int32_t PrintServiceAbility::StartGetPrintFile(const std::string &jobId, const PrintAttributes &printAttributes,
    const uint32_t fd)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("PrintServiceAbility::StartGetPrintFile start");
    auto eventIt = adapterListenersByJobId_.find(jobId);
    if (eventIt != adapterListenersByJobId_.end() && eventIt->second != nullptr) {
        PrintAttributes oldAttrs;
        auto attrIt = printAttributesList_.find(jobId);
        if (attrIt == printAttributesList_.end()) {
            printAttributesList_.insert(std::make_pair(jobId, printAttributes));
        } else {
            oldAttrs = attrIt->second;
            PRINT_HILOGD("PrintServiceAbility::StartGetPrintFile Replace printAttributes.");
            printAttributesList_[jobId] = printAttributes;
        }

        eventIt->second->OnCallbackAdapterLayout(jobId, oldAttrs, printAttributes, fd);
    } else {
        PRINT_HILOGW("PrintServiceAbility find event:%{public}s not found", PRINT_ADAPTER_EVENT_TYPE.c_str());
    }
    PRINT_HILOGI("PrintServiceAbility::StartGetPrintFile end");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::NotifyPrintService(const std::string &jobId, const std::string &type)
{
    std::string permission = PERMISSION_NAME_PRINT_JOB;
    if (!CheckPermission(permission)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    if (type == "0" || type == NOTIFY_INFO_SPOOLER_CLOSED_FOR_STARTED) {
        PRINT_HILOGI("Notify Spooler Closed for started jobId : %{public}s", jobId.c_str());
        notifyAdapterJobChanged(jobId, PRINT_JOB_SPOOLER_CLOSED, PRINT_JOB_SPOOLER_CLOSED_FOR_STARTED);
        return E_PRINT_NONE;
    }

    if (type == NOTIFY_INFO_SPOOLER_CLOSED_FOR_CANCELLED) {
        PRINT_HILOGI("Notify Spooler Closed for canceled jobId : %{public}s", jobId.c_str());
        notifyAdapterJobChanged(jobId, PRINT_JOB_SPOOLER_CLOSED, PRINT_JOB_SPOOLER_CLOSED_FOR_CANCELED);
        return E_PRINT_NONE;
    }
    return E_PRINT_INVALID_PARAMETER;
}

void PrintServiceAbility::notifyAdapterJobChanged(const std::string jobId, const uint32_t state,
    const uint32_t subState)
{
    if (state != PRINT_JOB_BLOCKED && state != PRINT_JOB_COMPLETED && state != PRINT_JOB_SPOOLER_CLOSED) {
        return;
    }

    auto attrIt = printAttributesList_.find(jobId);
    if (attrIt != printAttributesList_.end()) {
        printAttributesList_.erase(attrIt);
    }

    PRINT_HILOGI("get adapterListenersByJobId_ %{public}s", jobId.c_str());
    auto eventIt = adapterListenersByJobId_.find(jobId);
    if (eventIt == adapterListenersByJobId_.end() || eventIt->second == nullptr) {
        return;
    }

    uint32_t printAdapterListeningState = PRINT_TASK_FAIL;
    if (state == PRINT_JOB_SPOOLER_CLOSED) {
        printAdapterListeningState = PREVIEW_ABILITY_DESTROY;
    } else if (state == PRINT_JOB_BLOCKED) {
        printAdapterListeningState = PRINT_TASK_BLOCK;
    } else {
        switch (subState) {
            case PRINT_JOB_COMPLETED_SUCCESS:
                printAdapterListeningState = PRINT_TASK_SUCCEED;
                break;
            case PRINT_JOB_COMPLETED_FAILED:
                printAdapterListeningState = PRINT_TASK_FAIL;
                break;
            case PRINT_JOB_COMPLETED_CANCELLED:
                printAdapterListeningState = PRINT_TASK_CANCEL;
                break;
            default:
                printAdapterListeningState = PRINT_TASK_FAIL;
                break;
        }
    }
    PRINT_HILOGI("notifyAdapterJobChanged for subState: %{public}d, listeningState: %{public}d",
        subState, printAdapterListeningState);
    eventIt->second->onCallbackAdapterJobStateChanged(jobId, state, printAdapterListeningState);

    if (subState == PRINT_JOB_SPOOLER_CLOSED_FOR_CANCELED || state == PRINT_JOB_COMPLETED) {
        PRINT_HILOGI("erase adapterListenersByJobId_ %{public}s", jobId.c_str());
        adapterListenersByJobId_.erase(jobId);
    }
}

void PrintServiceAbility::CreateDefaultAdapterParam(const std::shared_ptr<AdapterParam> &adapterParam)
{
    adapterParam->documentName = "";
    adapterParam->isCheckFdList = true;
}

void PrintServiceAbility::BuildAdapterParam(const std::shared_ptr<AdapterParam> &adapterParam,
    AAFwk::Want &want, const std::string &jobId)
{
    want.SetParam(LAUNCH_PARAMETER_DOCUMENT_NAME, adapterParam->documentName);
    if (adapterParam->isCheckFdList) {
        std::string defaultAttribute = "";
        want.SetParam(LAUNCH_PARAMETER_PRINT_ATTRIBUTE, defaultAttribute);
        return;
    }

    PRINT_HILOGI("BuildAdapterParam for jobId %{public}s", jobId.c_str());
    auto eventIt = registeredListeners_.find(PRINT_ADAPTER_EVENT_TYPE);
    if (eventIt != registeredListeners_.end()) {
        PRINT_HILOGI("adapterListenersByJobId_ set adapterListenersByJobId_ %{public}s", jobId.c_str());
        adapterListenersByJobId_.insert(std::make_pair(jobId, eventIt->second));
    }
    want.SetParam(LAUNCH_PARAMETER_DOCUMENT_NAME, adapterParam->documentName);
    BuildPrintAttributesParam(adapterParam, want);
}

void PrintServiceAbility::BuildPrintAttributesParam(const std::shared_ptr<AdapterParam> &adapterParam,
    AAFwk::Want &want)
{
    json attrJson;
    PrintAttributes attrParam = adapterParam->printAttributes;
    if (attrParam.HasCopyNumber()) {
        attrJson["copyNumber"] = attrParam.GetCopyNumber();
    }
    if (attrParam.HasSequential()) {
        attrJson["isSequential"] = attrParam.GetIsSequential();
    }
    if (attrParam.HasLandscape()) {
        attrJson["isLandscape"] = attrParam.GetIsLandscape();
    }
    if (attrParam.HasDirectionMode()) {
        attrJson["directionMode"] = attrParam.GetDirectionMode();
    }
    if (attrParam.HasColorMode()) {
        attrJson["colorMode"] = attrParam.GetColorMode();
    }
    if (attrParam.HasDuplexMode()) {
        attrJson["duplexMode"] = attrParam.GetDuplexMode();
    }
    ParseAttributesObjectParamForJson(attrParam, attrJson);
    if (attrParam.HasOption()) {
        attrJson["options"] = attrParam.GetOption();
    }
    want.SetParam(LAUNCH_PARAMETER_PRINT_ATTRIBUTE, attrJson.dump());
    PRINT_HILOGD("CallSpooler set printAttributes: %{public}s", attrJson.dump().c_str());
}

void PrintServiceAbility::ParseAttributesObjectParamForJson(
    const PrintAttributes &attrParam, nlohmann::json &attrJson)
{
    if (attrParam.HasPageRange()) {
        json pageRangeJson;
        PrintRange printRangeAttr;
        attrParam.GetPageRange(printRangeAttr);
        if (printRangeAttr.HasStartPage()) {
            pageRangeJson["startPage"] = printRangeAttr.GetStartPage();
        }
        if (printRangeAttr.HasEndPage()) {
            pageRangeJson["endPage"] = printRangeAttr.GetEndPage();
        }
        if (printRangeAttr.HasPages()) {
            std::vector<uint32_t> pages;
            printRangeAttr.GetPages(pages);
            pageRangeJson["pages"] = pages;
        }
        attrJson["pageRange"] = pageRangeJson;
    }
    if (attrParam.HasPageSize()) {
        json pageSizeJson;
        PrintPageSize pageSizeAttr;
        attrParam.GetPageSize(pageSizeAttr);
        pageSizeJson["id"] = pageSizeAttr.GetId();
        pageSizeJson["name"] = pageSizeAttr.GetName();
        pageSizeJson["width"] = pageSizeAttr.GetWidth();
        pageSizeJson["height"] = pageSizeAttr.GetHeight();
        attrJson["pageSize"] = pageSizeJson;
    }
    if (attrParam.HasMargin()) {
        json marginJson;
        PrintMargin marginAttr;
        attrParam.GetMargin(marginAttr);
        if (marginAttr.HasTop()) {
            marginJson["top"] = marginAttr.GetTop();
        }
        if (marginAttr.HasBottom()) {
            marginJson["bottom"] = marginAttr.GetBottom();
        }
        if (marginAttr.HasLeft()) {
            marginJson["left"] = marginAttr.GetLeft();
        }
        if (marginAttr.HasRight()) {
            marginJson["right"] = marginAttr.GetRight();
        }
        attrJson["margin"] = marginJson;
    }
}
} // namespace OHOS::Print
