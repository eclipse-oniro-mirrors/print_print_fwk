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

#include "accesstoken_kit.h"
#include "array_wrapper.h"
#include "core_service_client.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "napi_print_utils.h"
#include "print_bms_helper.h"
#include "print_constant.h"
#include "print_log.h"
#include "printer_info.h"
#include "string_wrapper.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#include "want_params_wrapper.h"

namespace OHOS::Print {
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;

const uint32_t MAX_RETRY_TIMES = 10;
const uint32_t START_ABILITY_INTERVAL = 6;
const uint32_t ASYNC_CMD_DELAY = 10;
const int64_t INIT_INTERVAL = 5000L;

static const std::string PRINTEXT_BUNDLE_NAME = "com.open.harmony.packagemag";
static const std::string PRINTEXT_ABILITY_NAME = "com.open.harmony.packagemag.ServiceAbility2";
static const std::string PRINT_XML_PATH = "/system/profile/print_service.xml";
static const std::string SPOOLER_BUNDLE_BEGIN_TAG = "<spooler-bundle>";
static const std::string SPOOLER_BUNDLE_END_TAG = "</spooler-bundle>";
static const std::string SPOOLER_ABILITY_BEGIN_TAG = "<spooler-ability>";
static const std::string SPOOLER_ABILITY_END_TAG = "</spooler-ability>";
static const std::string DEFAULT_SPOOLER_ABILITY_NAME = ".MainAbility";
static const std::string SPOOLER_BUNDLE_NAME = "com.example.spoolerdemo";
static const std::string SPOOLER_ABILITY_NAME = "com.example.spoolerdemo.MainAbility";
static const std::string LAUNCH_PARAMETER_JOB_ID = "jobId";
static const std::string LAUNCH_PARAMETER_FILE_LIST = "fileList";
static const std::string LAUNCH_PARAMETER_FD_LIST = "fdList";
static const std::string PERMISSION_NAME_PRINT = "ohos.permission.PRINT";
static const std::string PERMISSION_NAME_PRINT_JOB = "ohos.permission.MANAGE_PRINT_JOB";
static const std::string PRINTER_EVENT_TYPE = "printerStateChange";
static const std::string PRINTJOB_EVENT_TYPE = "jobStateChange";
static const std::string EXTINFO_EVENT_TYPE = "extInfoChange";
static const std::string EVENT_BLOCK = "blocked";
static const std::string EVENT_SUCCESS = "success";
static const std::string EVENT_FAIL = "failed";
static const std::string EVENT_CANCEL = "cancelled";

static const std::string FD = "FD";
static const std::string TYPE_PROPERTY = "type";
static const std::string VALUE_PROPERTY = "value";


REGISTER_SYSTEM_ABILITY_BY_ID(PrintServiceAbility, PRINT_SERVICE_ID, true);

std::mutex PrintServiceAbility::instanceLock_;
sptr<PrintServiceAbility> PrintServiceAbility::instance_;
std::shared_ptr<AppExecFwk::EventHandler> PrintServiceAbility::serviceHandler_;

PrintServiceAbility::PrintServiceAbility(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START), 
    spoolerBundleName_(SPOOLER_BUNDLE_NAME), spoolerAbilityName_(SPOOLER_ABILITY_NAME), currentJobId_(0)
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
            PRINT_HILOGE("PrintServiceAbility instance_ create,addr=%{public}p", instance_.GetRefPtr());
        }
    }
    return instance_;
}

int32_t PrintServiceAbility::Init()
{
    bool ret = Publish(PrintServiceAbility::GetInstance());
    if (!ret) {
        PRINT_HILOGE("PrintServiceAbility Publish failed.");
        return E_PRINT_SERVER_FAILURE;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    PRINT_HILOGE("state_ is %{public}d.", static_cast<int>(state_));
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

    if (spoolerBundleName_ == SPOOLER_BUNDLE_NAME) {
        FILE *file = fopen(PRINT_XML_PATH.c_str(), "rt");
        if (file != nullptr) {
            std::vector<char> buffer;
            fseek(file, 0, SEEK_END);
            int32_t fileSize = static_cast<int32_t>(ftell(file));
            buffer.resize(fileSize + 1);
            fseek(file, 0, SEEK_SET);
            fread(static_cast<char*>(&buffer[0]), 1, fileSize, file);
            buffer[fileSize] = '\0';
            std::string config = &buffer[0];
            auto pos = config.find(SPOOLER_BUNDLE_BEGIN_TAG);
            if (pos != std::string::npos) {
                spoolerBundleName_ = config.substr(pos + SPOOLER_BUNDLE_BEGIN_TAG.size());
                spoolerBundleName_ = spoolerBundleName_.substr(0, spoolerBundleName_.find(SPOOLER_BUNDLE_END_TAG));
            }
            pos = config.find(SPOOLER_ABILITY_BEGIN_TAG);
            if (pos != std::string::npos) {
                spoolerAbilityName_ = config.substr(pos + SPOOLER_ABILITY_BEGIN_TAG.size());
                spoolerAbilityName_ = spoolerAbilityName_.substr(0, spoolerAbilityName_.find(SPOOLER_ABILITY_END_TAG));
            } else if (spoolerBundleName_ != SPOOLER_BUNDLE_NAME) {
                spoolerAbilityName_ = spoolerBundleName_ + DEFAULT_SPOOLER_ABILITY_NAME;
            }
        }
        fclose(file);
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

int32_t PrintServiceAbility::StartPrint(const std::vector<std::string> &fileList,
    const std::vector<uint32_t> &fdList, std::string &taskId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGD("no permission to access print service, ErrorCode:[%{public}d]", E_PRINT_NO_PERMISSION);
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("PrintServiceAbility StartPrint started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (fileList.empty()) {
        PRINT_HILOGE("to be printed file list is empty");
        return E_PRINT_INVALID_PARAMETER;
    }
    std::string jobId = GetPrintJobId();
    auto printJob = std::make_shared<PrintJob>();
    if (printJob == nullptr) {
        return E_PRINT_GENERIC_FAILURE;
    }
    printJob->SetFdList(fdList);
    printJob->SetJobId(jobId);
    printJob->SetJobState(PRINT_JOB_PREPARED);
    AAFwk::Want want;
    want.SetElementName(spoolerBundleName_, spoolerAbilityName_);
    want.SetParam(LAUNCH_PARAMETER_JOB_ID, jobId);
    want.SetParam(LAUNCH_PARAMETER_FILE_LIST, fileList);
    if (fdList.size() > 0) {
        AAFwk::WantParams wantParams = want.GetParams();
        sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(fdList.size(), AAFwk::g_IID_IWantParams);
        if (ao == nullptr) {
            PRINT_HILOGE("fail to create param");
            return E_PRINT_GENERIC_FAILURE;
        }
        if (ao != nullptr) {
            int32_t index = 0;
            for (auto fd : fdList) {
                AAFwk::WantParams wp;
                wp.SetParam(TYPE_PROPERTY, AAFwk::String::Box(FD));
                wp.SetParam(VALUE_PROPERTY, AAFwk::Integer::Box(fd));
                PRINT_HILOGD("fd[%{public}d] = %{public}d", index, fd);
                ao->Set(index++, AAFwk::WantParamWrapper::Box(wp));
            }
            wantParams.SetParam(LAUNCH_PARAMETER_FD_LIST, ao);
        }
        want.SetParams(wantParams);
    }
    if (!StartAbility(want)) {
        PRINT_HILOGE("Failed to start spooler ability");
        return E_PRINT_SERVER_FAILURE;
    }
    printJobList_.insert(std::make_pair(jobId, printJob));
    taskId = jobId;
    SendPrintJobEvent(*printJob);
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
    
    std::string extensionId = NapiPrintUtils::GetExtensionId(printerId);
    std::string cid = NapiPrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CONNECT_PRINTER);
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
    serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
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
    
    std::string extensionId = NapiPrintUtils::GetExtensionId(printerId);
    std::string cid = NapiPrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_DISCONNECT_PRINTER);
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
    serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
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
    printerJobMap_.clear();
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
    for (auto extension : extensionList_) {
        abilityList.insert(std::make_pair(extension.first, extension.second));
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
    
    std::string cid = NapiPrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_DISCOVERY);
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
        if (extension.second < PRINT_EXTENSION_LOADED) {
            return E_PRINT_NO_PERMISSION;
        }
        extension.second = PRINT_EXTENSION_UNLOAD;
        std::string cid = NapiPrintUtils::EncodeExtensionCid(extension.first, PRINT_EXTCB_STOP_DISCOVERY);
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
        serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
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
    PRINT_HILOGE("QueryAllExtension End.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::StartPrintJob(const PrintJob &jobInfo)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGD("StartPrintJob started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    auto jobId = jobInfo.GetJobId();
    auto printerId = jobInfo.GetPrinterId();
    auto extensionId = NapiPrintUtils::GetExtensionId(printerId);

    auto jobIt = printJobList_.find(jobId);
    if (jobIt == printJobList_.end()) {
        PRINT_HILOGD("invalid job id");
        return E_PRINT_INVALID_PRINTJOB;
    }

    if (printerInfoList_.find(printerId) == printerInfoList_.end()) {
        PRINT_HILOGD("invalid printer of the print job");
        return E_PRINT_INVALID_PRINTJOB;
    }
  
    std::string cid = NapiPrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
    if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
        PRINT_HILOGW("StartPrintJob Not Register Yet!!!");
        return E_PRINT_SERVER_FAILURE;
    }
    printJobList_.erase(jobIt);

    auto printJob = std::make_shared<PrintJob>();
    if (printJob == nullptr) {
        PRINT_HILOGE("fail to move print job to queue");
        return E_PRINT_GENERIC_FAILURE;
    }
    printJob->UpdateParams(jobInfo);
    queuedJobList_.insert(std::make_pair(jobId, printJob));
    printerJobMap_[printerId].insert(std::make_pair(jobId, true));

    auto cbFunc = extCallbackMap_[cid];
	auto callback = [=]() {
        PRINT_HILOGD("Start PrintJob %{public}s", jobId.c_str());        
        if (cbFunc != nullptr && cbFunc->OnCallback(*printJob)) {
            printJob->SetJobState(PRINT_JOB_QUEUED);
            UpdatePrintJobState(jobId, PRINT_JOB_QUEUED, PRINT_JOB_BLOCKED_UNKNOWN);
        }
    };
    serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::CancelPrintJob(const std::string &jobId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }    
    PRINT_HILOGD("CancelPrintJob started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    auto jobIt = queuedJobList_.find(jobId);
    if (jobIt == queuedJobList_.end() || jobIt->second == nullptr) {
        PRINT_HILOGD("invalid job id");
        return E_PRINT_INVALID_PRINTJOB;
    }

    int32_t ret = E_PRINT_NONE;
    if (jobIt->second->GetJobState() >= PRINT_JOB_QUEUED) {
        std::string extensionId = NapiPrintUtils::GetExtensionId(jobIt->second->GetPrinterId());
        std::string cid = NapiPrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CANCEL_PRINT);
        if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
            PRINT_HILOGW("CancelPrintJob Not Register Yet!!!");
            return E_PRINT_SERVER_FAILURE;
        }

        auto cbFunc = extCallbackMap_[cid];
        auto tmpPrintJob = queuedJobList_[jobId];
        auto callback = [=]() {
            if (cbFunc != nullptr) {
                cbFunc->OnCallback(*tmpPrintJob);
            }
        };
        serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    }
    auto printJob = std::make_shared<PrintJob>(*jobIt->second);
    if (printJob == nullptr) {
        PRINT_HILOGE("fail to move print job back to job list");
        return E_PRINT_GENERIC_FAILURE;
    }
    printJob->SetJobState(PRINT_JOB_UNKNOWN);
    printJobList_.insert(std::make_pair(jobId, printJob));

    printerJobMap_[jobIt->second->GetPrinterId()].erase(jobId);
    queuedJobList_.erase(jobIt);
    return ret;
}

void PrintServiceAbility::SendQueuePrintJob(const std::string &printerId)
{
    if (printerJobMap_[printerId].empty()) {
        return;
    }
    
    auto jobId = printerJobMap_[printerId].begin()->first;
    auto jobIt = queuedJobList_.find(jobId);
    if (jobIt == queuedJobList_.end() || jobIt->second == nullptr) {
        PRINT_HILOGE("invalid print job");
        return;
    }

    if (jobIt->second->GetJobState() != PRINT_JOB_PREPARED) {
        PRINT_HILOGE("job state isn't prepared");
        return;
    }

    auto extensionId = NapiPrintUtils::GetExtensionId(printerId);
    std::string cid = NapiPrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);

    auto cbFunc = extCallbackMap_[cid];
    auto printJob = jobIt->second;
	auto callback = [=]() {
        PRINT_HILOGD("Start Next Print Job %{public}s", jobId.c_str());
        if (cbFunc != nullptr && cbFunc->OnCallback(*printJob)) {
            printJob->SetJobState(PRINT_JOB_QUEUED);
            UpdatePrintJobState(jobId, PRINT_JOB_QUEUED, PRINT_JOB_BLOCKED_UNKNOWN);
        }
    };
    serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
}

int32_t PrintServiceAbility::AddPrinters(const std::vector<PrinterInfo> &printerInfos)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("AddPrinters started. Total size is %{public}d", printerInfoList_.size());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    for (auto info : printerInfos) {
        if (printerInfoList_.find(info.GetPrinterId()) != printerInfoList_.end()) {
            PRINT_HILOGE("duplicate printer id, ingore it");
            continue;
        }
        auto printerInfo = std::make_shared<PrinterInfo>(info);
        if (printerInfo == nullptr) {
            PRINT_HILOGE("fail to create printer info object");
            continue;            
        }
        printerInfo->SetPrinterState(PRINTER_ADDED);
        printerInfoList_.insert(std::make_pair(printerInfo->GetPrinterId(), printerInfo));
        SendPrinterEvent(*printerInfo);
        SendQueuePrintJob(printerInfo->GetPrinterId());
    }
    PRINT_HILOGD("AddPrinters end. Total size is %{public}d", printerInfoList_.size());
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
    PRINT_HILOGD("RemovePrinters started. Total size is %{public}d", count);
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    for (auto printerId : printerIds) {
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
    PRINT_HILOGD("RemovePrinters end. Total size is %{public}d", printerInfoList_.size());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::UpdatePrinters(const std::vector<PrinterInfo> &printerInfos)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }    
 
    PRINT_HILOGD("UpdatePrinters started. Total size is %{public}d", printerInfoList_.size());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    for (auto info : printerInfos) {
        auto printerIt = printerInfoList_.find(info.GetPrinterId());
        if (printerIt == printerInfoList_.end()) {
            PRINT_HILOGE("invalid printer id, ingore it");
            continue;
        }
        *printerIt->second = info;
        printerIt->second->SetPrinterState(PRINTER_UPDATE_CAP);
        SendPrinterEvent(*printerIt->second);
    }
    PRINT_HILOGD("UpdatePrinters end. Total size is %{public}d", printerInfoList_.size());
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

    PRINT_HILOGD("UpdatePrinterState started. %{printerId}s, state [%{public}d]", printerId.c_str(), state);
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (printerInfoList_.find(printerId) == printerInfoList_.end()) {
        PRINT_HILOGD("Invalid printer id");
        return E_PRINT_INVALID_PRINTER;
    }

    printerInfoList_[printerId]->SetPrinterState(state);
    SendPrinterEvent(*printerInfoList_[printerId]);
    PRINT_HILOGD("UpdatePrinterState end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::UpdatePrintJobState(const std::string &jobId, uint32_t state, uint32_t subState)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    if (state > PRINT_JOB_UNKNOWN) {
        return E_PRINT_INVALID_PARAMETER;
    }
    if (state == PRINT_JOB_BLOCKED && (subState < PRINT_JOB_BLOCKED_OFFLINE || subState > PRINT_JOB_BLOCKED_UNKNOWN)) {
        return E_PRINT_INVALID_PARAMETER;
    }
    
    if (state == PRINT_JOB_COMPLETED && subState > PRINT_JOB_COMPLETED_FILE_CORRUPT) {
        return E_PRINT_INVALID_PARAMETER;        
    }

    PRINT_HILOGD("UpdatePrintJobState started. %{public}s, state [%{public}d]", jobId.c_str(), state);
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    auto jobIt = queuedJobList_.find(jobId);
    bool jobInQueue = true;
    if (jobIt == queuedJobList_.end() || jobIt->second == nullptr) {
        jobInQueue = false;
        jobIt = printJobList_.find(jobId);
        if (jobIt == printJobList_.end() || jobIt->second == nullptr) {
            PRINT_HILOGD("Invalid print job id");
            return E_PRINT_INVALID_PRINTJOB;
        }
    }

    jobIt->second->SetJobState(state);
    jobIt->second->SetSubState(subState);
    SendPrintJobEvent(*jobIt->second);

    auto printerId = jobIt->second->GetPrinterId();
    if (state == PRINT_JOB_COMPLETED) {
        if (jobInQueue) {
            printerJobMap_[printerId].erase(jobId);
            queuedJobList_.erase(jobIt);
        }
        SendQueuePrintJob(printerId);
    }

    PRINT_HILOGD("UpdatePrintJobState end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::UpdateExtensionInfo(const std::string &extensionId, const std::string &extInfo)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }    

    PRINT_HILOGD("UpdateExtensionInfo started. %{public}s, extInfo [%{public}s]",
        extensionId.c_str(), extInfo.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (extensionList_.find(extensionId) == extensionList_.end()) {
        PRINT_HILOGD("Invalid eztension id");
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
    auto extensionId = NapiPrintUtils::GetExtensionId(printerId);

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
    
    std::string cid = NapiPrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
    if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
        PRINT_HILOGW("StartPrintJob Not Register Yet!!!");
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
    PRINT_HILOGD("QueryPrinterCapability started %{public}s", printerId.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (printerInfoList_.find(printerId) == printerInfoList_.end()) {
        PRINT_HILOGE("Invalid printer id");
        return E_PRINT_INVALID_PRINTER;
    }
    
    std::string extensionId = NapiPrintUtils::GetExtensionId(printerId);
    std::string cid = NapiPrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_REQUEST_CAP);
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
    serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    return E_PRINT_NONE;
}

bool PrintServiceAbility::CheckPermission(const std::string &permissionName)
{
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    TypeATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == TOKEN_INVALID) {
        PRINT_HILOGE("invalid token id %{public}d", tokenId);
        return false;
    }
    int result = AccessTokenKit::VerifyAccessToken(tokenId, permissionName);
    if (result != PERMISSION_GRANTED) {
        PRINT_HILOGE("Current tokenId permission is %{public}d", result);
    }
    return result == PERMISSION_GRANTED;
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
    if (!NapiPrintUtils::DecodeExtensionCid(extensionCID, extensionId, callbackId)) {
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
        std::string cid = NapiPrintUtils::EncodeExtensionCid(extensionId, callbackId);
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
    serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    PRINT_HILOGD("PrintServiceAbility::LoadExtSuccess end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::On(const std::string taskId, const std::string &type, const sptr<IPrintCallback> &listener)
{
    std::string permission = PERMISSION_NAME_PRINT_JOB;
    std::string eventType = type;
    if (taskId != "") {
        permission = PERMISSION_NAME_PRINT;
        eventType = NapiPrintUtils::GetTaskEventId(taskId, type);
    }
    if (!CheckPermission(permission)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGD("PrintServiceAbility::On started. type=%{public}s", eventType.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (registeredListeners_.find(eventType) == registeredListeners_.end()) {
        const auto temp = registeredListeners_.insert(std::make_pair(eventType, listener));
        if (!temp.second) {
            PRINT_HILOGE("PrintServiceAbility::On insert type=%{public}s object fail.", eventType.c_str());
            return E_PRINT_SERVER_FAILURE;
        }
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
        eventType = NapiPrintUtils::GetTaskEventId(taskId, type);
    }
    if (!CheckPermission(permission)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
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
    AppExecFwk::ElementName element = want.GetElement();
    AAFwk::AbilityManagerClient::GetInstance()->Connect();
    uint32_t retry = 0;
    while (retry++ < MAX_RETRY_TIMES) {
        PRINT_HILOGD("PrintServiceAbility::StartAbility %{public}s %{public}s",
            element.GetBundleName().c_str(), element.GetAbilityName().c_str());
        if (AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want) == 0) {
            break;
        }
        break;
        std::this_thread::sleep_for(std::chrono::seconds(START_ABILITY_INTERVAL));
        PRINT_HILOGD("PrintServiceAbility::StartAbility %{public}d", retry);
    }
    if (retry > MAX_RETRY_TIMES) {
        PRINT_HILOGE("PrintServiceAbility::StartAbility --> failed ");
        return false;
    }
    return true;
}
/*
bool PrintServiceAbility::StopAbility(const AAFwk::Want &want)
{
    AppExecFwk::ElementName element = want.GetElement();
    AAFwk::AbilityManagerClient::GetInstance()->Connect();
    uint32_t retry = 0;
    while (retry++ < MAX_RETRY_TIMES) {
        PRINT_HILOGD("PrintServiceAbility::StopAbility %{public}s %{public}s",
            element.GetBundleName().c_str(), element.GetAbilityName().c_str());
        if (AAFwk::AbilityManagerClient::GetInstance()->StopAbility(want) == 0) {
            break;
        }
        break;
        std::this_thread::sleep_for(std::chrono::seconds(START_ABILITY_INTERVAL));
        PRINT_HILOGD("PrintServiceAbility::StopAbility %{public}d", retry);
    }
    if (retry > MAX_RETRY_TIMES) {
        PRINT_HILOGE("PrintServiceAbility::StopAbility --> failed ");
        return false;
    }   
    return true;
}
*/
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
    PRINT_HILOGD("PrintServiceAbility::SendPrinterEvent type %{public}s, %{public}d",
        info.GetPrinterId().c_str(), info.GetPrinterState());
    auto eventIt = registeredListeners_.find(PRINTER_EVENT_TYPE);
    if (eventIt != registeredListeners_.end()) {
        eventIt->second->OnCallback(info.GetPrinterState(), info);
    }
}

void PrintServiceAbility::SendPrintJobEvent(const PrintJob &jobInfo)
{
    PRINT_HILOGD("PrintServiceAbility::SendPrintJobEvent type %{public}s, %{public}d",
        jobInfo.GetJobId().c_str(), jobInfo.GetJobState());
    auto eventIt = registeredListeners_.find(PRINTJOB_EVENT_TYPE);
    if (eventIt != registeredListeners_.end()) {
        eventIt->second->OnCallback(jobInfo.GetJobState(), jobInfo);
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
        std::string taskEvent = NapiPrintUtils::GetTaskEventId(jobInfo.GetJobId(), stateInfo);
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
} // namespace OHOS::Print
