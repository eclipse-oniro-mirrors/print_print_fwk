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
#include "core_service_client.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "napi_print_utils.h"
#include "print_bms_helper.h"
#include "print_constant.h"
#include "print_log.h"
#include "printer_info.h"
#include "system_ability.h"
#include "system_ability_definition.h"

namespace OHOS::Print {
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;

const uint32_t MAX_RETRY_TIMES = 10;
const uint32_t START_ABILITY_INTERVAL = 6;
const uint32_t START_DISCOVERY_DELAY = 100;
const int64_t INIT_INTERVAL = 5000L;

static const std::string PRINTEXT_BUNDLE_NAME = "com.open.harmony.packagemag";
static const std::string PRINTEXT_ABILITY_NAME =
    "com.open.harmony.packagemag.ServiceAbility2";
static const std::string SPOOLER_BUNDLE_NAME = "com.example.spoolerdemo";
static const std::string SPOOLER_ABILITY_NAME =
    "com.example.spoolerdemo.MainAbility";
static const std::string LAUNCH_PARAMETER_JOB_ID = "jobId";
static const std::string LAUNCH_PARAMETER_FILE_LIST = "fileList";
static const std::string PERMISSION_NAME_PRINT = "ohos.permission.PRINT";
static const std::string PERMISSION_NAME_PRINT_SESSION =
    "ohos.permission.PRINT_SESSION_MANAGER";
const std::string PRINTER_EVENT_TYPE = "printerStateChange";
const std::string PRINTJOB_EVENT_TYPE = "jobStateChange";
const std::string EXTINFO_EVENT_TYPE = "extInfoChange";
const std::string EVENT_BLOCK = "blocked";
const std::string EVENT_SUCCESS = "success";
const std::string EVENT_FAIL = "failed";
const std::string EVENT_CANCEL = "cancelled";

REGISTER_SYSTEM_ABILITY_BY_ID(PrintServiceAbility, PRINT_SERVICE_ID, true);

std::mutex PrintServiceAbility::instanceLock_;
sptr<PrintServiceAbility> PrintServiceAbility::instance_;
std::shared_ptr<AppExecFwk::EventHandler> PrintServiceAbility::serviceHandler_;

PrintServiceAbility::PrintServiceAbility(int32_t systemAbilityId,
                                         bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate),
      state_(ServiceRunningState::STATE_NOT_START), currentJobId_(0) {}

PrintServiceAbility::~PrintServiceAbility() {
  PRINT_HILOGE("~PrintServiceAbility state_  is %{public}d.",
               static_cast<int>(state_));
}

sptr<PrintServiceAbility> PrintServiceAbility::GetInstance() {
  if (instance_ == nullptr) {
    std::lock_guard<std::mutex> autoLock(instanceLock_);
    if (instance_ == nullptr) {
      instance_ = new PrintServiceAbility(PRINT_SERVICE_ID, true);
      PRINT_HILOGE("PrintServiceAbility instance_ create,addr=%{public}p",
                   instance_.GetRefPtr());
    }
  }
  return instance_;
}

int32_t PrintServiceAbility::Init() {
  bool ret = Publish(PrintServiceAbility::GetInstance());
  if (!ret) {
    PRINT_HILOGE("PrintServiceAbility Publish failed.");
    return ERROR_SERVER_FAIL;
  }
  state_ = ServiceRunningState::STATE_RUNNING;
  PRINT_HILOGE("state_ is %{public}d.", static_cast<int>(state_));
  PRINT_HILOGI("Init PrintServiceAbility success.");
  return ERR_OK;
}

void PrintServiceAbility::OnStart() {
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

void PrintServiceAbility::InitServiceHandler() {
  PRINT_HILOGI("InitServiceHandler started.");
  if (serviceHandler_ != nullptr) {
    PRINT_HILOGI("InitServiceHandler already init.");
    return;
  }
  std::shared_ptr<AppExecFwk::EventRunner> runner =
      AppExecFwk::EventRunner::Create("PrintServiceAbility");
  serviceHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
  PRINT_HILOGI("InitServiceHandler succeeded.");
}

void PrintServiceAbility::ManualStart() {
  if (state_ != ServiceRunningState::STATE_RUNNING) {
    PRINT_HILOGI("PrintServiceAbility restart.");
    OnStart();
  }
}

std::string PrintServiceAbility::GetPrintJobId() {
  std::lock_guard<std::mutex> autoLock(instanceLock_);
  return std::to_string(currentJobId_++);
}

void PrintServiceAbility::OnStop() {
  PRINT_HILOGI("OnStop started.");
  if (state_ != ServiceRunningState::STATE_RUNNING) {
    return;
  }
  serviceHandler_ = nullptr;
  state_ = ServiceRunningState::STATE_NOT_START;
  PRINT_HILOGI("OnStop end.");
}

int32_t
PrintServiceAbility::StartPrint(const std::vector<std::string> &fileList,
                                std::string &taskId) {
  ManualStart();
  PRINT_HILOGD("PrintServiceAbility StartPrint started.");

  if (!CheckPermission(PERMISSION_NAME_PRINT)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }

  if (fileList.empty()) {
    PRINT_HILOGE("to be printed file list is empty");
    return ERROR_INVALID_PARAMETER;
  }

  std::string jobId = GetPrintJobId();
  auto printJob = std::make_shared<PrintJob>();
  if (printJob == nullptr) {
    PRINT_HILOGE("fail to create print job");
    return ERROR_GENERIC_FAIL;
  }
  printJob->SetFiles(fileList);
  printJob->SetJobId(jobId);
  printJob->SetJobState(PRINT_JOB_PREPARED);

  AAFwk::Want want;
  want.SetElementName(SPOOLER_BUNDLE_NAME, SPOOLER_ABILITY_NAME);
  want.SetParam(LAUNCH_PARAMETER_JOB_ID, jobId);
  want.SetParam(LAUNCH_PARAMETER_FILE_LIST, fileList);
  if (!StartAbility(want)) {
    PRINT_HILOGE("Failed to start spooler ability");
    return ERROR_SERVER_FAIL;
  }
  printJobList_.insert(std::make_pair(jobId, printJob));
  taskId = jobId;
  SendPrintJobEvent(*printJob);
  return ERROR_NONE;
}

int32_t PrintServiceAbility::StopPrint(const std::string &taskId) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }

  PRINT_HILOGD("PrintServiceAbility StopPrint started.");
  return ERROR_NONE;
}

int32_t PrintServiceAbility::ConnectPrinter(const std::string &printerId) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }

  PRINT_HILOGD("ConnectPrinter started.");
  auto printerInfoIt = printerInfoList_.find(printerId);
  if (printerInfoIt == printerInfoList_.end()) {
    PRINT_HILOGE("Invalid printer id");
    return ERROR_INVALID_PRINTER;
  }

  std::string extensionId = NapiPrintUtils::GetExtensionId(printerId);
  auto extensionStateIt = extensionStateList_.find(extensionId);
  if (extensionStateIt == extensionStateList_.end()) {
    PRINT_HILOGE("Invalid extension id");
    return ERROR_INVALID_PRINTER;
  }

  if (extensionStateIt->second != PRINT_EXTENSION_RUNNING) {
    PRINT_HILOGE("Invalid Extension State");
    return ERROR_INVALID_PRINTER;
  }

  std::string cid = NapiPrintUtils::EncodeExtensionCid(
      extensionId, PRINT_EXTCB_CONNECT_PRINTER);
  auto callbackIt = extCallbackMap_.find(cid);
  if (callbackIt == extCallbackMap_.end()) {
    PRINT_HILOGW("ConnectPrinter Not Register Yet!!!");
    return ERROR_SERVER_FAIL;
  }

  int32_t ret = ERROR_SERVER_FAIL;
  if (callbackIt->second->OnCallback(printerId)) {
    ret = ERROR_NONE;
  }
  return ret;
}

int32_t PrintServiceAbility::DisconnectPrinter(const std::string &printerId) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }

  PRINT_HILOGD("DisconnectPrinter started.");
  auto printerInfoIt = printerInfoList_.find(printerId);
  if (printerInfoIt == printerInfoList_.end()) {
    PRINT_HILOGE("Invalid printer id");
    return ERROR_INVALID_PRINTER;
  }

  std::string extensionId = NapiPrintUtils::GetExtensionId(printerId);
  auto extensionStateIt = extensionStateList_.find(extensionId);
  if (extensionStateIt == extensionStateList_.end()) {
    PRINT_HILOGE("Invalid extension id");
    return ERROR_INVALID_PRINTER;
  }

  if (extensionStateIt->second != PRINT_EXTENSION_RUNNING) {
    PRINT_HILOGE("Invalid Extension State");
    return ERROR_INVALID_PRINTER;
  }

  std::string cid = NapiPrintUtils::EncodeExtensionCid(
      extensionId, PRINT_EXTCB_DISCONNECT_PRINTER);
  auto callbackIt = extCallbackMap_.find(cid);
  if (callbackIt == extCallbackMap_.end()) {
    PRINT_HILOGW("DisconnectPrinter Not Register Yet!!!");
    return ERROR_SERVER_FAIL;
  }

  int32_t ret = ERROR_SERVER_FAIL;
  if (callbackIt->second->OnCallback(printerId)) {
    ret = ERROR_NONE;
  }
  return ret;
}

int32_t PrintServiceAbility::StartDiscoverPrinter(
    const std::vector<std::string> &extensionIds) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }

  PRINT_HILOGD("StartDiscoverPrinter started.");
  printerInfoList_.clear();
  std::map<std::string, AppExecFwk::ExtensionAbilityInfo> abilityList;
  for (auto extensionId : extensionIds) {
    if (extensionList_.find(extensionId) != extensionList_.end()) {
      abilityList.insert(
          std::make_pair(extensionId, extensionList_[extensionId]));
    }
  }
  if (abilityList.empty()) {
    for (auto extension : extensionList_) {
      abilityList.insert(std::make_pair(extension.first, extension.second));
    }
  }

  if (abilityList.empty()) {
    PRINT_HILOGW("No valid extension found");
    return ERROR_INVALID_EXTENSION;
  }

  for (auto ability : abilityList) {
    AAFwk::Want want;
    want.SetElementName(ability.second.bundleName, ability.second.name);
    if (!StartAbility(want)) {
      PRINT_HILOGE("Failed to load extension %{public}s",
                   ability.second.name.c_str());
      continue;
    }
    auto extensionState = extensionStateList_.find(ability.first);
    if (extensionState == extensionStateList_.end()) {
      PRINT_HILOGE("extension has been removed");
      return ERROR_SERVER_FAIL;
    }
    extensionState->second = PRINT_EXTENSION_LOADING;
  }

  auto callback = [=]() { DelayStartDiscovery(); };
  serviceHandler_->PostTask(callback, START_DISCOVERY_DELAY);
  PRINT_HILOGD("StartDiscoverPrinter end.");
  return ERROR_NONE;
}

bool PrintServiceAbility::DelayStartDiscovery() {
  PRINT_HILOGD("DelayStartDiscovery started.");
  uint32_t loadingCount = 0;
  for (auto extension : extensionStateList_) {
    if (extension.second == PRINT_EXTENSION_LOADED) {
      std::string cid = NapiPrintUtils::EncodeExtensionCid(
          extension.first, PRINT_EXTCB_START_DISCOVERY);
      auto callbackIt = extCallbackMap_.find(cid);
      if (callbackIt == extCallbackMap_.end()) {
        PRINT_HILOGE("StartDiscoverPrinter Not Register, BUT State is LOADED");
        continue;
      }
      callbackIt->second->OnCallback();
      extension.second = PRINT_EXTENSION_RUNNING;
    } else if (extension.second == PRINT_EXTENSION_LOADING) {
      loadingCount++;
    }
  }

  if (loadingCount > 0) {
    auto callback = [=]() { DelayStartDiscovery(); };
    serviceHandler_->PostTask(callback, START_DISCOVERY_DELAY);
  }
  PRINT_HILOGD("[%{public}d] extension need to discover printer", loadingCount);
  return true;
}

int32_t PrintServiceAbility::StopDiscoverPrinter() {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }
  PRINT_HILOGD("StopDiscoverPrinter started.");
  for (auto extension : extensionStateList_) {
    if (extension.second >= PRINT_EXTENSION_LOADING) {
      std::string cid = NapiPrintUtils::EncodeExtensionCid(
          extension.first, PRINT_EXTCB_STOP_DISCOVERY);
      auto callbackIt = extCallbackMap_.find(cid);
      if (callbackIt == extCallbackMap_.end()) {
        continue;
      }
      callbackIt->second->OnCallback();
      extension.second = PRINT_EXTENSION_UNLOAD;
    }
  }
  PRINT_HILOGW("StopDiscoverPrinter out.");
  return ERROR_NONE;
}

int32_t PrintServiceAbility::QueryAllExtension(
    std::vector<PrintExtensionInfo> &extensionInfos) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }
  PRINT_HILOGD("QueryAllExtension started.");
  std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfo;
  if (!DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryExtensionInfos(
          extensionInfo)) {
    PRINT_HILOGE("Failed to query extension");
    return ERROR_SERVER_FAIL;
  }
  extensionList_.clear();
  extensionStateList_.clear();
  for (auto extInfo : extensionInfo) {
    PRINT_HILOGD("bundleName = %{public}s", extInfo.bundleName.c_str());
    PRINT_HILOGD("moduleName = %{public}s", extInfo.moduleName.c_str());
    PRINT_HILOGD("name = %{public}s", extInfo.name.c_str());
    PrintExtensionInfo printExtInfo = ConvertToPrintExtensionInfo(extInfo);
    extensionInfos.emplace_back(printExtInfo);
    extensionList_.insert(
        std::make_pair(printExtInfo.GetExtensionId(), extInfo));
    extensionStateList_.insert(
        std::make_pair(printExtInfo.GetExtensionId(), PRINT_EXTENSION_UNLOAD));
  }
  PRINT_HILOGE("QueryAllExtension End.");
  return ERROR_NONE;
}

int32_t PrintServiceAbility::StartPrintJob(const PrintJob &jobInfo) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }
  std::lock_guard<std::mutex> lock(mapMutex_);
  PRINT_HILOGD("StartPrintJob started.");
  if (printJobList_.find(jobInfo.GetJobId()) == printJobList_.end()) {
    PRINT_HILOGD("invalid job id");
    return ERROR_INVALID_PRINTJOB;
  }

  if (jobInfo.GetJobState() != PRINT_JOB_PREPARED) {
    PRINT_HILOGD(
        "invalid job state, only prepare state support to start print job");
    return ERROR_INVALID_PRINTJOB;
  }

  if (printerInfoList_.find(jobInfo.GetPrinterId()) == printerInfoList_.end()) {
    PRINT_HILOGD("invalid printer of the print job");
    return ERROR_INVALID_PRINTJOB;
  }

  std::string extensionId =
      NapiPrintUtils::GetExtensionId(jobInfo.GetPrinterId());
  auto extensionStateIt = extensionStateList_.find(extensionId);
  if (extensionStateIt == extensionStateList_.end()) {
    PRINT_HILOGE("Invalid extension id");
    return ERROR_INVALID_PRINTJOB;
  }

  if (extensionStateIt->second != PRINT_EXTENSION_RUNNING) {
    PRINT_HILOGE("Invalid Extension State");
    return ERROR_INVALID_PRINTJOB;
  }

  std::string cid =
      NapiPrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
  auto callbackIt = extCallbackMap_.find(cid);
  if (callbackIt == extCallbackMap_.end()) {
    PRINT_HILOGW("StartPrintJob Not Register Yet!!!");
    return ERROR_SERVER_FAIL;
  }

  int32_t ret = ERROR_SERVER_FAIL;
  if (callbackIt->second->OnCallback(jobInfo)) {
    *printJobList_[jobInfo.GetJobId()] = jobInfo;
    printJobList_[jobInfo.GetJobId()]->SetJobState(PRINT_JOB_QUEUED);
    UpdatePrintJobState(jobInfo.GetJobId(), PRINT_JOB_QUEUED,
                        PRINT_JOB_BLOCKED_UNKNOWN);
    ret = ERROR_NONE;
  }
  return ret;
}

int32_t PrintServiceAbility::CancelPrintJob(const PrintJob &jobInfo) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }
  PRINT_HILOGD("CancelPrintJob started.");

  if (printJobList_.find(jobInfo.GetJobId()) == printJobList_.end()) {
    PRINT_HILOGD("invalid job id");
    return ERROR_INVALID_PRINTJOB;
  }

  auto printJob = printJobList_[jobInfo.GetJobId()];

  if (printJob->GetJobState() < PRINT_JOB_RUNNING) {
    PRINT_HILOGD(
        "invalid job state, only prepare state support to start print job");
    return ERROR_INVALID_PRINTJOB;
  }

  std::string extensionId =
      NapiPrintUtils::GetExtensionId(printJob->GetPrinterId());
  auto extensionStateIt = extensionStateList_.find(extensionId);
  if (extensionStateIt == extensionStateList_.end()) {
    PRINT_HILOGE("Invalid extension id");
    return ERROR_INVALID_PRINTJOB;
  }

  if (extensionStateIt->second != PRINT_EXTENSION_RUNNING) {
    PRINT_HILOGE("Invalid Extension State");
    return ERROR_INVALID_PRINTJOB;
  }

  std::string cid =
      NapiPrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CANCEL_PRINT);
  auto callbackIt = extCallbackMap_.find(cid);
  if (callbackIt == extCallbackMap_.end()) {
    PRINT_HILOGW("CancelPrintJob Not Register Yet!!!");
    return ERROR_SERVER_FAIL;
  }

  int32_t ret = ERROR_SERVER_FAIL;
  if (callbackIt->second->OnCallback(jobInfo)) {
    ret = ERROR_NONE;
  }
  return ret;
}

int32_t
PrintServiceAbility::AddPrinters(const std::vector<PrinterInfo> &printerInfos) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }
  std::lock_guard<std::mutex> lock(mapMutex_);
  PRINT_HILOGD("AddPrinters started. Total size is %{public}d",
               printerInfoList_.size());
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
    printerInfoList_.insert(
        std::make_pair(printerInfo->GetPrinterId(), printerInfo));
    SendPrinterEvent(*printerInfo);
  }
  PRINT_HILOGD("AddPrinters end. Total size is %{public}d",
               printerInfoList_.size());
  return ERROR_NONE;
}

int32_t PrintServiceAbility::RemovePrinters(
    const std::vector<std::string> &printerIds) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }
  std::lock_guard<std::mutex> lock(mapMutex_);
  PRINT_HILOGD("RemovePrinters started. Total size is %{public}d",
               printerInfoList_.size());
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
  PRINT_HILOGD("RemovePrinters end. Total size is %{public}d",
               printerInfoList_.size());
  return ERROR_NONE;
}

int32_t PrintServiceAbility::UpdatePrinters(
    const std::vector<PrinterInfo> &printerInfos) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }
  std::lock_guard<std::mutex> lock(mapMutex_);
  PRINT_HILOGD("UpdatePrinters started. Total size is %{public}d",
               printerInfoList_.size());
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
  PRINT_HILOGD("UpdatePrinters end. Total size is %{public}d",
               printerInfoList_.size());
  return ERROR_NONE;
}

int32_t PrintServiceAbility::UpdatePrinterState(const std::string &printerId,
                                                uint32_t state) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }

  if (state > PRINTER_UNKNOWN) {
    return ERROR_INVALID_PARAMETER;
  }

  std::lock_guard<std::mutex> lock(mapMutex_);
  PRINT_HILOGD("UpdatePrinterState started. %{printerId}s, state [%{public}d]",
               printerId.c_str(), state);
  if (printerInfoList_.find(printerId) == printerInfoList_.end()) {
    return ERROR_INVALID_PRINTER;
  }

  auto printerInfo = printerInfoList_[printerId];
  printerInfo->SetPrinterState(state);
  SendPrinterEvent(*printerInfo);
  PRINT_HILOGD("UpdatePrinterState end.");
  return ERROR_NONE;
}

int32_t PrintServiceAbility::UpdatePrintJobState(const std::string &jobId,
                                                 uint32_t state,
                                                 uint32_t subState) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }

  if (state > PRINT_JOB_UNKNOWN) {
    return ERROR_INVALID_PARAMETER;
  }
  if (state == PRINT_JOB_BLOCKED && (subState < PRINT_JOB_BLOCKED_OFFLINE ||
                                     subState > PRINT_JOB_BLOCKED_UNKNOWN)) {
    return ERROR_INVALID_PARAMETER;
  }

  if (state == PRINT_JOB_COMPLETED &&
      subState > PRINT_JOB_COMPLETED_FILE_CORRUPT) {
    return ERROR_INVALID_PARAMETER;
  }

  std::lock_guard<std::mutex> lock(mapMutex_);
  PRINT_HILOGD("UpdatePrintJobState started. %{public}s, state [%{public}d]",
               jobId.c_str(), state);
  if (printJobList_.find(jobId) == printJobList_.end()) {
    return ERROR_INVALID_PRINTJOB;
  }

  auto printJob = printJobList_[jobId];
  printJob->SetJobState(state);
  printJob->SetSubState(subState);
  SendPrintJobEvent(*printJob);
  PRINT_HILOGD("UpdatePrintJobState end.");
  return ERROR_NONE;
}

int32_t PrintServiceAbility::UpdateExtensionInfo(const std::string &extensionId,
                                                 const std::string &extInfo) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }
  std::lock_guard<std::mutex> lock(mapMutex_);
  PRINT_HILOGD("UpdateExtensionInfo started. %{public}s, extInfo [%{public}s]",
               extensionId.c_str(), extInfo.c_str());
  if (extensionList_.find(extensionId) == extensionList_.end()) {
    return ERROR_INVALID_EXTENSION;
  }
  SendExtensionEvent(extensionId, extInfo);
  PRINT_HILOGD("UpdateExtensionInfo end.");
  return ERROR_NONE;
}

int32_t PrintServiceAbility::RequestPreview(const PrintJob &jobInfo,
                                            std::string &previewResult) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }
  PRINT_HILOGD("RequestPreview started.");
  if (printJobList_.find(jobInfo.GetJobId()) == printJobList_.end()) {
    PRINT_HILOGD("invalid job id");
    return ERROR_INVALID_PRINTJOB;
  }

  if (jobInfo.GetJobState() != PRINT_JOB_PREPARED) {
    PRINT_HILOGD(
        "invalid job state, only prepared state support to request previe");
    return ERROR_INVALID_PRINTJOB;
  }

  if (printerInfoList_.find(jobInfo.GetPrinterId()) == printerInfoList_.end()) {
    PRINT_HILOGD("invalid printer of the print job");
    return ERROR_INVALID_PRINTJOB;
  }

  std::string extensionId =
      NapiPrintUtils::GetExtensionId(jobInfo.GetPrinterId());
  auto extensionStateIt = extensionStateList_.find(extensionId);
  if (extensionStateIt == extensionStateList_.end()) {
    PRINT_HILOGE("Invalid extension id");
    return ERROR_INVALID_PRINTJOB;
  }

  if (extensionStateIt->second != PRINT_EXTENSION_RUNNING) {
    PRINT_HILOGE("Invalid Extension State");
    return ERROR_INVALID_PRINTJOB;
  }

  std::string cid = NapiPrintUtils::EncodeExtensionCid(
      extensionId, PRINT_EXTCB_REQUEST_PREVIEW);
  auto callbackIt = extCallbackMap_.find(cid);
  if (callbackIt == extCallbackMap_.end()) {
    PRINT_HILOGW("RequestPreview Not Register Yet!!!");
    return ERROR_SERVER_FAIL;
  }

  int32_t ret = ERROR_SERVER_FAIL;
  if (callbackIt->second->OnCallback(jobInfo)) {
    ret = ERROR_NONE;
  }
  return ret;
}

int32_t PrintServiceAbility::QueryPrinterCapability(
    const std::string &printerId, PrinterCapability &printerCapability) {
  ManualStart();
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }
  PRINT_HILOGD("QueryPrinterCapability started.");
  PRINT_HILOGD("printerId : %{public}s", printerId.c_str());
  auto printerInfoIt = printerInfoList_.find(printerId);
  if (printerInfoIt == printerInfoList_.end()) {
    PRINT_HILOGE("Invalid printer id");
    return ERROR_INVALID_PRINTER;
  }

  std::string extensionId = NapiPrintUtils::GetExtensionId(printerId);
  auto extensionStateIt = extensionStateList_.find(extensionId);
  if (extensionStateIt == extensionStateList_.end()) {
    PRINT_HILOGE("Invalid extension id");
    return ERROR_INVALID_PRINTER;
  }

  if (extensionStateIt->second != PRINT_EXTENSION_RUNNING) {
    PRINT_HILOGE("Invalid Extension State");
    return ERROR_INVALID_PRINTER;
  }

  std::string cid =
      NapiPrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_REQUEST_CAP);
  auto callbackIt = extCallbackMap_.find(cid);
  if (callbackIt == extCallbackMap_.end()) {
    PRINT_HILOGW("QueryPrinterCapability Not Register Yet!!!");
    return ERROR_SERVER_FAIL;
  }

  int32_t ret = ERROR_SERVER_FAIL;
  MessageParcel reply;
  if (callbackIt->second->OnCallback(printerId, printerCapability)) {
    ret = ERROR_NONE;
    printerCapability.Dump();
  }
  return ret;
}

bool PrintServiceAbility::CheckPermission(const std::string &permissionName) {
  /*
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
      //return result == PERMISSION_GRANTED;
  */
  return true;
}

int32_t PrintServiceAbility::RegisterExtCallback(
    const std::string &extensionCID,
    const sptr<IPrintExtensionCallback> &listener) {
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }
  std::string extensionId = "";
  uint32_t callbackId = 0;
  if (!NapiPrintUtils::DecodeExtensionCid(extensionCID, extensionId,
                                          callbackId)) {
    PRINT_HILOGE("Failed to decode extension");
    return ERROR_INVALID_PARAMETER;
  }

  PRINT_HILOGD("extensionCID = %{public}s, extensionId = %{public}s",
               extensionCID.c_str(), extensionId.c_str());

  auto extensionStateIt = extensionStateList_.find(extensionId);
  if (extensionStateIt == extensionStateList_.end()) {
    PRINT_HILOGE("Invalid extension id");
    return ERROR_INVALID_EXTENSION;
  }

  if (extensionStateIt->second != PRINT_EXTENSION_LOADING) {
    PRINT_HILOGE("Invalid Extension State");
    return ERROR_INVALID_EXTENSION;
  }

  PRINT_HILOGD(
      "PrintServiceAbility::RegisterExtCallback started. callbackId=%{public}d",
      callbackId);
  if (callbackId >= PRINT_EXTCB_MAX) {
    PRINT_HILOGE("Invalid callback id");
    return ERROR_INVALID_PARAMETER;
  }
  std::lock_guard<std::mutex> lock(mapMutex_);
  auto it = extCallbackMap_.find(extensionCID);
  if (it == extCallbackMap_.end()) {
    extCallbackMap_.insert(std::make_pair(extensionCID, listener));
  } else {
    PRINT_HILOGD("PrintServiceAbility::RegisterExtCallback Replace listener.");
    extCallbackMap_[extensionCID] = listener;
  }

  PRINT_HILOGD("PrintServiceAbility::RegisterExtCallback end.");
  return ERROR_NONE;
}

int32_t
PrintServiceAbility::UnregisterAllExtCallback(const std::string &extensionId) {
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }

  PRINT_HILOGD("PrintServiceAbility::UnregisterAllExtCallback started.");
  std::lock_guard<std::mutex> lock(mapMutex_);
  for (uint32_t callbackId = PRINT_EXTCB_START_DISCOVERY;
       callbackId < PRINT_EXTCB_MAX; callbackId++) {
    std::string cid =
        NapiPrintUtils::EncodeExtensionCid(extensionId, callbackId);
    auto callbackIt = extCallbackMap_.find(cid);
    if (callbackIt != extCallbackMap_.end()) {
      extCallbackMap_.erase(callbackIt);
    }
  }
  PRINT_HILOGD("PrintServiceAbility::UnregisterAllExtCallback end.");
  return ERROR_NONE;
}

int32_t PrintServiceAbility::LoadExtSuccess(const std::string &extensionId) {
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }

  PRINT_HILOGD("PrintServiceAbility::LoadExtSuccess started.");
  auto extensionStateIt = extensionStateList_.find(extensionId);
  if (extensionStateIt == extensionStateList_.end()) {
    PRINT_HILOGE("Invalid extension id");
    return ERROR_INVALID_EXTENSION;
  }

  if (extensionStateIt->second != PRINT_EXTENSION_LOADING) {
    PRINT_HILOGE("Invalid Extension State");
    return ERROR_INVALID_EXTENSION;
  }

  extensionStateIt->second = PRINT_EXTENSION_LOADED;
  PRINT_HILOGD("PrintServiceAbility::LoadExtSuccess end.");
  return ERROR_NONE;
}

int32_t PrintServiceAbility::Read(std::vector<uint8_t> &fileRead,
                                  const std::string &uri, uint32_t offset,
                                  uint32_t max) {
  if (!CheckPermission(PERMISSION_NAME_PRINT_SESSION)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }

  return ERROR_NONE;
}

int32_t PrintServiceAbility::On(const std::string taskId,
                                const std::string &type,
                                const sptr<IPrintCallback> &listener) {
  std::string permission = PERMISSION_NAME_PRINT_SESSION;
  std::string eventType = type;
  if (taskId != "") {
    permission = PERMISSION_NAME_PRINT;
    eventType = NapiPrintUtils::GetTaskEventId(taskId, type);
  }
  if (!CheckPermission(permission)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }

  std::lock_guard<std::mutex> lock(mapMutex_);
  PRINT_HILOGD("PrintServiceAbility::On started. type=%{public}s",
               eventType.c_str());
  auto iter = registeredListeners_.find(eventType);
  if (iter == registeredListeners_.end()) {
    const auto temp =
        registeredListeners_.insert(std::make_pair(eventType, listener));
    if (!temp.second) {
      PRINT_HILOGE(
          "PrintServiceAbility::On insert type=%{public}s object fail.",
          eventType.c_str());
      return ERROR_SERVER_FAIL;
    }
  } else {
    PRINT_HILOGD("PrintServiceAbility::On Replace listener.");
    registeredListeners_[eventType] = listener;
  }
  PRINT_HILOGD("PrintServiceAbility::On end.");
  return ERROR_NONE;
}

int32_t PrintServiceAbility::Off(const std::string taskId,
                                 const std::string &type) {
  std::string permission = PERMISSION_NAME_PRINT_SESSION;
  std::string eventType = type;
  if (taskId != "") {
    permission = PERMISSION_NAME_PRINT;
    eventType = NapiPrintUtils::GetTaskEventId(taskId, type);
  }
  if (!CheckPermission(permission)) {
    PRINT_HILOGE("no permission to access print service");
    return ERROR_NO_PERMISSION;
  }

  std::lock_guard<std::mutex> lock(mapMutex_);
  PRINT_HILOGD("PrintServiceAbility::Off started.");
  auto iter = registeredListeners_.find(eventType);
  if (iter != registeredListeners_.end()) {
    PRINT_HILOGD(
        "PrintServiceAbility::Off delete type=%{public}s object message.",
        eventType.c_str());
    registeredListeners_.erase(iter);
    return ERROR_NONE;
  }
  return ERROR_INVALID_PARAMETER;
}

bool PrintServiceAbility::StartAbility(const AAFwk::Want &want) {
  AppExecFwk::ElementName element = want.GetElement();
  AAFwk::AbilityManagerClient::GetInstance()->Connect();
  uint32_t retry = 0;
  while (retry++ < MAX_RETRY_TIMES) {
    PRINT_HILOGD("PrintServiceAbility::StartAbility %{public}s %{public}s",
                 element.GetBundleName().c_str(),
                 element.GetAbilityName().c_str());
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

PrintExtensionInfo PrintServiceAbility::ConvertToPrintExtensionInfo(
    const AppExecFwk::ExtensionAbilityInfo &extInfo) {
  PrintExtensionInfo printExtInfo;
  printExtInfo.SetExtensionId(extInfo.bundleName);
  printExtInfo.SetVendorId(extInfo.bundleName);
  printExtInfo.SetVendorName(extInfo.bundleName);
  printExtInfo.SetVendorIcon(0);
  printExtInfo.SetVersion("1.0.0");
  return printExtInfo;
}

void PrintServiceAbility::SendPrinterEvent(const PrinterInfo &info) {
  PRINT_HILOGD(
      "PrintServiceAbility::SendPrinterEvent type %{public}s, %{public}d",
      info.GetPrinterId().c_str(), info.GetPrinterState());
  auto eventIt = registeredListeners_.find(PRINTER_EVENT_TYPE);
  if (eventIt != registeredListeners_.end()) {
    eventIt->second->OnCallback(info.GetPrinterState(), info);
  }
}

void PrintServiceAbility::SendPrintJobEvent(const PrintJob &jobInfo) {
  PRINT_HILOGD(
      "PrintServiceAbility::SendPrintJobEvent type %{public}s, %{public}d",
      jobInfo.GetJobId().c_str(), jobInfo.GetJobState());
  auto eventIt = registeredListeners_.find(PRINTJOB_EVENT_TYPE);
  if (eventIt != registeredListeners_.end()) {
    eventIt->second->OnCallback(jobInfo.GetJobState(), jobInfo);
  }

  std::string stateInfo = "";
  if (jobInfo.GetJobState() == PRINT_JOB_BLOCKED) {
    stateInfo = EVENT_BLOCK;
  } else {
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
    std::string taskEvent =
        NapiPrintUtils::GetTaskEventId(jobInfo.GetJobId(), stateInfo);
    auto taskEventIt = registeredListeners_.find(taskEvent);
    if (taskEventIt != registeredListeners_.end()) {
      taskEventIt->second->OnCallback();
    }
  }
}

void PrintServiceAbility::SendExtensionEvent(const std::string &extensionId,
                                             const std::string &extInfo) {
  PRINT_HILOGD("PrintServiceAbility::SendExtensionEvent type %{public}s",
               extInfo.c_str());
  auto eventIt = registeredListeners_.find(EXTINFO_EVENT_TYPE);
  if (eventIt != registeredListeners_.end()) {
    eventIt->second->OnCallback(extensionId, extInfo);
  }
}
} // namespace OHOS::Print
