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
#ifdef IPPOVERUSB_ENABLE
#include "print_ipp_over_usb_manager.h"
#endif // IPPOVERUSB_ENABLE
#include <fstream>
#include <streambuf>

namespace OHOS::Print {
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;
using json = nlohmann::json;

const uint32_t MAX_JOBQUEUE_NUM = 512;
const uint32_t ASYNC_CMD_DELAY = 10;
const int64_t INIT_INTERVAL = 5000L;
const int32_t UID_TRANSFORM_DIVISOR = 200000;
const std::int32_t START_USER_ID = 100;
const std::int32_t MAX_USER_ID = 1099;
const uint32_t UNLOAD_SA_INTERVAL = 90000;

const uint32_t INDEX_ZERO = 0;
const uint32_t INDEX_THREE = 3;
const uint32_t SERIAL_LENGTH = 6;

static const std::string SPOOLER_BUNDLE_NAME = "com.ohos.spooler";
static const std::string SPOOLER_PACKAGE_NAME = "com.ohos.spooler";
static const std::string PRINT_EXTENSION_BUNDLE_NAME = "com.ohos.hwprintext";
static const std::string EPRINTER_ID = "com.ohos.hwprintext:ePrintID";
static const std::string SPOOLER_ABILITY_NAME = "MainAbility";
static const std::string LAUNCH_PARAMETER_DOCUMENT_NAME = "documentName";
static const std::string LAUNCH_PARAMETER_JOB_ID = "jobId";
static const std::string LAUNCH_PARAMETER_FILE_LIST = "fileList";
static const std::string LAUNCH_PARAMETER_FD_LIST = "fdList";
static const std::string LAUNCH_PARAMETER_PRINT_ATTRIBUTE = "printAttributes";
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
static const std::string QUEUE_JOB_LIST_UNSUBSCRIBE = "unsubscribe";
static const std::string QUEUE_JOB_LIST_HIDE = "hide";
static const std::string SPOOLER_PREVIEW_ABILITY_NAME = "PrintServiceExtAbility";
static const std::string SPOOLER_STATUS_BAR_ABILITY_NAME = "PluginPrintIconExtAbility";
static const std::string TOKEN_KEY = "ohos.ability.params.token";

static const std::string NOTIFY_INFO_SPOOLER_CLOSED_FOR_CANCELLED = "spooler_closed_for_cancelled";
static const std::string NOTIFY_INFO_SPOOLER_CLOSED_FOR_STARTED = "spooler_closed_for_started";

static const std::string PRINTER_ID_DELIMITER = ":";
static const std::string USB_PRINTER = "usb";

const std::string PRINTER_PREFERENCE_FILE = "printer_preference.json";

static bool g_publishState = false;

REGISTER_SYSTEM_ABILITY_BY_ID(PrintServiceAbility, PRINT_SERVICE_ID, true);

std::mutex PrintServiceAbility::instanceLock_;
sptr<PrintServiceAbility> PrintServiceAbility::instance_;
std::shared_ptr<AppExecFwk::EventHandler> PrintServiceAbility::serviceHandler_;
std::chrono::time_point<std::chrono::high_resolution_clock> PrintServiceAbility::startPrintTime_;
std::string PrintServiceAbility::ingressPackage;

PrintServiceAbility::PrintServiceAbility(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate),
      state_(ServiceRunningState::STATE_NOT_START),
      spoolerBundleName_(SPOOLER_BUNDLE_NAME),
      spoolerAbilityName_(SPOOLER_ABILITY_NAME),
      currentJobOrderId_(0),
      helper_(nullptr),
      isJobQueueBlocked_(false),
      currentUserId_(-1),
      printAppCount_(0),
      unloadCount_(0)
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
    if (helper_ == nullptr) {
        PRINT_HILOGE("PrintServiceHelper create failed.");
        return E_PRINT_SERVER_FAILURE;
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
    printSystemData_.Init();
    InitPreferenceMap();
    state_ = ServiceRunningState::STATE_RUNNING;
    PRINT_HILOGI("state_ is %{public}d.Init PrintServiceAbility success.", static_cast<int>(state_));
    helper_->PrintSubscribeCommonEvent();
#ifdef IPPOVERUSB_ENABLE
    PRINT_HILOGD("before PrintIppOverUsbManager Init");
    DelayedSingleton<PrintIppOverUsbManager>::GetInstance()->Init();
    PRINT_HILOGD("end PrintIppOverUsbManager Init");
#endif // IPPOVERUSB_ENABLE
#ifdef CUPS_ENABLE
    return DelayedSingleton<PrintCupsClient>::GetInstance()->InitCupsResources();
#endif  // CUPS_ENABLE
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
#ifdef CUPS_ENABLE
        DelayedSingleton<PrintCupsClient>::GetInstance()->InitCupsResources();
#endif  // CUPS_ENABLE
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
    vendorManager.Init(GetInstance(), true);
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
    } else {
#ifdef CUPS_ENABLE
        DelayedSingleton<PrintCupsClient>::GetInstance()->InitCupsResources();
#endif  // CUPS_ENABLE
    }
}

std::string PrintServiceAbility::GetPrintJobOrderId()
{
    std::lock_guard<std::mutex> autoLock(instanceLock_);
    return std::to_string(currentJobOrderId_++);
}

void PrintServiceAbility::OnStop()
{
    PRINT_HILOGI("OnStop started.");
    if (state_ != ServiceRunningState::STATE_RUNNING) {
        return;
    }
    vendorManager.UnInit();
    serviceHandler_ = nullptr;
    state_ = ServiceRunningState::STATE_NOT_START;
    PRINT_HILOGI("OnStop end.");
}

int32_t PrintServiceAbility::StartService()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service, ErrorCode:[%{public}d]", E_PRINT_NO_PERMISSION);
        return E_PRINT_NO_PERMISSION;
    }
    int64_t callerTokenId = static_cast<int64_t>(IPCSkeleton::GetCallingTokenID());
    auto iter = printUserDataMap_.find(callerTokenId);
    if (iter == printUserDataMap_.end()) {
        auto userData = std::make_shared<PrintUserData>();
        if (userData != nullptr) {
            std::lock_guard<std::recursive_mutex> lock(apiMutex_);
            printUserDataMap_.insert(std::make_pair(callerTokenId, userData));
        }
    }
    printAppCount_++;
    PRINT_HILOGI("NativePrint PrintServiceAbility StartService started. PrintAppCount_: %{public}u", printAppCount_);
#ifdef CUPS_ENABLE
    return DelayedSingleton<PrintCupsClient>::GetInstance()->InitCupsResources();
#endif // CUPS_ENABLE
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::StartPrint(const std::vector<std::string> &fileList,
    const std::vector<uint32_t> &fdList, std::string &taskId)
{
    return CallSpooler(fileList, fdList, taskId);
}

int32_t PrintServiceAbility::CallSpooler(const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList,
    std::string &taskId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service, ErrorCode:[%{public}d]", E_PRINT_NO_PERMISSION);
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("PrintServiceAbility StartPrint started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (taskId.empty()) {
        PRINT_HILOGE("jobId is empty");
        return E_PRINT_INVALID_PARAMETER;
    }
    PRINT_HILOGI("CallSpooler jobId: %{public}s", taskId.c_str());
    auto printJob = std::make_shared<PrintJob>();
    if (printJob == nullptr) {
        PRINT_HILOGE("printJob is nullptr");
        return E_PRINT_SERVER_FAILURE;
    }
    printJob->SetFdList(fdList);
    printJob->SetJobId(taskId);
    printJob->SetJobState(PRINT_JOB_PREPARED);
    RegisterAdapterListener(taskId);
    std::string callerPkg = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    ingressPackage = callerPkg;
    AddToPrintJobList(taskId, printJob);
    SendPrintJobEvent(*printJob);
    securityGuardManager_.receiveBaseInfo(taskId, callerPkg, fileList);

    printAppCount_++;
    PRINT_HILOGI("printAppCount_: %{public}u", printAppCount_);
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::StopPrint(const std::string &taskId)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGD("PrintServiceAbility StopPrint started.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::HandleExtensionConnectPrinter(const std::string &printerId)
{
    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CONNECT_PRINTER);
    if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
        PRINT_HILOGW("ConnectPrinter Not Register Yet!!!");
        return E_PRINT_SERVER_FAILURE;
    }
#ifdef IPPOVERUSB_ENABLE
    int32_t port = 0;
    std::string newPrinterId = printerId;
    auto ret = DelayedSingleton<PrintIppOverUsbManager>::GetInstance()->ConnectPrinter(printerId, port);
    if (ret && port > 0) {
        newPrinterId = PrintUtils::GetGlobalId(printerId, std::to_string(port));
    }
    auto cbFunc = extCallbackMap_[cid];
    auto callback = [=]() {
        if (cbFunc != nullptr) {
            cbFunc->OnCallback(newPrinterId);
        }
    };
    if (helper_->IsSyncMode()) {
        callback();
    } else {
        serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    }
#endif // IPPOVERUSB_ENABLE
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::ConnectPrinter(const std::string &printerId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("ConnectPrinter started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    vendorManager.ClearConnectingPrinter();
    if (printSystemData_.QueryDiscoveredPrinterInfoById(printerId) == nullptr) {
        PRINT_HILOGI("Invalid printer id, try connect printer by ip");
        return TryConnectPrinterByIp(printerId);
    }
    vendorManager.SetConnectingPrinter(ID_AUTO, printerId);
    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    if (!vendorManager.ExtractVendorName(extensionId).empty()) {
        if (!vendorManager.ConnectPrinter(printerId)) {
            PRINT_HILOGE("Vendor not found");
            return E_PRINT_SERVER_FAILURE;
        }
        return E_PRINT_NONE;
    }
    return HandleExtensionConnectPrinter(printerId);
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

    if (printSystemData_.QueryDiscoveredPrinterInfoById(printerId) == nullptr) {
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
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGD("StartDiscoverPrinter started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    printSystemData_.ClearDiscoveredPrinterList();
    std::vector<std::string> printerIdList = printSystemData_.QueryAddedPrinterIdList();
    for (auto &printerId : printerIdList) {
        vendorManager.MonitorPrinterStatus(printerId, true);
    }
    vendorManager.StartStatusMonitor();
    vendorManager.StartDiscovery();
    return StartExtensionDiscovery(extensionIds);
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
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("StopDiscoverPrinter started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    vendorManager.StopDiscovery();
    vendorManager.StopStatusMonitor();
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
            serviceHandler_->PostTask(callback, 0);
        }
    }
    PRINT_HILOGW("StopDiscoverPrinter out.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::DestroyExtension()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("DestroyExtension started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    for (auto extension : extensionStateList_) {
        if (extension.second < PRINT_EXTENSION_LOADING) {
            continue;
        }
        extension.second = PRINT_EXTENSION_UNLOAD;
        std::string cid = PrintUtils::EncodeExtensionCid(extension.first, PRINT_EXTCB_DESTROY_EXTENSION);
        if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
            PRINT_HILOGE("Destroy extension Not Register, BUT State is LOADED");
            continue;
        }

        auto cbFunc = extCallbackMap_[cid];
        if (cbFunc != nullptr) {
            cbFunc->OnCallback();
        }
    }
    PRINT_HILOGW("DestroyExtension out.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
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
    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return E_PRINT_INVALID_USERID;
    }
    int32_t ret = userData->QueryAllPrintJob(printJobs);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("QueryAllPrintJob failed.");
        return ret;
    }
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryAddedPrinter(std::vector<std::string> &printerList)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("QueryAddedPrinter started.");
    std::vector<std::string> printerNameList;
    printSystemData_.GetAddedPrinterListFromSystemData(printerNameList);
    if (printerNameList.size() <= 0) {
        PRINT_HILOGW("no added printerId");
        return E_PRINT_NONE;
    }
    for (uint32_t i = 0; i < printerNameList.size(); i++) {
        PRINT_HILOGD("QueryAddedPrinter in printerName %{public}s", printerNameList[i].c_str());
        std::string printerId = printSystemData_.QueryPrinterIdByStandardizeName(printerNameList[i]);
        PRINT_HILOGD("QueryAddedPrinter in printerId %{public}s", printerId.c_str());
        if (printerId.empty()) {
            continue;
        }
        printerList.push_back(printerId);
    }
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryPrinterInfoByPrinterId(const std::string &printerId, PrinterInfo &info)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("QueryPrinterInfoByPrinterId started %{public}s", printerId.c_str());
    info.SetPrinterId(printerId);
    OHOS::Print::CupsPrinterInfo cupsPrinter;
    if (printSystemData_.QueryCupsPrinterInfoByPrinterId(printerId, cupsPrinter)) {
        info.SetPrinterName(PrintUtil::RemoveUnderlineFromPrinterName(cupsPrinter.name));
        nlohmann::json option;
        option["printerName"] = cupsPrinter.name;
        option["printerUri"] = cupsPrinter.uri; // Deprecated, to be removed in a future version.
        option["make"] = cupsPrinter.maker;     // Deprecated, to be removed in a future version.
        option["alias"] = cupsPrinter.alias;
        if (!cupsPrinter.uri.empty()) {
            info.SetUri(cupsPrinter.uri);
        }
        if (!cupsPrinter.maker.empty()) {
            info.SetPrinterMake(cupsPrinter.maker);
        }
        info.SetOption(option.dump());
        info.SetCapability(cupsPrinter.printerCapability);
        info.SetPrinterStatus(cupsPrinter.printerStatus);
        PRINT_HILOGI("QueryPrinterInfoByPrinterId printerStatus: %{public}d", info.GetPrinterStatus());
    } else {
        std::string extensionId = PrintUtils::GetExtensionId(printerId);
        if (!vendorManager.ExtractVendorName(extensionId).empty()) {
            return QueryVendorPrinterInfo(printerId, info);
        }
#ifdef CUPS_ENABLE
        int32_t ret = DelayedSingleton<PrintCupsClient>::GetInstance()->QueryPrinterInfoByPrinterId(printerId, info);
        if (ret != 0) {
            PRINT_HILOGE("cups QueryPrinterInfoByPrinterId fail, ret = %{public}d", ret);
            return E_PRINT_INVALID_PRINTER;
        }
#endif  // CUPS_ENABLE
    }
    if (CheckIsDefaultPrinter(printerId)) {
        PRINT_HILOGI("is default printer");
        info.SetIsDefaultPrinter(true);
    }
    if (CheckIsLastUsedPrinter(printerId)) {
        PRINT_HILOGI("is last used printer");
        info.SetIsLastUsedPrinter(true);
    }
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryPrinterProperties(const std::string &printerId,
    const std::vector<std::string> &keyList, std::vector<std::string> &valueList)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    PRINT_HILOGD("printerId %{public}s", printerId.c_str());
    PrinterInfo printerInfo;
    uint32_t ret = QueryPrinterInfoByPrinterId(printerId, printerInfo);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGW("no printerInfo");
        return E_PRINT_INVALID_PRINTER;
    }
    PRINT_HILOGD("printerInfo %{public}s", printerInfo.GetPrinterName().c_str());
    for (auto &key : keyList) {
        PRINT_HILOGD("QueryPrinterProperties key %{public}s", key.c_str());
        if (key == "printerPreference") {
            std::string printerPreference;
            if (GetPrinterPreference(printerId, printerPreference) == E_PRINT_NONE &&
                json::accept(printerPreference)) {
                nlohmann::json preferenceJson = json::parse(printerPreference);
                valueList.emplace_back(preferenceJson.at("setting").dump());
                PRINT_HILOGD("getPrinterPreference success");
            }
        }
    }
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

    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return E_PRINT_INVALID_USERID;
    }
    int32_t ret = userData->QueryPrintJobById(printJobId, printJob);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("QueryPrintJobById failed.");
        return ret;
    }
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::AddPrinterToCups(const std::string &printerUri, const std::string &printerName,
    const std::string &printerMake)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("AddPrinterToCups started.");
#ifdef CUPS_ENABLE
    auto ret = DelayedSingleton<PrintCupsClient>::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGW("AddPrinterToCups error = %{public}d.", ret);
        return ret;
    }
#endif // CUPS_ENABLE
    PRINT_HILOGD("AddPrinterToCups End.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryPrinterCapabilityByUri(const std::string &printerUri, const std::string &printerId,
    PrinterCapability &printerCaps)
{
    {
        std::lock_guard <std::recursive_mutex> lock(apiMutex_);
        ManualStart();
        if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
            PRINT_HILOGE("no permission to access print service");
            return E_PRINT_NO_PERMISSION;
        }
    }
    PRINT_HILOGD("QueryPrinterCapabilityByUri started.");
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    std::string standardizeId = printerId;
    if (standardizeId.find(extensionId) == std::string::npos && vendorManager.ExtractVendorName(printerId).empty()) {
        standardizeId = PrintUtils::GetGlobalId(extensionId, printerId);
    }
    PRINT_HILOGI("extensionId = %{public}s, printerId : %{public}s", extensionId.c_str(), standardizeId.c_str());
#ifdef CUPS_ENABLE
    if (printerUri.length() > SERIAL_LENGTH && printerUri.substr(INDEX_ZERO, INDEX_THREE) == USB_PRINTER) {
        auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(standardizeId);
        if (printerInfo == nullptr) {
            PRINT_HILOGE("can not find the printer");
            return E_PRINT_INVALID_PRINTER;
        }
        if (printerInfo->HasOption() && json::accept(printerInfo->GetOption())) {
            PRINT_HILOGD("QueryPrinterCapabilityByUri ops : %{public}s.", printerInfo->GetOption().c_str());
            nlohmann::json opsJson = json::parse(printerInfo->GetOption());
            if (!opsJson.contains("printerMake") || !opsJson["printerMake"].is_string()) {
                PRINT_HILOGW("can not find printerMake");
                return E_PRINT_INVALID_PRINTER;
            }
            std::string make = opsJson["printerMake"];
            auto ret = DelayedSingleton<PrintCupsClient>::GetInstance()->
                AddPrinterToCups(printerUri, printerInfo->GetPrinterName(), make);
            if (ret != E_PRINT_NONE) {
                PRINT_HILOGE("AddPrinterToCups error = %{public}d.", ret);
                return ret;
            }
            DelayedSingleton<PrintCupsClient>::GetInstance()->
                QueryPrinterCapabilityFromPPD(printerInfo->GetPrinterName(), printerCaps);
        }
    } else {
        DelayedSingleton<PrintCupsClient>::GetInstance()->
            QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
    }
#endif // CUPS_ENABLE
    PRINT_HILOGD("QueryPrinterCapabilityByUri End.");
    WritePrinterPreference(standardizeId, printerCaps);
    return E_PRINT_NONE;
}

void PrintServiceAbility::BuildPrinterPreferenceByDefault(nlohmann::json& capOpt, PreferenceSetting &printerDefaultAttr)
{
    if (capOpt.contains("defaultPageSizeId") && capOpt["defaultPageSizeId"].is_string()) {
        printerDefaultAttr.pagesizeId = capOpt["defaultPageSizeId"].get<std::string>();
    }
    if (capOpt.contains("orientation-requested-default") && capOpt["orientation-requested-default"].is_string()) {
        printerDefaultAttr.orientation = capOpt["orientation-requested-default"].get<std::string>();
    }
    if (capOpt.contains("sides-default") && capOpt["sides-default"].is_string()) {
        printerDefaultAttr.duplex = capOpt["sides-default"].get<std::string>();
    }
    if (capOpt.contains("print-quality-default") && capOpt["print-quality-default"].is_string()) {
        printerDefaultAttr.quality = capOpt["print-quality-default"].get<std::string>();
    }
}

void PrintServiceAbility::BuildPrinterPreferenceByOption(std::string& key, std::string& supportedOpts,
    std::vector<std::string>& optAttrs)
{
    if (supportedOpts.length() <= 0) {
        return;
    }
    PRINT_HILOGI("BuildPrinterPreferenceByOption %{public}s", supportedOpts.c_str());
    if (json::accept(supportedOpts) && supportedOpts.find("{") != std::string::npos) {
        nlohmann::json ArrJson = json::parse(supportedOpts);
        BuildPrinterAttrComponentByJson(key, ArrJson, optAttrs);
    } else {
        PrintUtil::Str2VecStr(supportedOpts, optAttrs);
    }
}

int32_t PrintServiceAbility::BuildPrinterPreference(PrinterCapability &cap, PrinterPreference &printPreference)
{
    std::string capOption = cap.GetOption();
    PRINT_HILOGI("printer capOption %{public}s", capOption.c_str());
    if (!json::accept(capOption)) {
        PRINT_HILOGW("capOption can not parse to json object");
        return E_PRINT_INVALID_PARAMETER;
    }
    nlohmann::json capJson = json::parse(capOption);
    if (!capJson.contains("cupsOptions")) {
        PRINT_HILOGW("The capJson does not have a cupsOptions attribute.");
        return E_PRINT_INVALID_PARAMETER;
    }
    nlohmann::json capOpt = capJson["cupsOptions"];

    std::string key = "id";
    if (capOpt.contains("supportedPageSizeArray") && capOpt["supportedPageSizeArray"].is_string()) {
        std::string supportedPageSizeOpts = capOpt["supportedPageSizeArray"].get<std::string>();
        BuildPrinterPreferenceByOption(key, supportedPageSizeOpts, printPreference.pagesizeId);
    }

    key = "orientation";
    if (capOpt.contains("orientation-requested-supported") && capOpt["orientation-requested-supported"].is_string()) {
        std::string supportedOriOpts = capOpt["orientation-requested-supported"].get<std::string>();
        BuildPrinterPreferenceByOption(key, supportedOriOpts, printPreference.orientation);
    }

    key = "duplex";
    if (capOpt.contains("sides-supported") && capOpt["sides-supported"].is_string()) {
        std::string supportedDeplexOpts = capOpt["sides-supported"].get<std::string>();
        BuildPrinterPreferenceByOption(key, supportedDeplexOpts, printPreference.duplex);
    }

    key = "quality";
    if (capOpt.contains("print-quality-supported") && capOpt["print-quality-supported"].is_string()) {
        std::string supportedQualityOpts = capOpt["print-quality-supported"].get<std::string>();
        BuildPrinterPreferenceByOption(key, supportedQualityOpts, printPreference.quality);
    }

    BuildPrinterPreferenceByDefault(capOpt, printPreference.defaultSetting);
    return E_PRINT_NONE;
}

void PrintServiceAbility::BuildPrinterAttrComponentByJson(std::string &key, nlohmann::json &jsonArrObject,
    std::vector<std::string> &printerAttrs)
{
    if (!jsonArrObject.is_array()) {
        PRINT_HILOGW("can not PrinterAttrsComponent by jsonArrObject");
        return;
    }
    for (auto &element : jsonArrObject.items()) {
        nlohmann::json object = element.value();
        if (object.contains(key)) {
            if (object[key].is_string()) {
                printerAttrs.push_back(object[key].get<std::string>());
            } else if (object[key].is_number()) {
                int value = object[key];
                printerAttrs.push_back(std::to_string(value));
            }
        }
    }
}

int32_t PrintServiceAbility::GetPrinterPreference(const std::string &printerId, std::string &printerPreference)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    int printerPreferenceNum = static_cast<int>(printerIdAndPreferenceMap_.size());
    if (printerPreferenceNum <= 0) {
        InitPreferenceMap();
    }
    if (printerIdAndPreferenceMap_.size() > 0 && ReadPreferenceFromFile(printerId, printerPreference)) {
        PRINT_HILOGI("ReadPreferenceFromFile %{public}s", printerPreference.c_str());
        return E_PRINT_NONE;
    }
    return E_PRINT_INVALID_PRINTER;
}

int32_t PrintServiceAbility::SetPrinterPreference(const std::string &printerId, const std::string &printerSetting)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    int printerPreferenceNum = static_cast<int>(printerIdAndPreferenceMap_.size());
    if (printerPreferenceNum <= 0) {
        InitPreferenceMap();
    }
    std::string printPreference;
    if (printerIdAndPreferenceMap_.size() > 0 && ReadPreferenceFromFile(printerId, printPreference)) {
        if (!nlohmann::json::accept(printPreference) || !nlohmann::json::accept(printerSetting)) {
            PRINT_HILOGW("json accept fail");
            return E_PRINT_INVALID_PRINTER;
        }
        nlohmann::json objectJson = nlohmann::json::parse(printPreference);
        PrinterPreference oldPrintPreference = PrinterPreference::BuildPrinterPreferenceFromJson(objectJson);

        PRINT_HILOGD("printerSetting %{public}s", printerSetting.c_str());
        nlohmann::json settingJson = nlohmann::json::parse(printerSetting);
        PreferenceSetting newSetting = PreferenceSetting::BuildPreferenceSettingFromJson(settingJson);
        oldPrintPreference.setting = newSetting;

        nlohmann::json savePrinterPreference = oldPrintPreference.BuildPrinterPreferenceJson();
        std::string newPrintPreference = savePrinterPreference.dump();
        PRINT_HILOGI("WriteNewPreferenceToFile %{public}s", newPrintPreference.c_str());
        printerIdAndPreferenceMap_[printerId] = newPrintPreference;
        PrinterInfo info;
        printSystemData_.QueryPrinterInfoById(printerId, info);
        SendPrinterChangeEvent(PRINTER_EVENT_PREFERENCE_CHANGED, info);
        if (WritePreferenceToFile() == false) {
            PRINT_HILOGE("WritePreferenceToFile fail");
            return E_PRINT_SERVER_FAILURE;
        };
        return E_PRINT_NONE;
    }
    return E_PRINT_INVALID_PRINTER;
}

bool PrintServiceAbility::ReadPreferenceFromFile(const std::string &printerId, std::string& printPreference)
{
    auto iter = printerIdAndPreferenceMap_.find(printerId);
    if (iter != printerIdAndPreferenceMap_.end()) {
        printPreference = iter->second;
        PRINT_HILOGE("open printer preference find %{public}s", printPreference.c_str());
        return true;
    }
    return false;
}

void PrintServiceAbility::InitPreferenceMap()
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    std::string printerPreferenceFilePath = PRINTER_SERVICE_FILE_PATH + "/" + PRINTER_PREFERENCE_FILE;
    std::ifstream ifs(printerPreferenceFilePath.c_str(), std::ios::in | std::ios::binary);
    if (!ifs.is_open()) {
        PRINT_HILOGW("open printer preference file fail");
        return;
    }
    std::string fileData((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();
    if (!nlohmann::json::accept(fileData)) {
        PRINT_HILOGW("json accept fail");
        return;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(fileData);
    if (!jsonObject.contains("printer_list") || !jsonObject["printer_list"].is_array()) {
        PRINT_HILOGW("can not find printer_list");
        return;
    }
    for (auto &element : jsonObject["printer_list"].items()) {
        nlohmann::json object = element.value();
        for (auto it = object.begin(); it != object.end(); it++) {
            std::string printerId = it.key();
            nlohmann::json printPreferenceJson = object[printerId];
            printerIdAndPreferenceMap_[printerId] = printPreferenceJson.dump();
        }
    }
}

bool PrintServiceAbility::WritePreferenceToFile()
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    char realPidFile[PATH_MAX] = {};
    std::string printerPreferenceFilePath = PRINTER_SERVICE_FILE_PATH + "/" + PRINTER_PREFERENCE_FILE;
    if (realpath(PRINTER_SERVICE_FILE_PATH.c_str(), realPidFile) == nullptr) {
        PRINT_HILOGE("The realPidFile is null, errno:%{public}s", std::to_string(errno).c_str());
        return false;
    }
    int32_t fd = open(printerPreferenceFilePath.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0640);
    PRINT_HILOGD("SavePrinterPreferenceMap fd: %{public}d", fd);
    if (fd < 0) {
        PRINT_HILOGW("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
        close(fd);
        return false;
    }
    nlohmann::json printerMapJson = nlohmann::json::array();

    for (auto& printPreference : printerIdAndPreferenceMap_) {
        if (json::accept(printPreference.second)) {
            nlohmann::json printPreferenceJson = nlohmann::json::parse(printPreference.second);
            nlohmann::json objectJson;
            objectJson[printPreference.first] = printPreferenceJson;
            printerMapJson.push_back(objectJson);
        }
    }

    nlohmann::json jsonObject;
    jsonObject["printer_list"] = printerMapJson;
    std::string jsonString = jsonObject.dump();
    size_t jsonLength = jsonString.length();
    auto writeLength = write(fd, jsonString.c_str(), jsonLength);
    close(fd);
    return (size_t)writeLength == jsonLength;
}

bool PrintServiceAbility::WritePrinterPreference(const std::string &printerId, PrinterCapability &printerCaps)
{
    if (printerCaps.HasOption()) {
        if (printerIdAndPreferenceMap_.count(printerId)) {
            return false;
        }
        PrinterPreference printPreference;
        int32_t ret = BuildPrinterPreference(printerCaps, printPreference);
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("printerCaps can not success to printPreference");
            return false;
        }
        nlohmann::json jsonObject = nlohmann::json::object();
        jsonObject = printPreference.BuildPrinterPreferenceJson();
        std::string savePrinterPreference = jsonObject.dump();
        printerIdAndPreferenceMap_.insert(std::make_pair(printerId, savePrinterPreference));
        return WritePreferenceToFile();
    }
    return false;
}

bool PrintServiceAbility::WriteEprinterPreference(const std::string &printerId, PrinterCapability &printerCaps)
{
    if (printerIdAndPreferenceMap_.count(printerId)) {
        return false;
    }
    json printerPreference;
    std::vector<PrintPageSize> supportedPageSize;
    printerCaps.GetSupportedPageSize(supportedPageSize);
    std::vector<std::string> supportedPageSizeStr;
    for (auto &item : supportedPageSize) {
        supportedPageSizeStr.push_back(item.GetId());
    }
    std::vector<uint32_t> supportedDuplexMode;
    printerCaps.GetSupportedDuplexMode(supportedDuplexMode);
    std::vector<std::string> supportedDuplexModeStr;
    for (auto &item : supportedDuplexMode) {
        supportedDuplexModeStr.push_back(std::to_string(item));
    }
    std::vector<uint32_t> supportedOrientation;
    printerCaps.GetSupportedOrientation(supportedOrientation);
    std::vector<std::string> supportedOrientationStr;
    for (auto &item : supportedOrientation) {
        supportedOrientationStr.push_back(std::to_string(item));
    }
    std::vector<uint32_t> supportedQuality;
    printerCaps.GetSupportedQuality(supportedQuality);
    std::vector<std::string> supportedQualityStr;
    for (auto &item : supportedQuality) {
        supportedQualityStr.push_back(std::to_string(item));
    }

    printerPreference["pagesizeId"] = supportedPageSizeStr;
    printerPreference["orientation"] = supportedOrientationStr;
    printerPreference["duplex"] = supportedDuplexModeStr;
    printerPreference["quality"] = supportedQualityStr;
    PreferenceSetting preferenceSetting;
    printerPreference["defaultSetting"] = preferenceSetting.BuildPreferenceSettingJson();
    printerPreference["setting"] = preferenceSetting.BuildPreferenceSettingJson();
    std::string savePrinterPreference = printerPreference.dump();
    PRINT_HILOGD("savePrinterPreference = %{public}s", savePrinterPreference.c_str());
    printerIdAndPreferenceMap_.insert(std::make_pair(printerId, savePrinterPreference));
    return WritePreferenceToFile();
}

bool PrintServiceAbility::UpdatePrintJobOptionByPrinterId(PrintJob &printJob)
{
    CupsPrinterInfo printerInfo;
    if (!printSystemData_.QueryCupsPrinterInfoByPrinterId(printJob.GetPrinterId(), printerInfo)) {
        PRINT_HILOGW("cannot find printer info by printerId");
        return false;
    }
    std::string oldOption = printJob.GetOption();
    PRINT_HILOGD("Print job option: %{public}s", oldOption.c_str());
    if (!json::accept(oldOption)) {
        PRINT_HILOGW("old option not accepted");
        return false;
    }
    nlohmann::json infoJson = json::parse(oldOption);
    infoJson["printerName"] = printerInfo.name;
    infoJson["printerUri"] = printerInfo.uri;
    infoJson["alias"] = printerInfo.alias;
    std::string updatedOption = infoJson.dump();
    PRINT_HILOGD("Updated print job option: %{public}s", updatedOption.c_str());
    printJob.SetOption(updatedOption);
    return true;
}

std::shared_ptr<PrintJob> PrintServiceAbility::AddNativePrintJob(const std::string &jobId, PrintJob &printJob)
{
    PRINT_HILOGD("jobId %{public}s", jobId.c_str());
    printJob.SetJobId(jobId);
    printJob.SetJobState(PRINT_JOB_PREPARED);
    auto nativePrintJob = std::make_shared<PrintJob>();
    if (nativePrintJob == nullptr) {
        PRINT_HILOGW("nativePrintJob is null");
        return nullptr;
    }
    nativePrintJob->UpdateParams(printJob);
    nativePrintJob->Dump();
    AddToPrintJobList(jobId, nativePrintJob);
    return nativePrintJob;
}

int32_t PrintServiceAbility::StartNativePrintJob(PrintJob &printJob)
{
    startPrintTime_ = std::chrono::high_resolution_clock::now();
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (!UpdatePrintJobOptionByPrinterId(printJob)) {
        PRINT_HILOGW("cannot update printer name/uri");
        return E_PRINT_INVALID_PRINTER;
    }
    std::string jobId = PrintUtils::GetPrintJobId();
    auto nativePrintJob = AddNativePrintJob(jobId, printJob);
    if (nativePrintJob == nullptr) {
        return E_PRINT_SERVER_FAILURE;
    }
    UpdateQueuedJobList(jobId, nativePrintJob);
    auto printerId = nativePrintJob->GetPrinterId();
    printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    return StartPrintJobInternal(nativePrintJob);
}

int32_t PrintServiceAbility::StartPrintJob(PrintJob &jobInfo)
{
    startPrintTime_ = std::chrono::high_resolution_clock::now();
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (!CheckPrintJob(jobInfo)) {
        PRINT_HILOGW("check printJob unavailable");
        return E_PRINT_INVALID_PRINTJOB;
    }
    auto jobId = jobInfo.GetJobId();
    auto printerId = jobInfo.GetPrinterId();
    auto printJob = std::make_shared<PrintJob>();
    printJob->UpdateParams(jobInfo);
    PRINT_HILOGI("set job state to PRINT_JOB_QUEUED");
    printJob->SetJobState(PRINT_JOB_QUEUED);
    UpdateQueuedJobList(jobId, printJob);
    printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    return StartPrintJobInternal(printJob);
}

bool PrintServiceAbility::CheckPrintJob(PrintJob &jobInfo)
{
    if (!UpdatePrintJobOptionByPrinterId(jobInfo)) {
        PRINT_HILOGW("cannot update printer name/uri");
        return false;
    }
    auto jobIt = printJobList_.find(jobInfo.GetJobId());
    if (jobIt == printJobList_.end()) {
        PRINT_HILOGE("invalid job id");
        return false;
    }
    printJobList_.erase(jobIt);
    return true;
}

void PrintServiceAbility::UpdateQueuedJobList(const std::string &jobId, const std::shared_ptr<PrintJob> &printJob)
{
    PRINT_HILOGI("enter UpdateQueuedJobList, jobId: %{public}s.", jobId.c_str());
#ifdef IPPOVERUSB_ENABLE
    int32_t port = 0;
    DelayedSingleton<PrintIppOverUsbManager>::GetInstance()->ConnectPrinter(printJob->GetPrinterId(), port);
#endif // IPPOVERUSB_ENABLE
    std::string jobOrderId = GetPrintJobOrderId();
    if (jobOrderId == "0") {
        jobOrderList_.clear();
    }
    PRINT_HILOGI("UpdateQueuedJobList jobOrderId: %{public}s.", jobOrderId.c_str());
    if (queuedJobList_.find(jobId) != queuedJobList_.end()) {
        queuedJobList_[jobId] = printJob;
        jobOrderList_[jobOrderId] = jobId;
    } else if (static_cast<uint32_t>(queuedJobList_.size()) < MAX_JOBQUEUE_NUM) {
        queuedJobList_.insert(std::make_pair(jobId, printJob));
        jobOrderList_.insert(std::make_pair(jobOrderId, jobId));
    } else {
        PRINT_HILOGE("UpdateQueuedJobList out of MAX_JOBQUEUE_NUM or jobId not found");
    }

    int32_t userId = GetCurrentUserId();
    if (userId == E_PRINT_INVALID_USERID) {
        PRINT_HILOGE("Invalid user id.");
        return;
    }
    auto iter = printUserMap_.find(userId);
    if (iter == printUserMap_.end() || iter->second == nullptr) {
        PRINT_HILOGE("Invalid user id");
        return;
    }
    iter->second->UpdateQueuedJobList(jobId, printJob, jobOrderId);

    std::string printerId = printJob->GetPrinterId();
    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(printerId);
    if (printerInfo != nullptr) {
        printerInfo->SetPrinterStatus(PRINTER_STATUS_BUSY);
        printerInfo->SetPrinterName(PrintUtil::RemoveUnderlineFromPrinterName(printerInfo->GetPrinterName()));
        printSystemData_.UpdatePrinterStatus(printerId, PRINTER_STATUS_BUSY);
        SendPrinterEventChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo, true);
        SendPrinterChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
        SendPrinterEventChangeEvent(PRINTER_EVENT_LAST_USED_PRINTER_CHANGED, *printerInfo);
    }
    SetLastUsedPrinter(printerId);
}

void PrintServiceAbility::SetLastUsedPrinter(const std::string &printerId)
{
    PRINT_HILOGD("SetLastUsedPrinter started.");
    if (!printSystemData_.IsPrinterAdded(printerId)) {
        PRINT_HILOGE("Printer is not added to cups.");
        return;
    }

    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return;
    }
    int32_t ret = userData->SetLastUsedPrinter(printerId);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("SetLastUsedPrinter failed.");
        return;
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

    auto userData = GetUserDataByJobId(jobId);
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return E_PRINT_INVALID_USERID;
    }
    auto jobIt = userData->queuedJobList_.find(jobId);
    if (jobIt == userData->queuedJobList_.end()) {
        PRINT_HILOGE("invalid job id");
        return E_PRINT_INVALID_PRINTJOB;
    }

    if (jobIt->second->GetJobState() >= PRINT_JOB_QUEUED) {
        std::string extensionId = PrintUtils::GetExtensionId(jobIt->second->GetPrinterId());
        std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CANCEL_PRINT);
        if (cid.find(PRINT_EXTENSION_BUNDLE_NAME) == string::npos) {
#ifdef CUPS_ENABLE
            DelayedSingleton<PrintCupsClient>::GetInstance()->CancelCupsJob(jobIt->second->GetJobId());
#endif // CUPS_ENABLE
            return E_PRINT_NONE;
        }
        if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
            PRINT_HILOGW("CancelPrintJob Not Register Yet!!!");
            UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED, PRINT_JOB_COMPLETED_CANCELLED);
            return E_PRINT_SERVER_FAILURE;
        }
        auto cbFunc = extCallbackMap_[cid];
        auto tmpPrintJob = userData->queuedJobList_[jobId];
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
        SetPrintJobCanceled(*jobIt->second);
    }
    return E_PRINT_NONE;
}

void PrintServiceAbility::SetPrintJobCanceled(PrintJob &jobinfo)
{
    auto printJob = std::make_shared<PrintJob>(jobinfo);
    if (printJob == nullptr) {
        PRINT_HILOGE("create printJob failed.");
        return;
    }
    std::string jobId = printJob->GetJobId();
    auto userData = GetUserDataByJobId(jobId);
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return;
    }
    printJob->SetJobState(PRINT_JOB_COMPLETED);
    printJob->SetSubState(PRINT_JOB_COMPLETED_CANCELLED);
    userData->printJobList_.insert(std::make_pair(jobId, printJob));
    printJobList_.insert(std::make_pair(jobId, printJob));
    UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED, PRINT_JOB_COMPLETED_CANCELLED);
}

void PrintServiceAbility::CancelUserPrintJobs(const int32_t userId)
{
    auto removedUser = printUserMap_.find(userId);
    if (removedUser == printUserMap_.end()) {
        PRINT_HILOGE("User dose not exist.");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (removedUser->second == nullptr) {
        PRINT_HILOGE("PrintUserData is nullptr.");
        return;
    }
    for (auto jobIt: removedUser->second->queuedJobList_) {
        PRINT_HILOGI("CancelUserPrintJobs user jobId: %{public}s", jobIt.first.c_str());
        int32_t ret = CancelPrintJob(jobIt.first);
        PRINT_HILOGI("CancelUserPrintJobs CancelPrintJob ret: %{public}d", ret);
        userJobMap_.erase(jobIt.first);
    }
    printUserMap_.erase(userId);
    PRINT_HILOGI("remove user-%{publis}d success.", userId);
}

void PrintServiceAbility::NotifyCurrentUserChanged(const int32_t userId)
{
    PRINT_HILOGD("NotifyAppCurrentUserChanged begin");
    PRINT_HILOGI("currentUserId_ is: %{public}d", userId);
    currentUserId_ = userId;
    auto userData = GetUserDataByUserId(userId);
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return;
    }
    auto status = DetermineUserJobStatus(userData->queuedJobList_);

    switch (status) {
        case PRINT_JOB_BLOCKED:
            NotifyAppJobQueueChanged(QUEUE_JOB_LIST_BLOCKED);
            break;
        case PRINT_JOB_COMPLETED:
            NotifyAppJobQueueChanged(QUEUE_JOB_LIST_HIDE);
            break;
        case PRINT_JOB_RUNNING:
            NotifyAppJobQueueChanged(QUEUE_JOB_LIST_PRINTING);
            break;
        default:
            break;
    }
    PRINT_HILOGD("NotifyAppCurrentUserChanged end");
}

void PrintServiceAbility::SendQueuePrintJob(const std::string &printerId)
{
    if (printerJobMap_[printerId].empty()) {
        return;
    }

    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return;
    }
    auto jobId = printerJobMap_[printerId].begin()->first;
    auto jobIt = userData->queuedJobList_.find(jobId);
    if (jobIt == userData->queuedJobList_.end()) {
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
    if (cid.find(PRINT_EXTENSION_BUNDLE_NAME) != string::npos) {
    PRINT_HILOGD("not eprint extension, no need SendQueuePrintJob");
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

bool PrintServiceAbility::CheckPrinterUriDifferent(const std::shared_ptr<PrinterInfo> &info)
{
    CupsPrinterInfo cupsPrinter;
    if (printSystemData_.QueryCupsPrinterInfoByPrinterId(info->GetPrinterId(), cupsPrinter)) {
        std::string printerUri = info->GetUri();
        if (!printerUri.empty() && printerUri != cupsPrinter.uri) {
            return true;
        }
    }
    return false;
}

int32_t PrintServiceAbility::AddPrinters(const std::vector<PrinterInfo> &printerInfos)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    PRINT_HILOGD("AddPrinters started. Total size is %{public}zd", printSystemData_.GetDiscoveredPrinterCount());

    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());
    for (auto &info : printerInfos) {
        AddSinglePrinterInfo(info, extensionId);
    }
    PRINT_HILOGD("AddPrinters end. Total size is %{public}zd", printSystemData_.GetDiscoveredPrinterCount());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::RemovePrinters(const std::vector<std::string> &printerIds)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    PRINT_HILOGD("RemovePrinters started. Total size is %{public}zd", printSystemData_.GetDiscoveredPrinterCount());
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());

    bool anyPrinterRemoved = false;
    for (const auto& printerId : printerIds) {
        std::string globalPrinterId = PrintUtils::GetGlobalId(extensionId, printerId);
        PRINT_HILOGD("RemovePrinters printerId = %{public}s", globalPrinterId.c_str());

        if (RemoveSinglePrinterInfo(globalPrinterId)) {
            anyPrinterRemoved = true;
        }
    }
    if (!anyPrinterRemoved) {
        PRINT_HILOGE("Invalid printer ids");
        return E_PRINT_INVALID_PARAMETER;
    }
    PRINT_HILOGD("RemovePrinters end. Total size is %{public}zd", printSystemData_.GetDiscoveredPrinterCount());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::UpdatePrinters(const std::vector<PrinterInfo> &printerInfos)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGD("UpdatePrinters started. Total size is %{public}zd", printSystemData_.GetDiscoveredPrinterCount());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());

    bool isAnyPrinterChanged = false;
    for (const auto &info : printerInfos) {
        bool isPrinterChanged = UpdateSinglePrinterInfo(info, extensionId);
        isAnyPrinterChanged |= isPrinterChanged;
    }
    if (isAnyPrinterChanged) {
        printSystemData_.SaveCupsPrinterMap();
    }
    PRINT_HILOGD("UpdatePrinters end. Total size is %{private}zd", printSystemData_.GetDiscoveredPrinterCount());
    return E_PRINT_NONE;
}

bool PrintServiceAbility::UpdatePrinterSystemData(const PrinterInfo &info)
{
    std::string option = info.GetOption();
    if (json::accept(option)) {
        json optionJson = json::parse(option);
        if (optionJson.contains("alias") && optionJson["alias"].is_string()) {
            if (printSystemData_.UpdatePrinterAlias(info.GetPrinterId(), optionJson["alias"])) {
                SendPrinterEventChangeEvent(PRINTER_EVENT_INFO_CHANGED, info);
                return true;
            }
        }
    }
    return false;
}

bool PrintServiceAbility::UpdatePrinterCapability(const std::string &printerId, const PrinterInfo &info)
{
    PRINT_HILOGI("UpdatePrinterCapability Enter");
    if (!PrintUtil::startsWith(printerId, SPOOLER_BUNDLE_NAME)) {
        PRINT_HILOGI("ePrinter Enter");
        PrinterCapability printerCaps;
        info.GetCapability(printerCaps);
        WriteEprinterPreference(printerId, printerCaps);
    }

    CupsPrinterInfo cupsPrinterInfo;
    auto output = info;
    cupsPrinterInfo.name = info.GetPrinterName();
    cupsPrinterInfo.uri = info.GetUri();
    cupsPrinterInfo.maker = info.GetPrinterMake();
    cupsPrinterInfo.printerStatus = PRINTER_STATUS_IDLE;
    info.GetCapability(cupsPrinterInfo.printerCapability);
    printSystemData_.InsertCupsPrinter(printerId, cupsPrinterInfo, true);
    output.SetPrinterStatus(PRINTER_STATUS_IDLE);
    output.SetPrinterId(printerId);
    SendPrinterEventChangeEvent(PRINTER_EVENT_ADDED, output, true);
    SendPrinterChangeEvent(PRINTER_EVENT_ADDED, output);
    SendPrinterEventChangeEvent(PRINTER_EVENT_LAST_USED_PRINTER_CHANGED, output);
    SetLastUsedPrinter(printerId);
    return true;
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

    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(printerExtId);
    if (printerInfo == nullptr) {
        PRINT_HILOGD("Invalid printer id");
        return E_PRINT_INVALID_PRINTER;
    }

    printerInfo->SetPrinterState(state);
    SendPrinterDiscoverEvent(PRINTER_CONNECTED, *printerInfo);
    SendPrinterEvent(*printerInfo);
    PRINT_HILOGD("UpdatePrinterState end.");
    return E_PRINT_NONE;
}

bool PrintServiceAbility::checkJobState(uint32_t state, uint32_t subState)
{
    if (state > PRINT_JOB_UNKNOWN) {
        return false;
    }
    if (state == PRINT_JOB_BLOCKED && subState < PRINT_JOB_BLOCKED_OFFLINE) {
        return false;
    }
    if (state == PRINT_JOB_COMPLETED && subState > PRINT_JOB_COMPLETED_FILE_CORRUPT) {
        return false;
    }

    return true;
}

int32_t PrintServiceAbility::UpdatePrintJobStateOnlyForSystemApp(
    const std::string &jobId, uint32_t state, uint32_t subState)
{
    ManualStart();
    if (state != PRINT_JOB_CREATE_FILE_COMPLETED && !CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    return UpdatePrintJobState(jobId, state, subState);
}

int32_t PrintServiceAbility::UpdatePrintJobState(const std::string &jobId, uint32_t state, uint32_t subState)
{
    ManualStart();
    if (state == PRINT_JOB_CREATE_FILE_COMPLETED) {
        return AdapterGetFileCallBack(jobId, state, subState);
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
    if (eventIt != registeredListeners_.end() && eventIt->second != nullptr) {
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
    auto userData = GetUserDataByJobId(jobId);
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return E_PRINT_INVALID_USERID;
    }
    auto jobIt = userData->queuedJobList_.find(jobId);
    bool jobInQueue = true;
    if (jobIt == userData->queuedJobList_.end()) {
        jobInQueue = false;
        jobIt = userData->printJobList_.find(jobId);
        if (jobIt == userData->printJobList_.end()) {
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
            userData->queuedJobList_.erase(jobId);
            queuedJobList_.erase(jobId);
        }
        if (printerJobMap_[printerId].empty()) {
            auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(printerId);
            if (printerInfo != nullptr) {
                printerInfo->SetPrinterStatus(PRINTER_STATUS_IDLE);
                printSystemData_.UpdatePrinterStatus(printerId, PRINTER_STATUS_IDLE);
                SendPrinterEventChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
                SendPrinterChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
            }
        }
        if (IsQueuedJobListEmpty(jobId)) {
            ReportCompletedPrint(printerId);
        }
        SendQueuePrintJob(printerId);
    }

    PRINT_HILOGD("CheckAndSendQueuePrintJob end.");
    return E_PRINT_NONE;
}

bool PrintServiceAbility::IsQueuedJobListEmpty(const std::string &jobId)
{
    auto userData = GetUserDataByJobId(jobId);
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return false;
    }
    if (!userData->queuedJobList_.empty()) {
        PRINT_HILOGD("This user still has print jobs in progress.");
        return false;
    }
    if (GetUserIdByJobId(jobId) != currentUserId_) {
        PRINT_HILOGE("The user corresponding to this task is different from the current user.");
        return false;
    }
    return true;
}

void PrintServiceAbility::ReportCompletedPrint(const std::string &printerId)
{
    NotifyAppJobQueueChanged(QUEUE_JOB_LIST_COMPLETED);
    PRINT_HILOGD("no print job exists, destroy extension");
    PRINT_HILOGI("printAppCount_: %{public}u", printAppCount_);
    if (queuedJobList_.size() == 0 && printAppCount_ == 0) {
        UnloadSystemAbility();
    }
    json msg;
    auto endPrintTime = std::chrono::high_resolution_clock::now();
    auto printTime = std::chrono::duration_cast<std::chrono::milliseconds>(endPrintTime - startPrintTime_);
    msg["PRINT_TIME"] = printTime.count();
    msg["INGRESS_PACKAGE"] = ingressPackage;
    msg["STATUS"] = 0;
    HisysEventUtil::reportPrintSuccess(msg.dump());
}

void PrintServiceAbility::ReportHisysEvent(
    const std::shared_ptr<PrintJob> &jobInfo, const std::string &printerId, uint32_t subState)
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

    std::vector<uint32_t> fdList;
    jobInfo->GetFdList(fdList);
    msg["FILE_NUM"] = fdList.size();
    msg["PAGE_NUM"] = fdList.size();
    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(printerId);
    if (printerInfo == nullptr) {
        msg["MODEL"] = "";
    } else {
        msg["MODEL"] = printerInfo->GetPrinterName();
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
    std::string ePrintID = "ePrintID";
    if (printerId.length() < ePrintID.length()) {
        return false;
    }
    return std::equal(ePrintID.rbegin(), ePrintID.rend(), printerId.rbegin());
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

    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return E_PRINT_INVALID_USERID;
    }
    auto jobId = jobInfo.GetJobId();
    auto printerId = jobInfo.GetPrinterId();
    auto extensionId = PrintUtils::GetExtensionId(printerId);

    auto jobIt = userData->printJobList_.find(jobId);
    if (jobIt == userData->printJobList_.end()) {
        PRINT_HILOGD("invalid job id");
        return E_PRINT_INVALID_PRINTJOB;
    }

    if (userData->printJobList_[jobId] == nullptr) {
        PRINT_HILOGE("printJob is nullptr.");
        return E_PRINT_INVALID_PRINTJOB;
    }
    if (userData->printJobList_[jobId]->GetJobState() < PRINT_JOB_QUEUED) {
        PRINT_HILOGD("invalid job state [%{public}d]", userData->printJobList_[jobId]->GetJobState());
        return E_PRINT_INVALID_PRINTJOB;
    }
    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(printerId);
    if (printerInfo == nullptr) {
        PRINT_HILOGD("invalid printer of the print job");
        return E_PRINT_INVALID_PRINTJOB;
    }

    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_REQUEST_PREVIEW);
    if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
        PRINT_HILOGW("RequestPreview Not Register Yet!!!");
        return E_PRINT_SERVER_FAILURE;
    }

    userData->printJobList_[jobId]->UpdateParams(jobInfo);
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
    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(printerId);
    if (printerInfo == nullptr) {
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

int32_t PrintServiceAbility::NotifyPrintServiceEvent(std::string &jobId, uint32_t event)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    if (event < APPLICATION_CREATED || event > APPLICATION_CLOSED_FOR_CANCELED) {
        PRINT_HILOGE("Invalid parameter");
        return E_PRINT_INVALID_PARAMETER;
    }

    switch (event) {
        case APPLICATION_CREATED:
            if (printJobList_.find(jobId) == printJobList_.end()) {
                PRINT_HILOGI("add printJob from phone, jobId: %{public}s", jobId.c_str());
                auto printJob = std::make_shared<PrintJob>();
                if (printJob == nullptr) {
                    PRINT_HILOGE("printJob is nullptr.");
                    return E_PRINT_SERVER_FAILURE;
                }
                printJob->SetJobId(jobId);
                printJob->SetJobState(PRINT_JOB_PREPARED);
                RegisterAdapterListener(jobId);
                AddToPrintJobList(jobId, printJob);
                SendPrintJobEvent(*printJob);
            }
            printAppCount_++;
            PRINT_HILOGI("printAppCount_: %{public}u", printAppCount_);
            break;
        case APPLICATION_CLOSED_FOR_STARTED:
            ReduceAppCount();
            break;
        case APPLICATION_CLOSED_FOR_CANCELED:
            ReduceAppCount();
            break;
        default:
            break;
    }
    return E_PRINT_NONE;
}

void PrintServiceAbility::UnloadSystemAbility()
{
    PRINT_HILOGI("delay unload task begin");
    auto unloadTask = [this]() {
        std::lock_guard<std::recursive_mutex> lock(apiMutex_);
        unloadCount_--;
        PRINT_HILOGI("do unload task, unloadCount_: %{public}u", unloadCount_);
        if (printAppCount_ != 0 || queuedJobList_.size() > 0 || unloadCount_ != 0) {
            PRINT_HILOGE("There are still print jobs being executed.");
            return;
        }
        NotifyAppJobQueueChanged(QUEUE_JOB_LIST_UNSUBSCRIBE);
        int32_t ret = DestroyExtension();
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("DestroyExtension failed.");
            return;
        }
#ifdef CUPS_ENABLE
        DelayedSingleton<PrintCupsClient>::GetInstance()->StopCupsdService();
#endif // CUPS_ENABLE
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            PRINT_HILOGE("get samgr failed");
            return;
        }
        ret = samgrProxy->UnloadSystemAbility(PRINT_SERVICE_ID);
        if (ret != ERR_OK) {
            PRINT_HILOGE("unload print system ability failed");
            return;
        }
        PRINT_HILOGI("unload print system ability successfully");
    };
    serviceHandler_->PostTask(unloadTask, UNLOAD_SA_INTERVAL);
    unloadCount_++;
    PRINT_HILOGI("unloadCount_: %{public}u", unloadCount_);
}

bool PrintServiceAbility::CheckPermission(const std::string &permissionName)
{
    if (helper_ == nullptr) {
        return false;
    }
    return helper_->CheckPermission(permissionName);
}

int32_t PrintServiceAbility::RegisterPrinterCallback(const std::string &type, const sptr<IPrintCallback> &listener)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    if (listener == nullptr) {
        PRINT_HILOGE("Invalid listener");
        return E_PRINT_INVALID_PARAMETER;
    }
    int64_t callerTokenId = static_cast<int64_t>(IPCSkeleton::GetCallingTokenID());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto iter = printUserDataMap_.find(callerTokenId);
    if (iter == printUserDataMap_.end() || iter->second == nullptr) {
        PRINT_HILOGE("Invalid token");
        return E_PRINT_INVALID_TOKEN;
    }
    iter->second->RegisterPrinterCallback(type, listener);
    PRINT_HILOGD("PrintServiceAbility::RegisterPrinterCallback end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::UnregisterPrinterCallback(const std::string &type)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    int64_t callerTokenId = static_cast<int64_t>(IPCSkeleton::GetCallingTokenID());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto iter = printUserDataMap_.find(callerTokenId);
    if (iter == printUserDataMap_.end() || iter->second == nullptr) {
        PRINT_HILOGE("Invalid token");
        return E_PRINT_INVALID_TOKEN;
    }
    iter->second->UnregisterPrinterCallback(type);
    PRINT_HILOGD("PrintServiceAbility::UnregisterPrinterCallback end.");
    if (type == PRINTER_CHANGE_EVENT_TYPE) {
        ReduceAppCount();
    }
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::RegisterExtCallback(const std::string &extensionCID,
    const sptr<IPrintExtensionCallback> &listener)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
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
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
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
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGD("PrintServiceAbility::LoadExtSuccess started. extensionId=%{public}s:", extensionId.c_str());
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
    ManualStart();
    std::string permission = PERMISSION_NAME_PRINT_JOB;
    std::string eventType = type;
    if (type == PRINT_CALLBACK_ADAPTER || type == PRINTER_CHANGE_EVENT_TYPE || taskId != "") {
        permission = PERMISSION_NAME_PRINT;
    }
    if (!CheckPermission(permission)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    if (listener == nullptr) {
        PRINT_HILOGE("Invalid listener");
        return E_PRINT_INVALID_PARAMETER;
    }

    if (type == PRINT_CALLBACK_ADAPTER) {
        eventType = type;
    }
    if (type == PRINTER_CHANGE_EVENT_TYPE || type == PRINTER_EVENT_TYPE) {
        int32_t userId = GetCurrentUserId();
        int32_t callerPid = IPCSkeleton::GetCallingPid();
        eventType = PrintUtils::GetEventTypeWithToken(userId, callerPid, type);
    }
    if (taskId != "") {
        eventType = PrintUtils::GetTaskEventId(taskId, type);
    }
    if (eventType == "") {
        PRINT_HILOGE("Invalid event type");
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
    HandlePrinterStateChangeRegister(eventType);
    HandlePrinterChangeRegister(eventType);
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
    if (type == PRINTER_CHANGE_EVENT_TYPE||type == PRINTER_EVENT_TYPE) {
        permission = PERMISSION_NAME_PRINT;
        int32_t userId = GetCurrentUserId();
        int32_t callerPid = IPCSkeleton::GetCallingPid();
        eventType = PrintUtils::GetEventTypeWithToken(userId, callerPid, type);
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
        if (PrintUtils::GetEventType(eventType) == PRINTER_CHANGE_EVENT_TYPE) {
            ReduceAppCount();
        }
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

void PrintServiceAbility::SendPrinterDiscoverEvent(int event, const PrinterInfo &info)
{
    PRINT_HILOGD("PrintServiceAbility::SendPrinterDiscoverEvent type %{private}s, %{public}d",
        info.GetPrinterId().c_str(), event);
    for (auto &item : printUserDataMap_) {
        if (item.second != nullptr) {
            item.second->SendPrinterEvent(PRINTER_DISCOVER_EVENT_TYPE, event, info);
        }
    }
}

void PrintServiceAbility::SendPrinterChangeEvent(int event, const PrinterInfo &info)
{
    PRINT_HILOGD("PrintServiceAbility::SendPrinterChangeEvent type %{private}s, %{public}d",
        info.GetPrinterId().c_str(), event);
    for (auto &item : printUserDataMap_) {
        if (item.second != nullptr) {
            item.second->SendPrinterEvent(PRINTER_CHANGE_EVENT_TYPE, event, info);
        }
    }
}

void PrintServiceAbility::SendPrinterEvent(const PrinterInfo &info)
{
    PRINT_HILOGD("PrintServiceAbility::SendPrinterEvent type %{private}s, %{public}d",
                 info.GetPrinterId().c_str(), info.GetPrinterState());
    for (auto eventIt: registeredListeners_) {
        if (PrintUtils::GetEventType(eventIt.first) == PRINTER_EVENT_TYPE && eventIt.second != nullptr) {
            PRINT_HILOGD("PrintServiceAbility::SendPrinterEvent find PRINTER_EVENT_TYPE");
            eventIt.second->OnCallback(info.GetPrinterState(), info);
        }
    }
}

void PrintServiceAbility::SendPrinterEventChangeEvent(
    PrinterEvent printerEvent, const PrinterInfo &info, bool isSignalUser)
{
    PRINT_HILOGD("PrintServiceAbility::SendPrinterEventChangeEvent printerId: %{public}s, printerEvent: %{public}d",
        info.GetPrinterId().c_str(), printerEvent);
    for (auto eventIt: registeredListeners_) {
        if (PrintUtils::GetEventType(eventIt.first) != PRINTER_CHANGE_EVENT_TYPE || eventIt.second == nullptr) {
            continue;
        }
        PRINT_HILOGD("PrintServiceAbility::SendPrinterEventChangeEvent eventType = %{public}s",
            eventIt.first.c_str());
        if (isSignalUser && CheckUserIdInEventType(eventIt.first)) {
            PRINT_HILOGI("PrintServiceAbility::SendPrinterEventChangeEvent update info for a signal user");
            PrinterInfo newInfo(info);
            newInfo.SetIsLastUsedPrinter(true);
            eventIt.second->OnCallback(printerEvent, newInfo);
        } else if (printerEvent == PRINTER_EVENT_LAST_USED_PRINTER_CHANGED) {
            if (CheckUserIdInEventType(eventIt.first)) {
                PRINT_HILOGI("PrintServiceAbility::SendPrinterEventChangeEvent last used printer event");
                eventIt.second->OnCallback(printerEvent, info);
            }
        } else {
            eventIt.second->OnCallback(printerEvent, info);
        }
    }
}

void PrintServiceAbility::SendPrintJobEvent(const PrintJob &jobInfo)
{
    PRINT_HILOGD("PrintServiceAbility::SendPrintJobEvent jobId: %{public}s, state: %{public}d, subState: %{public}d",
        jobInfo.GetJobId().c_str(), jobInfo.GetJobState(), jobInfo.GetSubState());
    auto eventIt = registeredListeners_.find(PRINTJOB_EVENT_TYPE);
    if (eventIt != registeredListeners_.end() && eventIt->second != nullptr) {
        eventIt->second->OnCallback(jobInfo.GetJobState(), jobInfo);
    }

    // notify securityGuard
    if (jobInfo.GetJobState() == PRINT_JOB_COMPLETED) {
        auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(jobInfo.GetPrinterId());
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
        if (taskEventIt != registeredListeners_.end() && taskEventIt->second != nullptr) {
            taskEventIt->second->OnCallback();
        }
    }
}

void PrintServiceAbility::SendExtensionEvent(const std::string &extensionId, const std::string &extInfo)
{
    PRINT_HILOGD("PrintServiceAbility::SendExtensionEvent type %{public}s", extInfo.c_str());
    auto eventIt = registeredListeners_.find(EXTINFO_EVENT_TYPE);
    if (eventIt != registeredListeners_.end() && eventIt->second != nullptr) {
        eventIt->second->OnCallback(extensionId, extInfo);
    }
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
        if (GetUserIdByJobId(jobInfo.GetJobId()) == currentUserId_) {
            NotifyAppJobQueueChanged(QUEUE_JOB_LIST_BLOCKED);
        }
    }

    if (isJobQueueBlocked_ && jobInfo.GetJobState() != PRINT_JOB_BLOCKED) {
        bool hasJobBlocked = false;
        auto userData = GetUserDataByJobId(jobInfo.GetJobId());
        if (userData == nullptr) {
            PRINT_HILOGE("Get user data failed.");
            return;
        }
        for (auto printJob : userData->queuedJobList_) {
            if (printJob.second->GetJobState() == PRINT_JOB_BLOCKED) {
                hasJobBlocked = true;
                break;
            }
        }
        if (!hasJobBlocked) {
            // clear blocked
            isJobQueueBlocked_ = false;
            if (GetUserIdByJobId(jobInfo.GetJobId()) == currentUserId_) {
                NotifyAppJobQueueChanged(QUEUE_JOB_LIST_CLEAR_BLOCKED);
            }
        }
    }
    PRINT_HILOGD("CheckJobQueueBlocked end,isJobQueueBlocked_=%{public}s", isJobQueueBlocked_ ? "true" : "false");
}

int32_t PrintServiceAbility::PrintByAdapter(const std::string jobName, const PrintAttributes &printAttributes,
    std::string &taskId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("PrintServiceAbility::PrintByAdapter start");

    std::vector<std::string> fileList;
    std::vector<uint32_t> fdList;
    int32_t ret = CallSpooler(fileList, fdList, taskId);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("PrintServiceAbility::PrintByAdapter CallSpooler failed, ret: %{public}d", ret);
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
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
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
        ReduceAppCount();
        return E_PRINT_NONE;
    }

    if (type == NOTIFY_INFO_SPOOLER_CLOSED_FOR_CANCELLED) {
        PRINT_HILOGI("Notify Spooler Closed for canceled jobId : %{public}s", jobId.c_str());
        notifyAdapterJobChanged(jobId, PRINT_JOB_SPOOLER_CLOSED, PRINT_JOB_SPOOLER_CLOSED_FOR_CANCELED);
        ReduceAppCount();
        return E_PRINT_NONE;
    }
    return E_PRINT_INVALID_PARAMETER;
}

void PrintServiceAbility::ReduceAppCount()
{
    printAppCount_ = printAppCount_ >= 1 ? printAppCount_ - 1 : 0;
    PRINT_HILOGI("printAppCount_: %{public}u", printAppCount_);
    if (printAppCount_ == 0 && queuedJobList_.size() == 0) {
        UnloadSystemAbility();
    }
}

void PrintServiceAbility::notifyAdapterJobChanged(const std::string jobId, const uint32_t state,
    const uint32_t subState)
{
    if (state != PRINT_JOB_BLOCKED && state != PRINT_JOB_COMPLETED && state != PRINT_JOB_SPOOLER_CLOSED) {
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto attrIt = printAttributesList_.find(jobId);
    if (attrIt != printAttributesList_.end()) {
        printAttributesList_.erase(attrIt);
    }

    PRINT_HILOGI("get adapterListenersByJobId_ %{public}s", jobId.c_str());
    auto eventIt = adapterListenersByJobId_.find(jobId);
    if (eventIt == adapterListenersByJobId_.end() || eventIt->second == nullptr) {
        return;
    }

    uint32_t printAdapterListeningState = GetListeningState(state, subState);
    PRINT_HILOGI("notifyAdapterJobChanged for subState: %{public}d, listeningState: %{public}d",
        subState, printAdapterListeningState);
    eventIt->second->onCallbackAdapterJobStateChanged(jobId, state, printAdapterListeningState);

    if (subState == PRINT_JOB_SPOOLER_CLOSED_FOR_CANCELED || state == PRINT_JOB_COMPLETED) {
        PRINT_HILOGI("erase adapterListenersByJobId_ %{public}s", jobId.c_str());
        adapterListenersByJobId_.erase(jobId);
    }
}

uint32_t PrintServiceAbility::GetListeningState(const uint32_t subState)
{
    switch (subState) {
        case PRINT_JOB_SPOOLER_CLOSED_FOR_CANCELED:
            return PREVIEW_ABILITY_DESTROY_FOR_CANCELED;
            break;
        case PRINT_JOB_SPOOLER_CLOSED_FOR_STARTED:
            return PREVIEW_ABILITY_DESTROY_FOR_STARTED;
            break;
        default:
            return PREVIEW_ABILITY_DESTROY;
            break;
    }
}

uint32_t PrintServiceAbility::GetListeningState(uint32_t state, uint32_t subState)
{
    uint32_t printAdapterListeningState = PRINT_TASK_FAIL;
    if (state == PRINT_JOB_SPOOLER_CLOSED) {
        printAdapterListeningState = GetListeningState(subState);
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
    return printAdapterListeningState;
}

int32_t PrintServiceAbility::CallStatusBar()
{
    PRINT_HILOGI("PrintServiceAbility CallStatusBar enter.");
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT) && !CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service, ErrorCode:[%{public}d]", E_PRINT_NO_PERMISSION);
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    AAFwk::Want want;
    want.SetElementName(SPOOLER_BUNDLE_NAME, SPOOLER_STATUS_BAR_ABILITY_NAME);
    int32_t callerTokenId = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    std::string callerPkg = SPOOLER_PACKAGE_NAME;
    ingressPackage = callerPkg;
    int32_t callerUid = IPCSkeleton::GetCallingUid();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_TOKEN, callerTokenId);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_UID, callerUid);
    want.SetParam(AAFwk::Want::PARAM_RESV_CALLER_PID, callerPid);
    want.SetParam(CALLER_PKG_NAME, callerPkg);
    if (!StartPluginPrintIconExtAbility(want)) {
        PRINT_HILOGE("Failed to start PluginPrintIconExtAbility");
        return E_PRINT_SERVER_FAILURE;
    }
    return E_PRINT_NONE;
}

bool PrintServiceAbility::StartPluginPrintIconExtAbility(const AAFwk::Want &want)
{
    if (helper_ == nullptr) {
        PRINT_HILOGE("Invalid print service helper.");
        return false;
    }
    PRINT_HILOGI("enter PrintServiceAbility::StartPluginPrintIconExtAbility");
    return helper_->StartPluginPrintIconExtAbility(want);
}

std::shared_ptr<PrintUserData> PrintServiceAbility::GetCurrentUserData()
{
    int32_t userId = GetCurrentUserId();
    if (userId == E_PRINT_INVALID_USERID) {
        PRINT_HILOGE("Invalid user id.");
        return nullptr;
    }
    auto iter = printUserMap_.find(userId);
    if (iter == printUserMap_.end()) {
        PRINT_HILOGE("Current user is not added, add it.");
        UpdatePrintUserMap();
        iter = printUserMap_.find(userId);
        if (iter == printUserMap_.end()) {
            PRINT_HILOGE("add user failed.");
            return nullptr;
        }
    }
    return iter->second;
}

int32_t PrintServiceAbility::GetCurrentUserId()
{
    int32_t userId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    PRINT_HILOGI("Current userId = %{public}d", userId);
    if (userId < START_USER_ID) {
        PRINT_HILOGE("id %{public}d is system reserved", userId);
        return E_PRINT_INVALID_USERID;
    }
    if (userId > MAX_USER_ID) {
        PRINT_HILOGE("id %{public}d is out of range", userId);
        return E_PRINT_INVALID_USERID;
    }
    return userId;
}

std::shared_ptr<PrintUserData> PrintServiceAbility::GetUserDataByJobId(const std::string jobId)
{
    int32_t userId = GetUserIdByJobId(jobId);
    PRINT_HILOGI("the job is belong to user-%{public}d.", userId);
    if (userId == E_PRINT_INVALID_PRINTJOB) {
        PRINT_HILOGE("Invalid job id.");
        return nullptr;
    }
    auto iter = printUserMap_.find(userId);
    if (iter == printUserMap_.end()) {
        PRINT_HILOGE("Current user is not added.");
        UpdatePrintUserMap();
        iter = printUserMap_.find(userId);
        if (iter == printUserMap_.end()) {
            PRINT_HILOGE("add user failed.");
            return nullptr;
        }
    }
    return iter->second;
}

int32_t PrintServiceAbility::GetUserIdByJobId(const std::string jobId)
{
    for (std::map<std::string, int32_t>::iterator it = userJobMap_.begin(); it != userJobMap_.end();
         ++it) {
        PRINT_HILOGI("jobId: %{public}s, userId: %{public}d.", it->first.c_str(), it->second);
    }
    auto iter = userJobMap_.find(jobId);
    if (iter == userJobMap_.end()) {
        PRINT_HILOGE("Invalid job id.");
        return E_PRINT_INVALID_PRINTJOB;
    }
    return iter->second;
}

void PrintServiceAbility::UpdatePrintUserMap()
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    int32_t userId = GetCurrentUserId();
    if (userId == E_PRINT_INVALID_USERID) {
        PRINT_HILOGE("Invalid user id.");
        return;
    }
    PRINT_HILOGI("new user id: %{public}d.", userId);
    currentUserId_ = userId;
    auto iter = printUserMap_.find(userId);
    if (iter == printUserMap_.end()) {
        auto userData = std::make_shared<PrintUserData>();
        if (userData != nullptr) {
            printUserMap_.insert(std::make_pair(userId, userData));
            userData->SetUserId(userId);
            userData->ParseUserData();
            PRINT_HILOGI("add user success");
        }
    }
}

void PrintServiceAbility::AddToPrintJobList(const std::string jobId, const std::shared_ptr<PrintJob> &printjob)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    PRINT_HILOGD("begin AddToPrintJobList.");
    UpdatePrintUserMap();
    printJobList_.insert(std::make_pair(jobId, printjob));
    for (auto printjob : printJobList_) {
        PRINT_HILOGI("printjob in printJobList_, jobId: %{public}s.", printjob.first.c_str());
    }
    int32_t userId = GetCurrentUserId();
    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return;
    }
    userJobMap_.insert(std::make_pair(jobId, userId));
    userData->AddToPrintJobList(jobId, printjob);
}

void PrintServiceAbility::RegisterAdapterListener(const std::string &jobId)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    PRINT_HILOGD("RegisterAdapterListener for jobId %{public}s", jobId.c_str());
    auto eventIt = registeredListeners_.find(PRINT_ADAPTER_EVENT_TYPE);
    if (eventIt != registeredListeners_.end()) {
        PRINT_HILOGI("adapterListenersByJobId_ set adapterListenersByJobId_ %{public}s", jobId.c_str());
        adapterListenersByJobId_.insert(std::make_pair(jobId, eventIt->second));
    }
}

int32_t PrintServiceAbility::SetDefaultPrinter(const std::string &printerId, uint32_t type)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("SetDefaultPrinter started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return E_PRINT_INVALID_USERID;
    }
    int32_t ret = userData->SetDefaultPrinter(printerId, type);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("SetDefaultPrinter failed.");
        return ret;
    }
    return E_PRINT_NONE;
}

bool PrintServiceAbility::CheckIsDefaultPrinter(const std::string &printerId)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return false;
    }
    if (printerId != userData->GetDefaultPrinter()) {
        return false;
    }
    return true;
}

bool PrintServiceAbility::CheckIsLastUsedPrinter(const std::string &printerId)
{
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return false;
    }
    if (printerId != userData->GetLastUsedPrinter()) {
        return false;
    }
    return true;
}

int32_t PrintServiceAbility::DeletePrinterFromCups(const std::string &printerName)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("DeletePrinterFromCups started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
#ifdef CUPS_ENABLE
    std::string standardName = PrintUtil::StandardizePrinterName(printerName);
    DelayedSingleton<PrintCupsClient>::GetInstance()->DeleteCupsPrinter(standardName.c_str());
#endif  // CUPS_ENABLE
    std::string printerId = printSystemData_.QueryPrinterIdByStandardizeName(printerName);
#ifdef IPPOVERUSB_ENABLE
    DelayedSingleton<PrintIppOverUsbManager>::GetInstance()->DisConnectPrinter(printerId);
#endif // IPPOVERUSB_ENABLE
    vendorManager.MonitorPrinterStatus(printerId, false);
    DeletePrinterFromUserData(printerId);
    NotifyAppDeletePrinter(printerId);
    printSystemData_.DeleteCupsPrinter(printerId);
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::AddPrinterToDiscovery(const PrinterInfo &printerInfo)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    PRINT_HILOGD("AddPrinterToDiscovery started. Current total size is %{public}zd",
        printSystemData_.GetDiscoveredPrinterCount());
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());

    int32_t result = AddSinglePrinterInfo(printerInfo, extensionId);

    PRINT_HILOGD("AddPrinterToDiscovery end. New total size is %{public}zd",
        printSystemData_.GetDiscoveredPrinterCount());
    return result;
}

int32_t PrintServiceAbility::UpdatePrinterInDiscovery(const PrinterInfo &printerInfo)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());
    int32_t ret = E_PRINT_NONE;
    if (!PrintUtil::startsWith(extensionId, PRINT_EXTENSION_BUNDLE_NAME)) {
        ret = AddPrinterToCups(printerInfo.GetUri(), printerInfo.GetPrinterName(), printerInfo.GetPrinterMake());
    }
    if (ret == E_PRINT_NONE) {
        UpdateSinglePrinterInfo(printerInfo, extensionId);
    }
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::RemovePrinterFromDiscovery(const std::string &printerId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::string printerUri;
    std::string extensionId;
    std::string printerExtId;
    std::shared_ptr<PrinterInfo> printerInfo;
    {
        std::lock_guard<std::recursive_mutex> lock(apiMutex_);
        extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
        PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());
        printerExtId = PrintUtils::GetGlobalId(extensionId, printerId);
        printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(printerExtId);
        if (printerInfo == nullptr) {
            PRINT_HILOGE("invalid printer id");
            return E_PRINT_INVALID_PRINTER;
        }
        printerUri = printerInfo->GetUri();
    }
    bool mdnsPrinter = printerId.find("mdns") != string::npos;
    const uint32_t waitTime = 1000;
    JobMonitorParam monitorParam{ nullptr, "", 0, printerUri, "", printerId };
    PRINT_HILOGD("printerid is %{public}s, printer type is %{public}d", printerId.c_str(), mdnsPrinter);
    // 连接类型为mdns且为spooler显示的已经连接的打印机才判断是否离线
    if (!printerUri.empty() && mdnsPrinter &&
        DelayedSingleton<PrintCupsClient>::GetInstance()->CheckPrinterOnline(&monitorParam, waitTime)) {
        PRINT_HILOGD("printer is online, do not remove.");
        return E_PRINT_INVALID_PRINTER;
    }
    PRINT_HILOGD("printer uri is empty or priter is offline, printerUri = %{public}s", printerUri.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    bool result = RemoveSinglePrinterInfo(PrintUtils::GetGlobalId(extensionId, printerId));
    return result ? E_PRINT_NONE : E_PRINT_INVALID_PRINTER;
}

int32_t PrintServiceAbility::UpdatePrinterInSystem(const PrinterInfo &printerInfo)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (!UpdatePrinterSystemData(printerInfo)) {
        PRINT_HILOGE("UpdatePrinterSystemData failed");
        return E_PRINT_INVALID_PARAMETER;
    }

    printSystemData_.SaveCupsPrinterMap();
    return E_PRINT_NONE;
}

void PrintServiceAbility::DeletePrinterFromUserData(const std::string &printerId)
{
    std::vector<int32_t> allPrintUserList;
    printSystemData_.GetAllPrintUser(allPrintUserList);
    for (auto userId : allPrintUserList) {
        PRINT_HILOGI("DeletePrinterFromUserData userId %{public}d.", userId);
        auto iter = printUserMap_.find(userId);
        if (iter != printUserMap_.end()) {
            ChangeDefaultPrinterForDelete(iter->second, printerId);
        } else {
            auto userData = std::make_shared<PrintUserData>();
            userData->SetUserId(userId);
            userData->ParseUserData();
            ChangeDefaultPrinterForDelete(userData, printerId);
        }
    }
}

void PrintServiceAbility::ChangeDefaultPrinterForDelete(
    std::shared_ptr<PrintUserData> &userData, const std::string &printerId)
{
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return;
    }
    userData->DeletePrinter(printerId);
    std::string defaultPrinterId = userData->GetDefaultPrinter();
    bool ret = userData->CheckIfUseLastUsedPrinterForDefault();
    PRINT_HILOGI("DeletePrinterFromUserData defaultPrinterId %{public}s.", defaultPrinterId.c_str());
    if (!strcmp(printerId.c_str(), defaultPrinterId.c_str())) {
        if (!ret) {
            userData->SetDefaultPrinter("", DELETE_DEFAULT_PRINTER);
        } else {
            userData->SetDefaultPrinter("", DELETE_LAST_USED_PRINTER);
        }
    }
}

std::shared_ptr<PrintUserData> PrintServiceAbility::GetUserDataByUserId(int32_t userId)
{
    auto iter = printUserMap_.find(userId);
    if (iter == printUserMap_.end()) {
        PRINT_HILOGE("Current user is not added, add it.");
        auto userData = std::make_shared<PrintUserData>();
        if (userData != nullptr) {
            printUserMap_.insert(std::make_pair(userId, userData));
            userData->SetUserId(userId);
            userData->ParseUserData();
            PRINT_HILOGI("add user success");
            return userData;
        } else {
            return nullptr;
        }
    }
    return iter->second;
}

PrintJobState PrintServiceAbility::DetermineUserJobStatus(
    const std::map<std::string, std::shared_ptr<PrintJob>> &jobList)
{
    bool hasBlocked = std::any_of(jobList.begin(), jobList.end(),
        [](const auto& pair) { return pair.second->GetJobState() == PRINT_JOB_BLOCKED; });
    if (hasBlocked) {
        return PRINT_JOB_BLOCKED;
    }
    bool allComplete = std::all_of(jobList.begin(), jobList.end(),
        [](const auto& pair) { return pair.second->GetJobState() == PRINT_JOB_COMPLETED; });
    if (allComplete) {
        return PRINT_JOB_COMPLETED;
    }
    return PRINT_JOB_RUNNING;
}

void PrintServiceAbility::NotifyAppDeletePrinter(const std::string &printerId)
{
    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return;
    }
    std::string dafaultPrinterId = userData->GetDefaultPrinter();
    PrinterInfo printerInfo;
    printSystemData_.QueryPrinterInfoById(printerId, printerInfo);
    std::string ops = printerInfo.GetOption();
    if (!json::accept(ops)) {
        PRINT_HILOGW("ops can not parse to json object");
        return;
    }
    nlohmann::json opsJson = json::parse(ops);
    opsJson["nextDefaultPrinter"] = dafaultPrinterId;
    printerInfo.SetOption(opsJson.dump());
    SendPrinterEventChangeEvent(PRINTER_EVENT_DELETED, printerInfo);
    SendPrinterChangeEvent(PRINTER_EVENT_DELETED, printerInfo);

    std::string lastUsedPrinterId = userData->GetLastUsedPrinter();
    if (!lastUsedPrinterId.empty()) {
        PrinterInfo lastUsedPrinterInfo;
        printSystemData_.QueryPrinterInfoById(lastUsedPrinterId, lastUsedPrinterInfo);
        PRINT_HILOGI("NotifyAppDeletePrinter lastUsedPrinterId = %{public}s", lastUsedPrinterId.c_str());
        SendPrinterEventChangeEvent(PRINTER_EVENT_LAST_USED_PRINTER_CHANGED, lastUsedPrinterInfo);
    }
}

int32_t PrintServiceAbility::DiscoverUsbPrinters(std::vector<PrinterInfo> &printers)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGD("DiscoverUsbPrinters started.");
#ifdef CUPS_ENABLE
    int32_t ret = DelayedSingleton<PrintCupsClient>::GetInstance()->DiscoverUsbPrinters(printers);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("DiscoverUsbDevices failed.");
        return ret;
    }
#endif  // CUPS_ENABLE
    PRINT_HILOGD("DiscoverUsbDevices printers size: %{public}zu", printers.size());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::AddSinglePrinterInfo(const PrinterInfo &info, const std::string &extensionId)
{
    if (printSystemData_.QueryDiscoveredPrinterInfoById(info.GetPrinterId()) != nullptr) {
        PRINT_HILOGE("duplicate printer id, ignore it");
        return E_PRINT_INVALID_PRINTER;
    }

    auto infoPtr = std::make_shared<PrinterInfo>(info);
    infoPtr->SetPrinterId(PrintUtils::GetGlobalId(extensionId, infoPtr->GetPrinterId()));
    PRINT_HILOGD("Printer ID = %{public}s", infoPtr->GetPrinterId().c_str());
    infoPtr->SetPrinterState(PRINTER_ADDED);
    printSystemData_.AddPrinterToDiscovery(infoPtr);

    SendPrinterDiscoverEvent(PRINTER_ADDED, *infoPtr);
    SendPrinterEvent(*infoPtr);
    SendQueuePrintJob(infoPtr->GetPrinterId());

    if (printSystemData_.IsPrinterAdded(infoPtr->GetPrinterId()) &&
        !printSystemData_.CheckPrinterBusy(infoPtr->GetPrinterId())) {
        if (CheckPrinterUriDifferent(infoPtr)) {
            if (UpdateAddedPrinterInCups(infoPtr->GetPrinterId(), infoPtr->GetUri())) {
                printSystemData_.UpdatePrinterUri(infoPtr);
                printSystemData_.SaveCupsPrinterMap();
            }
        }
        infoPtr->SetPrinterStatus(PRINTER_STATUS_IDLE);
        printSystemData_.UpdatePrinterStatus(infoPtr->GetPrinterId(), PRINTER_STATUS_IDLE);
        SendPrinterEventChangeEvent(PRINTER_EVENT_STATE_CHANGED, *infoPtr);
        SendPrinterChangeEvent(PRINTER_EVENT_STATE_CHANGED, *infoPtr);
    }

    return E_PRINT_NONE;
}

bool PrintServiceAbility::UpdateSinglePrinterInfo(const PrinterInfo &info, const std::string &extensionId)
{
    std::string printExtId = info.GetPrinterId();
    printExtId = PrintUtils::GetGlobalId(extensionId, printExtId);

    bool isSystemDataUpdated = UpdatePrinterSystemData(info);
    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(printExtId);
    if (printerInfo == nullptr) {
        PRINT_HILOGE("invalid printer id, ignore it");
        return false;
    }
    *printerInfo = info;
    printerInfo->SetPrinterState(PRINTER_UPDATE_CAP);
    printerInfo->SetPrinterId(printExtId);
    printerInfo->Dump();

    bool isCapabilityUpdated = false;
    if (printerInfo->HasCapability()) {
        isCapabilityUpdated = UpdatePrinterCapability(printExtId, info);
    }

    bool isChanged = isSystemDataUpdated || isCapabilityUpdated;
    if (isChanged) {
        SendPrinterEvent(*printerInfo);
        SendPrinterDiscoverEvent(PRINTER_UPDATE_CAP, *printerInfo);
        printSystemData_.SaveCupsPrinterMap();
    }

    return isChanged;
}

bool PrintServiceAbility::RemoveSinglePrinterInfo(const std::string &printerId)
{
    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(printerId);
    if (printerInfo == nullptr) {
        PRINT_HILOGE("invalid printer id, ignore it");
        return false;
    }
    printerInfo->SetPrinterState(PRINTER_REMOVED);
    SendPrinterDiscoverEvent(PRINTER_REMOVED, *printerInfo);
    SendPrinterEvent(*printerInfo);
    printSystemData_.RemovePrinterFromDiscovery(printerId);

    if (printSystemData_.IsPrinterAdded(printerId)) {
        printerInfo->SetPrinterStatus(PRINTER_STATUS_UNAVAILABLE);
        printSystemData_.UpdatePrinterStatus(printerId, PRINTER_STATUS_UNAVAILABLE);
        SendPrinterEventChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
        SendPrinterChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
    }
    return true;
}

bool PrintServiceAbility::AddVendorPrinterToDiscovery(const std::string &globalVendorName, const PrinterInfo &info)
{
    PRINT_HILOGI("AddPrinterToDiscovery");
    auto globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, info.GetPrinterId());
    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(globalPrinterId);
    if (printerInfo == nullptr) {
        PRINT_HILOGI("new printer, add it");
        printerInfo = std::make_shared<PrinterInfo>(info);
        if (printerInfo == nullptr) {
            PRINT_HILOGW("allocate printer info fail");
            return false;
        }
        OHOS::Print::CupsPrinterInfo cupsPrinter;
        if (printSystemData_.QueryCupsPrinterInfoByPrinterId(globalPrinterId, cupsPrinter)) {
            printerInfo->SetPrinterName(cupsPrinter.name);
        }
        printerInfo->SetPrinterId(globalPrinterId);
        printerInfo->SetPrinterState(PRINTER_ADDED);
        printSystemData_.AddPrinterToDiscovery(printerInfo);
    }
    SendPrinterDiscoverEvent(PRINTER_ADDED, *printerInfo);
    SendPrinterEvent(*printerInfo);
    SendQueuePrintJob(globalPrinterId);
    if (printSystemData_.IsPrinterAdded(printerInfo->GetPrinterId()) &&
        !printSystemData_.CheckPrinterBusy(printerInfo->GetPrinterId())) {
        if (CheckPrinterUriDifferent(printerInfo)) {
            PRINT_HILOGW("different printer uri, ignore it");
        } else {
            PRINT_HILOGI("added printer, update status to idle");
            printerInfo->SetPrinterStatus(PRINTER_STATUS_IDLE);
            printSystemData_.UpdatePrinterStatus(printerInfo->GetPrinterId(), PRINTER_STATUS_IDLE);
            SendPrinterEventChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
            SendPrinterChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
        }
    }
    return true;
}

bool PrintServiceAbility::UpdateVendorPrinterToDiscovery(const std::string &globalVendorName, const PrinterInfo &info)
{
    PRINT_HILOGI("UpdatePrinterToDiscovery");
    auto globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, info.GetPrinterId());
    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(globalPrinterId);
    if (printerInfo == nullptr) {
        printerInfo = std::make_shared<PrinterInfo>(info);
        if (printerInfo == nullptr) {
            PRINT_HILOGW("invalid printer id, ingore it");
            return false;
        }
        printerInfo->SetPrinterId(globalPrinterId);
        printSystemData_.AddPrinterToDiscovery(printerInfo);
    } else {
        if (info.HasCapability()) {
            *printerInfo = info;
            printerInfo->SetPrinterId(globalPrinterId);
        }
    }
    OHOS::Print::CupsPrinterInfo cupsPrinter;
    if (printSystemData_.QueryCupsPrinterInfoByPrinterId(globalPrinterId, cupsPrinter)) {
        printerInfo->SetPrinterName(cupsPrinter.name);
    }
    printerInfo->SetPrinterState(PRINTER_UPDATE_CAP);
    SendPrinterDiscoverEvent(PRINTER_UPDATE_CAP, *printerInfo);
    SendPrinterEvent(*printerInfo);
    return true;
}

bool PrintServiceAbility::RemoveVendorPrinterFromDiscovery(const std::string &globalVendorName,
    const std::string &printerId)
{
    PRINT_HILOGI("RemovePrinterFromDiscovery");
    auto globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, printerId);
    return RemoveSinglePrinterInfo(globalPrinterId);
}

bool PrintServiceAbility::AddVendorPrinterToCupsWithPpd(const std::string &globalVendorName,
    const std::string &printerId, const std::string &ppdData)
{
    auto globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, printerId);
    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(globalPrinterId);
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printerInfo is null");
        return false;
    }
    if (!printerInfo->HasCapability() || !printerInfo->HasUri() || !printerInfo->HasPrinterMake()) {
        PRINT_HILOGW("empty capability or invalid printer info");
        return false;
    }
    printerInfo->SetPrinterName(RenamePrinterWhenAdded(*printerInfo));
    CupsPrinterInfo info;
    info.name = printerInfo->GetPrinterName();
    info.uri = printerInfo->GetUri();
    info.maker = printerInfo->GetPrinterMake();
#ifdef CUPS_ENABLE
    int32_t ret = E_PRINT_NONE;
    if (ppdData.empty()) {
        ret = DelayedSingleton<PrintCupsClient>::GetInstance()->AddPrinterToCups(info.uri, info.name, info.maker);
    } else {
        ret = DelayedSingleton<PrintCupsClient>::GetInstance()->AddPrinterToCupsWithPpd(info.uri, info.name,
            "Brocadesoft Universal Driver", ppdData);
    }
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGW("AddPrinterToCups error = %{public}d.", ret);
        return false;
    }
#endif // CUPS_ENABLE
    info.printerStatus = PRINTER_STATUS_IDLE;
    printerInfo->GetCapability(info.printerCapability);
    WritePrinterPreference(globalPrinterId, info.printerCapability);
    printerInfo->SetPrinterState(PRINTER_CONNECTED);
    printerInfo->SetIsLastUsedPrinter(true);
    printerInfo->SetPrinterStatus(PRINTER_STATUS_IDLE);
    SetLastUsedPrinter(globalPrinterId);
    if (printSystemData_.IsPrinterAdded(globalPrinterId)) {
        SendPrinterEventChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
        SendPrinterChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
    } else {
        printSystemData_.InsertCupsPrinter(globalPrinterId, info, true);
        printSystemData_.SaveCupsPrinterMap();
        SendPrinterEventChangeEvent(PRINTER_EVENT_ADDED, *printerInfo, true);
        SendPrinterChangeEvent(PRINTER_EVENT_ADDED, *printerInfo);
    }
    SendPrinterDiscoverEvent(PRINTER_CONNECTED, *printerInfo);
    vendorManager.MonitorPrinterStatus(globalPrinterId, true);
    return true;
}

bool PrintServiceAbility::RemoveVendorPrinterFromCups(const std::string &globalVendorName,
    const std::string &printerId)
{
    PRINT_HILOGI("RemovePrinterFromCups");
    auto globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, printerId);
    CupsPrinterInfo cupsPrinter;
    if (!printSystemData_.QueryCupsPrinterInfoByPrinterId(globalPrinterId, cupsPrinter)) {
        PRINT_HILOGW("cannot find printer");
        return false;
    }
#ifdef CUPS_ENABLE
    std::string standardName = PrintUtil::StandardizePrinterName(cupsPrinter.name);
    auto ret = DelayedSingleton<PrintCupsClient>::GetInstance()->DeleteCupsPrinter(standardName.c_str());
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGW("DeleteCupsPrinter error = %{public}d.", ret);
        return false;
    }
#endif  // CUPS_ENABLE
    vendorManager.MonitorPrinterStatus(globalPrinterId, false);
    DeletePrinterFromUserData(globalPrinterId);
    NotifyAppDeletePrinter(globalPrinterId);
    printSystemData_.DeleteCupsPrinter(globalPrinterId);
    return true;
}

bool PrintServiceAbility::OnVendorStatusUpdate(const std::string &globalVendorName, const std::string &printerId,
    const PrinterVendorStatus &status)
{
    PRINT_HILOGD("OnVendorStatusUpdate: %{public}d", static_cast<int32_t>(status.state));
    auto globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, printerId);
    PRINT_HILOGD("OnVendorStatusUpdate %{public}s", globalPrinterId.c_str());
    printSystemData_.UpdatePrinterStatus(globalPrinterId, static_cast<PrinterStatus>(status.state));
    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(globalPrinterId);
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printer info missing");
        return false;
    }
    printerInfo->SetPrinterStatus(static_cast<uint32_t>(status.state));
    SendPrinterEventChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
    SendPrinterChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
    return true;
}

bool PrintServiceAbility::QueryPrinterCapabilityByUri(const std::string &uri, PrinterCapability &printerCap)
{
#ifdef CUPS_ENABLE
    return DelayedSingleton<PrintCupsClient>::GetInstance()->QueryPrinterCapabilityByUri(uri, "", printerCap) ==
        E_PRINT_NONE;
#else
    return false;
#endif
}

bool PrintServiceAbility::QueryPrinterStatusByUri(const std::string &uri, PrinterStatus &status)
{
#ifdef CUPS_ENABLE
    return DelayedSingleton<PrintCupsClient>::GetInstance()->QueryPrinterStatusByUri(uri, status) == E_PRINT_NONE;
#else
    return false;
#endif
}

int32_t PrintServiceAbility::StartExtensionDiscovery(const std::vector<std::string> &extensionIds)
{
    std::map<std::string, AppExecFwk::ExtensionAbilityInfo> abilityList;
    for (auto const &extensionId : extensionIds) {
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

int32_t PrintServiceAbility::StartPrintJobInternal(const std::shared_ptr<PrintJob> &printJob)
{
    if (printJob == nullptr) {
        PRINT_HILOGW("printJob is null");
        return E_PRINT_SERVER_FAILURE;
    }
    if (isEprint(printJob->GetPrinterId())) {
        auto extensionId = PrintUtils::GetExtensionId(printJob->GetPrinterId());
        std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
        auto cbIter = extCallbackMap_.find(cid);
        if (cbIter == extCallbackMap_.end()) {
            return E_PRINT_SERVER_FAILURE;
        }
        auto cbFunc = cbIter->second;
        auto callback = [=]() {
            if (cbFunc != nullptr) {
                StartPrintJobCB(printJob->GetJobId(), printJob);
                cbFunc->OnCallback(*printJob);
                CallStatusBar();
            }
        };
        if (helper_->IsSyncMode()) {
            callback();
        } else {
            serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
        }
    } else {
#ifdef CUPS_ENABLE
        NotifyAppJobQueueChanged(QUEUE_JOB_LIST_PRINTING);
        DelayedSingleton<PrintCupsClient>::GetInstance()->AddCupsPrintJob(*printJob);
        CallStatusBar();
#endif  // CUPS_ENABLE
    }
    return E_PRINT_NONE;
}
int32_t PrintServiceAbility::QueryVendorPrinterInfo(const std::string &globalPrinterId, PrinterInfo &info)
{
    auto discoveredInfo = printSystemData_.QueryDiscoveredPrinterInfoById(globalPrinterId);
    if (discoveredInfo != nullptr && discoveredInfo->HasCapability()) {
        info = *discoveredInfo;
        return E_PRINT_NONE;
    }
    const int waitTimeout = 5000;
    if (!vendorManager.QueryPrinterInfo(globalPrinterId, waitTimeout)) {
        return E_PRINT_INVALID_PRINTER;
    }
    discoveredInfo = printSystemData_.QueryDiscoveredPrinterInfoById(globalPrinterId);
    if (discoveredInfo != nullptr && discoveredInfo->HasCapability()) {
        info = *discoveredInfo;
        return E_PRINT_NONE;
    }
    return E_PRINT_INVALID_PRINTER;
}

int32_t PrintServiceAbility::TryConnectPrinterByIp(const std::string &params)
{
    if (!json::accept(params)) {
        PRINT_HILOGW("invalid params");
        return E_PRINT_INVALID_PRINTER;
    }
    nlohmann::json connectParamJson = json::parse(params, nullptr, false);
    if (connectParamJson.is_discarded()) {
        PRINT_HILOGW("json discarded");
        return E_PRINT_INVALID_PRINTER;
    }
    if (!connectParamJson.contains("ip") || !connectParamJson["ip"].is_string()) {
        PRINT_HILOGW("ip missing");
        return E_PRINT_INVALID_PRINTER;
    }
    std::string ip = connectParamJson["ip"].get<std::string>();
    std::string protocol = "auto";
    if (connectParamJson.contains("protocol") && connectParamJson["protocol"].is_string()) {
        protocol = connectParamJson["protocol"].get<std::string>();
    }
    vendorManager.SetConnectingPrinter(IP_AUTO, ip);
    if (!vendorManager.ConnectPrinterByIp(ip, protocol)) {
        PRINT_HILOGW("ConnectPrinterByIp fail");
        return E_PRINT_SERVER_FAILURE;
    }
    PRINT_HILOGD("connecting printer by ip success");
    return E_PRINT_NONE;
}

void PrintServiceAbility::HandlePrinterStateChangeRegister(const std::string &eventType)
{
    if (PrintUtils::GetEventType(eventType) == PRINTER_EVENT_TYPE) {
        PRINT_HILOGI("begin HandlePrinterStateChangeRegister");
        std::map <std::string, std::shared_ptr<PrinterInfo>> discoveredPrinterInfoList_ =
                printSystemData_.GetDiscoveredPrinterInfo();
        for (const auto &pair: discoveredPrinterInfoList_) {
            std::string key = pair.first;
            std::shared_ptr <PrinterInfo> printerInfoPtr = pair.second;
            SendPrinterEvent(*printerInfoPtr);
        }
        PRINT_HILOGI("end HandlePrinterStateChangeRegister");
    }
}

void PrintServiceAbility::HandlePrinterChangeRegister(const std::string &eventType)
{
    if (PrintUtils::GetEventType(eventType) == PRINTER_CHANGE_EVENT_TYPE) {
        PRINT_HILOGD("begin HandlePrinterChangeRegister, StartDiscoverPrinter");
        std::vector <PrintExtensionInfo> extensionInfos;
        QueryAllExtension(extensionInfos);
        std::vector <std::string> extensionIds;
        StartDiscoverPrinter(extensionIds);
        printAppCount_++;
        PRINT_HILOGD("end HandlePrinterChangeRegister, printAppCount_: %{public}u", printAppCount_);
    }
}

bool PrintServiceAbility::UpdateAddedPrinterInCups(const std::string &printerId, const std::string &printerUri)
{
    CupsPrinterInfo cupsPrinter;
    if (printSystemData_.QueryCupsPrinterInfoByPrinterId(printerId, cupsPrinter)) {
        int32_t ret = DelayedSingleton<PrintCupsClient>::GetInstance()->
            AddPrinterToCups(printerUri, cupsPrinter.name, cupsPrinter.maker);
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("UpdateAddedPrinterInCups error = %{public}d.", ret);
            return false;
        }
        return true;
    }
    return false;
}

std::string PrintServiceAbility::RenamePrinterWhenAdded(const PrinterInfo &info)
{
    static uint32_t repeatNameLimit = 10;
    std::vector<std::string> printerNameList;
    printSystemData_.GetAddedPrinterListFromSystemData(printerNameList);
    uint32_t nameIndex = 1;
    auto printerName = info.GetPrinterName();
    auto iter = printerNameList.begin();
    auto end = printerNameList.end();
    do {
        iter = std::find(iter, end, printerName);
        if (iter == end) {
            break;
        }
        printerName = info.GetPrinterName();
        printerName += " ";
        printerName += std::to_string(nameIndex);
        if (nameIndex == repeatNameLimit) {
            break;
        }
        ++nameIndex;
        iter = printerNameList.begin();
    } while (iter != end);
    return printerName;
}

std::shared_ptr<PrinterInfo> PrintServiceAbility::QueryDiscoveredPrinterInfoById(const std::string &printerId)
{
    return printSystemData_.QueryDiscoveredPrinterInfoById(printerId);
}

bool PrintServiceAbility::CheckUserIdInEventType(const std::string &type)
{
    int32_t callerUserId = GetCurrentUserId();
    PRINT_HILOGD("callerUserId = %{public}d", callerUserId);
    if (PrintUtils::CheckUserIdInEventType(type, callerUserId)) {
        PRINT_HILOGD("find current user");
        return true;
    }
    return false;
}
} // namespace OHOS::Print
