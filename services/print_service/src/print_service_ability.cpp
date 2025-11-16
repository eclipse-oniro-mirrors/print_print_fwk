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
#endif  // CUPS_ENABLE
#include "accesstoken_kit.h"
#include "array_wrapper.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "iservice_registry.h"
#include "parameters.h"
#include "print_bms_helper.h"
#include "print_constant.h"
#include "print_log.h"
#include "printer_info.h"
#include "print_service_converter.h"
#include "print_utils.h"
#include "string_wrapper.h"
#include "system_ability_definition.h"
#include "want_params_wrapper.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "print_security_guard_manager.h"
#include "hisys_event_util.h"
#include "uri.h"
#include <fstream>
#include <streambuf>
#include "print_json_util.h"
#include "print_setting_data_helper.h"
#include "parameters.h"
#include "bundle_mgr_client.h"
#include "bundle_info.h"
#include "print_caller_app_monitor.h"
#ifdef EDM_SERVICE_ENABLE
#include "enterprise_device_mgr_proxy.h"
#include "sg_collect_client.h"
#include "event_info.h"
#endif // EDM_SERVICE_ENABLE

namespace OHOS::Print {
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;

const uint32_t MAX_JOBQUEUE_NUM = 512;
const uint32_t ASYNC_CMD_DELAY = 10;
const int64_t INIT_INTERVAL = 5000L;
const int32_t UID_TRANSFORM_DIVISOR = 200000;
const uint32_t QUERY_CUPS_ALIVE_INTERVAL = 10;
const uint32_t QUERY_CUPS_ALIVE_MAX_RETRY_TIMES = 50;
const uint32_t ENTER_LOW_POWER_INTERVAL = 90000;
const uint32_t UNREGISTER_CALLBACK_INTERVAL = 5000;
const uint32_t CHECK_CALLER_APP_INTERVAL = 60;
const uint32_t CONNECT_PLUGIN_PRINT_TIMEOUT = 5000;

const uint32_t INDEX_ZERO = 0;
const uint32_t INDEX_THREE = 3;
const uint32_t SERIAL_LENGTH = 6;

static const std::string SPOOLER_BUNDLE_NAME = "com.ohos.spooler";
static const std::string SPOOLER_PACKAGE_NAME = "com.ohos.spooler";
static const std::string PRINT_EXTENSION_BUNDLE_NAME = "com.ohos.hwprintext";
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
static const std::string PRINT_QUERY_INFO_EVENT_TYPE = "printerInfoQuery";
static const std::string EVENT_BLOCK = "block";
static const std::string EVENT_SUCCESS = "succeed";
static const std::string EVENT_FAIL = "fail";
static const std::string EVENT_CANCEL = "cancel";
static const std::string CALLER_PKG_NAME = "caller.pkgName";
static const std::string MDNS_PRINTER = "mdns";

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

static const std::string RAW_GLOBAL_ID_DELIMITER = ".";
static const std::string PRINTER_ID_DELIMITER = ":";
static const std::string USB_PRINTER = "usb";
static const std::string DEVICE_TYPE = "PRINTER";
static const std::string PRINT_CONSTRAINT = "constraint.print";

static const std::string PARAMETER_SUPPORT_WINDOW_PCMODE_SWITCH = "const.window.support_window_pcmode_switch";
static const std::string WINDOW_PCMODE_SWITCH_STATUS = "window_pcmode_switch_status";

#if ENTERPRISE_ENABLE
static const std::string IS_ENTERPRISE_ENABLE = "true";
static const std::string ENTERPRISE_SPACE_PARAM = "persist.space_mgr_service.enterprise_space_enable";
#endif  // ENTERPRISE_ENABLE

static const std::vector<std::string> PRINT_TASK_EVENT_LIST = {EVENT_BLOCK, EVENT_SUCCESS, EVENT_FAIL, EVENT_CANCEL};

static const std::vector<std::string> PREINSTALLED_DRIVER_PRINTER = {};

static bool g_publishState = false;

const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(PrintServiceAbility::GetInstance().GetRefPtr());
const int32_t JOB_BANNED_EVENTID = 0x02E000001;
const std::string JOB_BANNED_VERSION = "1.0";
const int32_t JOB_BANNED_POLICY_CODE = 1021;
const std::string VIRTUAL_PRINTER_ID = "fwk.driver.ppd:Virtual PDF Printer";

std::mutex PrintServiceAbility::instanceLock_;
sptr<PrintServiceAbility> PrintServiceAbility::instance_;
std::chrono::time_point<std::chrono::high_resolution_clock> PrintServiceAbility::startPrintTime_;
std::string PrintServiceAbility::ingressPackage;

PrintServiceAbility::PrintServiceAbility(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate),
      state_(ServiceRunningState::STATE_NOT_START),
      currentJobOrderId_(0),
      helper_(nullptr),
      serviceHandler_(nullptr),
      isJobQueueBlocked_(false),
      currentUserId_(-1),
      enterLowPowerCount_(0),
      isLowPowerMode_(false)
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

void PrintServiceAbility::RefreshEprinterErrorCapability()
{
    std::string eprinterId = "";
    std::vector<std::string> printerIdList = printSystemData_.QueryAddedPrinterIdList();
    for (auto &printerId : printerIdList) {
        if (printerId.find(EPRINTID) != std::string::npos) {
            eprinterId = printerId;
        }
    }
    if (eprinterId.empty()) {
        return;
    }
    PrinterInfo printerInfo;
    if (!printSystemData_.QueryAddedPrinterInfoByPrinterId(eprinterId, printerInfo)) {
        PRINT_HILOGE("QueryEprinterInfo fail.");
        return;
    }
    PrinterCapability caps;
    printerInfo.GetCapability(caps);
    std::vector<uint32_t> colorList;
    caps.GetSupportedColorMode(colorList);
    if (std::find(colorList.begin(), colorList.end(), PRINT_COLOR_MODE_COLOR) != colorList.end()) {
        return;
    }
    PRINT_HILOGW("Error eprint capability found.");
    colorList = { PRINT_COLOR_MODE_MONOCHROME, PRINT_COLOR_MODE_COLOR };
    caps.SetSupportedColorMode(colorList);
    printerInfo.SetCapability(caps);
    printSystemData_.InsertAddedPrinter(eprinterId, printerInfo);
    printSystemData_.SavePrinterFile(eprinterId);
}

int32_t PrintServiceAbility::Init()
{
    {
        std::lock_guard<std::recursive_mutex> lock(apiMutex_);
        if (helper_ == nullptr) {
            helper_ = std::make_shared<PrintServiceHelper>();
        }
        if (helper_ == nullptr) {
            PRINT_HILOGE("PrintServiceHelper create failed.");
            return E_PRINT_SERVER_FAILURE;
        }
        DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(helper_);
        helper_->PrintSubscribeCommonEvent();
    }
#ifdef ENTERPRISE_ENABLE
    UpdateIsEnterprise();
#endif
    printSystemData_.Init();
    RefreshEprinterErrorCapability();
    vendorManager.Init(GetInstance(), true);
#ifdef CUPS_ENABLE
    int32_t initCupsRet = DelayedSingleton<PrintCupsClient>::GetInstance()->InitCupsResources();
    if (initCupsRet != ERR_OK) {
        return initCupsRet;
    }
#endif
    auto tmpState = state_;
    state_ = ServiceRunningState::STATE_RUNNING;
    if (!g_publishState) {
        if (!Publish(PrintServiceAbility::GetInstance())) {
            state_ = tmpState;
            PRINT_HILOGE("PrintServiceAbility Publish failed");
            return E_PRINT_SERVER_FAILURE;
        }
        g_publishState = true;
    }
    PrintCallerAppMonitor::GetInstance().StartCallerAppMonitor([this]() {
        return this->UnloadSystemAbility();
    });
    CheckCupsServerAlive();
    UpdatePpdForPreinstalledDriverPrinter();
    if (!printSystemData_.CheckPrinterVersionFile()) {
        RefreshPrinterInfoByPpd();
    }
    StartDiscoverPrinter();
    PRINT_HILOGI("state_ is %{public}d.Init PrintServiceAbility success.", static_cast<int>(state_));
    return ERR_OK;
}

void PrintServiceAbility::StartDiscoverPrinter()
{
    std::vector<PrintExtensionInfo> extensionInfos;
    QueryAllExtension(extensionInfos);
    std::vector<std::string> extensionIds;
    for (const auto &extensionInfo : extensionInfos) {
        extensionIds.emplace_back(extensionInfo.GetExtensionId());
    }
    StartDiscoverPrinter(extensionIds);
}

void PrintServiceAbility::UpdatePpdForPreinstalledDriverPrinter()
{
#ifdef CUPS_ENABLE
    std::vector<std::string> printerIdList = printSystemData_.QueryAddedPrinterIdList();
    for (auto &printerId : printerIdList) {
        PrinterInfo printerInfo;
        if (!printSystemData_.QueryAddedPrinterInfoByPrinterId(printerId, printerInfo)) {
            continue;
        }
        std::string printerMake = printerInfo.GetPrinterMake();
        if (printerMake.empty()) {
            PRINT_HILOGE("printer make empty");
            continue;
        }
        PRINT_HILOGD("CheckPrinterPpdUpdateRequired printerMake: %{public}s", printerMake.c_str());
        if (!IsPreinstalledDriverPrinter(printerInfo.GetPrinterName())) {
            PRINT_HILOGW("no need to update ppd");
            continue;
        }
        std::string ppdName = DEFAULT_PPD_NAME;
        if (!QueryPPDInformation(printerMake.c_str(), ppdName) || ppdName == DEFAULT_PPD_NAME) {
            PRINT_HILOGW("no ppd file for this printer");
            continue;
        }
        PRINT_HILOGI("CheckPrinterPpdUpdateRequired ppd driver: %{public}s", ppdName.c_str());

        std::string standardPrinterName = PrintUtil::StandardizePrinterName(printerInfo.GetPrinterName());
        std::string ppdHashCode = DelayedSingleton<PrintCupsClient>::GetInstance()->GetPpdHashCode(ppdName);
        if (printerInfo.GetPpdHashCode() == ppdHashCode) {
            PRINT_HILOGW("no need to update ppd");
            continue;
        }
        if (!DelayedSingleton<PrintCupsClient>::GetInstance()->ModifyCupsPrinterPpd(standardPrinterName, ppdName)) {
            PRINT_HILOGE("update cups printer ppd failed");
            continue;
        }
        printSystemData_.UpdatePpdHashCode(printerId, ppdHashCode);
        printSystemData_.SavePrinterFile(printerId);
    }
#endif
}

bool PrintServiceAbility::IsPreinstalledDriverPrinter(const std::string &printerName)
{
    for (auto &preinstalledMake: PREINSTALLED_DRIVER_PRINTER) {
        if (printerName.find(preinstalledMake) != std::string::npos) {
            PRINT_HILOGI("find target printer");
            return true;
        }
    }
    return false;
}

void PrintServiceAbility::CheckCupsServerAlive()
{
#ifdef CUPS_ENABLE
    int32_t retryCount = 0;
    while (retryCount < QUERY_CUPS_ALIVE_MAX_RETRY_TIMES) {
        if (DelayedSingleton<PrintCupsClient>::GetInstance()->IsCupsServerAlive()) {
            break;
        }
        ++retryCount;
        std::this_thread::sleep_for(std::chrono::milliseconds(QUERY_CUPS_ALIVE_INTERVAL));
    }
    PRINT_HILOGI("retryCount: %{public}d", retryCount);
#endif
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
    PrintCallerAppMonitor::GetInstance().AddCallerAppToMap();

    if (state_ != ServiceRunningState::STATE_RUNNING) {
        PRINT_HILOGI("PrintServiceAbility restart.");
        OnStart();
    } else {
#ifdef CUPS_ENABLE
        if (!DelayedSingleton<PrintCupsClient>::GetInstance()->IsCupsServerAlive()) {
            DelayedSingleton<PrintCupsClient>::GetInstance()->StartCupsdServiceNotAlive();
        }
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
    PrintCallerAppMonitor::GetInstance().IncrementPrintCounter("");
    PrintCallerAppMonitor::GetInstance().IncrementCallerAppCounter();
    int64_t callerTokenId = static_cast<int64_t>(IPCSkeleton::GetCallingTokenID());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto iter = printUserDataMap_.find(callerTokenId);
    if (iter == printUserDataMap_.end()) {
        auto userData = std::make_shared<PrintUserData>();
        if (userData != nullptr) {
            printUserDataMap_.insert(std::make_pair(callerTokenId, userData));
        }
    }
#ifdef CUPS_ENABLE
    return DelayedSingleton<PrintCupsClient>::GetInstance()->InitCupsResources();
#endif  // CUPS_ENABLE
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::StartPrint(
    const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList, std::string &taskId)
{
    return CallSpooler(fileList, fdList, taskId);
}

int32_t PrintServiceAbility::CallSpooler(
    const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList, std::string &taskId)
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
    PrintCallerAppMonitor::GetInstance().IncrementPrintCounter(taskId);
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::HandleExtensionConnectPrinter(const std::string &printerId)
{
    PRINT_HILOGI("HandleExtensionConnectPrinter begin");
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
    PRINT_HILOGI("HandleExtensionConnectPrinter end");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::ConnectPrinter(const std::string &printerId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("[Printer: %{public}s] ConnectPrinter started", PrintUtils::AnonymizePrinterId(printerId).c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    vendorManager.ClearConnectingPrinter();
    vendorManager.ClearConnectingProtocol();
    vendorManager.ClearConnectingPpdName();
    std::string oldPrinterId = SPOOLER_BUNDLE_NAME + PRINTER_ID_DELIMITER + MDNS_PRINTER;
    if (printerId.find(oldPrinterId) != std::string::npos && printSystemData_.IsPrinterAdded(printerId)) {
        PRINT_HILOGI("old version printerId, check connected successfully");
        return E_PRINT_NONE;
    }
    if (printSystemData_.QueryDiscoveredPrinterInfoById(printerId) == nullptr) {
        PRINT_HILOGI("Invalid printer id, try connect printer by ip");
        return TryConnectPrinterByIp(printerId);
    }
    printSystemData_.ClearPrintEvents(printerId, CONNECT_PRINT_EVENT_TYPE);
    vendorManager.SetConnectingPrinter(ID_AUTO, printerId);
    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    if (!vendorManager.ExtractVendorName(extensionId).empty()) {
        if (!vendorManager.ConnectPrinter(printerId)) {
            PRINT_HILOGE("Vendor not found");
            return E_PRINT_SERVER_FAILURE;
        }
        return E_PRINT_NONE;
    }
    if (PrintUtils::IsUsbPrinter(printerId)) {
        int32_t result = ConnectUsbPrinter(printerId);
        PRINT_HILOGI("[Printer: %{public}s] ConnectUsbPrinter end, result: %{public}d",
            PrintUtils::AnonymizePrinterId(printerId).c_str(), result);
        return result;
    }
    int32_t result = HandleExtensionConnectPrinter(printerId);
    PRINT_HILOGI("[Printer: %{public}s] ConnectPrinter end", PrintUtils::AnonymizePrinterId(printerId).c_str());
    return result;
}

int32_t PrintServiceAbility::DisconnectPrinter(const std::string &printerId)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGI("[Printer: %{public}s] DisconnectPrinter start", PrintUtils::AnonymizePrinterId(printerId).c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    if (printSystemData_.QueryDiscoveredPrinterInfoById(printerId) == nullptr) {
        PRINT_HILOGE("Invalid printer id");
        return E_PRINT_INVALID_PRINTER;
    }

    std::string extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_DISCONNECT_PRINTER);
    if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
        PRINT_HILOGW("[Printer: %{public}s] DisconnectPrinter Not Register Yet!!!",
            PrintUtils::AnonymizePrinterId(printerId).c_str());
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
    PRINT_HILOGI("DisconnectPrinter end");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::StartDiscoverPrinter(const std::vector<std::string> &extensionIds)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGI("StartDiscoverPrinter start.");

    int32_t callerPid = IPCSkeleton::GetCallingPid();
    std::string bundleName = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();

    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    std::lock_guard<std::recursive_mutex> discoveryLock(discoveryMutex_);
    StartDiscoveryCallerMonitorThread();

    discoveryCallerMap_.insert(std::make_pair(callerPid, bundleName));
    PRINT_HILOGI("Add discovery caller, pid: %{public}d, bundleName: %{public}s", callerPid, bundleName.c_str());

    vendorManager.ClearConnectingPrinter();
    vendorManager.ClearConnectingProtocol();
    vendorManager.ClearConnectingPpdName();
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
    PRINT_HILOGI("DelayStartDiscovery start, extensionId: %{public}s", extensionId.c_str());
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
    PRINT_HILOGI("DelayStartDiscovery end, extensionId: %{public}s", extensionId.c_str());
    return ret == E_PRINT_NONE;
}

int32_t PrintServiceAbility::StopDiscoverPrinter()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("StopDiscoverPrinter start.");

    int32_t callerPid = IPCSkeleton::GetCallingPid();

    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    std::lock_guard<std::recursive_mutex> discoveryLock(discoveryMutex_);

    auto iter = discoveryCallerMap_.find(callerPid);
    if (iter != discoveryCallerMap_.end()) {
        PRINT_HILOGI("Remove discovery caller, pid: %{public}d, bundleName: %{public}s",
                     callerPid, iter->second.c_str());
        discoveryCallerMap_.erase(iter);
    }
    PRINT_HILOGI("discoveryCallerMap size: %{public}lu", discoveryCallerMap_.size());

    if (!discoveryCallerMap_.empty()) {
        PRINT_HILOGI("Other discovery caller processes still discovering, keep discovery running.");
        return E_PRINT_NONE;
    }

    PRINT_HILOGI("All discovery callers stopped, stopping discovery");
    StopDiscoveryInternal();

    PRINT_HILOGI("StopDiscoverPrinter end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::DestroyExtension()
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("DestroyExtension start.");
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
    PRINT_HILOGI("DestroyExtension end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::AddRawPrinter(PrinterInfo &info)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("AddRawPrinter start.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());
    if (extensionId.find(RAW_PPD_DRIVER) != std::string::npos) {
        PRINT_HILOGD("QueryCallerBundleName error, contains RAW_PPD_DRIVER.");
        return E_PRINT_INVALID_EXTENSION;
    }
    std::string printerId = info.GetPrinterId();
    std::string globalPrinterId = PrintUtils::GetGlobalId(extensionId, printerId);
    std::string rawGlobalPrinterId = RAW_PPD_DRIVER + RAW_GLOBAL_ID_DELIMITER + globalPrinterId;
    PRINT_HILOGD("AddRawPrinter printerId = %{public}s", rawGlobalPrinterId.c_str());
    info.SetPrinterId(rawGlobalPrinterId);
    std::string printerName = RenamePrinterWhenAdded(info);
    PRINT_HILOGI("[Printer: %{public}s]", printerName.c_str());
    info.SetPrinterName(printerName);

    Json::Value optionJson;
    optionJson["driver"] = "RAW";
    int32_t ret = DelayedSingleton<PrintCupsClient>::GetInstance()->AddPrinterToCupsWithSpecificPpd(
        info.GetUri(), printerName, RAW_PPD_NAME);
    std::string option = PrintJsonUtil::WriteString(optionJson);
    PRINT_HILOGD("AddRawPrinter option: %{public}s", option.c_str());
    info.SetOption(option);

    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("Failed to add raw printer, ret = [%{public}d]", ret);
        return ret;
    }

    std::shared_ptr<PrinterInfo> infoptr = std::make_shared<PrinterInfo>(info);
    OnPrinterAddedToCups(infoptr, RAW_PPD_NAME);
    PRINT_HILOGI("AddRawPrinter success.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("QueryAllExtension start.");
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
    PRINT_HILOGI("QueryAllExtension end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryAllActivePrintJob(std::vector<PrintJob> &printJobs)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("QueryAllActivePrintJob start.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return E_PRINT_INVALID_USERID;
    }
    int32_t ret = userData->QueryAllActivePrintJob(printJobs);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("QueryAllActivePrintJob failed.");
        return ret;
    }
    PRINT_HILOGI("QueryAllActivePrintJob end, size: %{public}zu.", printJobs.size());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryAllPrintJob(std::vector<PrintJob> &printJobs)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("QueryAllPrintJob start.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return E_PRINT_INVALID_USERID;
    }
    int32_t ret = userData->QueryAllPrintJob(printSystemData_.QueryAddedPrinterIdList(), printJobs);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("QueryAllPrintJob failed.");
        return ret;
    }
    PRINT_HILOGI("QueryAllPrintJob end, size: %{public}zu.", printJobs.size());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryAddedPrinter(std::vector<std::string> &printerList)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("QueryAddedPrinter start.");
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
    PRINT_HILOGI("QueryAddedPrinter end, size: %{public}zu.", printerList.size());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryRawAddedPrinter(std::vector<std::string> &printerList)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    PRINT_HILOGD("QueryRawAddedPrinter started.");
    std::vector<std::string> printerNameList;
    printSystemData_.GetRawAddedPrinterListFromSystemData(printerNameList);
    if (printerNameList.size() <= 0) {
        PRINT_HILOGW("no added raw printerId");
        return E_PRINT_NONE;
    }
    for (uint32_t i = 0; i < printerNameList.size(); i++) {
        PRINT_HILOGD("QueryRawAddedPrinter in printerName %{public}s", printerNameList[i].c_str());
        std::string printerId = printSystemData_.QueryPrinterIdByStandardizeName(printerNameList[i]);
        PRINT_HILOGD("QueryRawAddedPrinter in printerId %{public}s", printerId.c_str());
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
    info.SetPrinterId(printerId);
    OHOS::Print::PrinterInfo printer;
    if (printSystemData_.QueryAddedPrinterInfoByPrinterId(printerId, printer)) {
        info = printer;
    } else {
        std::string extensionId = PrintUtils::GetExtensionId(printerId);
        if (!vendorManager.ExtractVendorName(extensionId).empty()) {
            return QueryVendorPrinterInfo(printerId, info);
        }
        int32_t ret = DelayedSingleton<PrintCupsClient>::GetInstance()->QueryPrinterInfoByPrinterId(printerId, info);
        if (ret != 0) {
            PRINT_HILOGE("cups QueryPrinterInfoByPrinterId fail, ret = %{public}d", ret);
            return E_PRINT_INVALID_PRINTER;
        }
    }
    PRINT_HILOGI("[Printer: %{public}s] QueryPrinterInfoByPrinterId printerStatus: %{public}d",
        PrintUtils::AnonymizePrinterId(printerId).c_str(), info.GetPrinterStatus());
    if (CheckIsDefaultPrinter(printerId)) {
        info.SetIsDefaultPrinter(true);
    }
    if (CheckIsLastUsedPrinter(printerId)) {
        info.SetIsLastUsedPrinter(true);
    }
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryPrinterProperties(
    const std::string &printerId, const std::vector<std::string> &keyList, std::vector<std::string> &valueList)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    PRINT_HILOGI("[Printer: %{public}s] QueryPrinterProperties", PrintUtils::AnonymizePrinterId(printerId).c_str());
    PrinterInfo printerInfo;
    uint32_t ret = QueryPrinterInfoByPrinterId(printerId, printerInfo);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGW("no printerInfo");
        return E_PRINT_INVALID_PRINTER;
    }
    PRINT_HILOGD("printerInfo %{public}s", printerInfo.GetPrinterName().c_str());
    for (auto &key : keyList) {
        PRINT_HILOGD("QueryPrinterProperties key %{public}s", key.c_str());
        if (key == "printerPreference" && printerInfo.HasPreferences()) {
            PrinterPreferences preferences;
            printerInfo.GetPreferences(preferences);
            Json::Value preferencesJson = preferences.ConvertToJson();
            valueList.emplace_back(PrintJsonUtil::WriteString(preferencesJson));
            PRINT_HILOGD("getPrinterPreference success");
        }
    }
    PRINT_HILOGI("QueryPrinterProperties valueList size: %{public}zu", valueList.size());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryPrintJobById(std::string &printJobId, PrintJob &printJob)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("[Job Id: %{public}s] QueryPrintJobById start", printJobId.c_str());
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
    PRINT_HILOGI("QueryPrintJobById end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::AddPrinterToCups(
    const std::string &printerUri, const std::string &printerName, const std::string &printerMake)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("[Printer: %{public}s] AddPrinterToCups start, printerUri: %{public}s, printerMake: %{public}s.",
        printerName.c_str(), PrintUtils::AnonymizePrinterUri(printerUri).c_str(), printerMake.c_str());
#ifdef CUPS_ENABLE
    auto ret = DelayedSingleton<PrintCupsClient>::GetInstance()->AddPrinterToCups(printerUri, printerName, printerMake);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGW("AddPrinterToCups error = %{public}d.", ret);
        return ret;
    }
#endif  // CUPS_ENABLE
    PRINT_HILOGI("AddPrinterToCups end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryPrinterCapabilityByUri(
    const std::string &printerUri, const std::string &printerId, PrinterCapability &printerCaps)
{
    {
        std::lock_guard<std::recursive_mutex> lock(apiMutex_);
        ManualStart();
        if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
            PRINT_HILOGE("no permission to access print service");
            return E_PRINT_NO_PERMISSION;
        }
    }
    PRINT_HILOGI("QueryPrinterCapabilityByUri start.");
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    std::string standardizeId = printerId;
    if (standardizeId.find(extensionId) == std::string::npos && vendorManager.ExtractVendorName(printerId).empty()) {
        standardizeId = PrintUtils::GetGlobalId(extensionId, printerId);
    }
    PRINT_HILOGI("[Printer: %{public}s] extensionId = %{public}s",
        PrintUtils::AnonymizePrinterId(standardizeId).c_str(), extensionId.c_str());
#ifdef CUPS_ENABLE
    if (printerUri.length() > SERIAL_LENGTH && printerUri.substr(INDEX_ZERO, INDEX_THREE) == USB_PRINTER) {
        auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(standardizeId);
        if (printerInfo == nullptr) {
            PRINT_HILOGE("can not find the printer");
            return E_PRINT_INVALID_PRINTER;
        }
        if (!printerInfo->HasPrinterMake()) {
            PRINT_HILOGW("can not find printerMake");
            return E_PRINT_INVALID_PRINTER;
        }
        std::string make = printerInfo->GetPrinterMake();
        auto ret = DelayedSingleton<PrintCupsClient>::GetInstance()->AddPrinterToCups(
            printerUri, printerInfo->GetPrinterName(), make);
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("AddPrinterToCups error = %{public}d.", ret);
            return ret;
        }
        std::string ppdName;
        QueryPPDInformation(make, ppdName);
        DelayedSingleton<PrintCupsClient>::GetInstance()->QueryPrinterCapabilityFromPPD(
            printerInfo->GetPrinterName(), printerCaps, ppdName);
    } else {
        DelayedSingleton<PrintCupsClient>::GetInstance()->QueryPrinterCapabilityByUri(
            printerUri, printerId, printerCaps);
    }
#endif  // CUPS_ENABLE
    PRINT_HILOGI("QueryPrinterCapabilityByUri end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::SetPrinterPreference(const std::string &printerId, const PrinterPreferences &preferences)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    PRINT_HILOGI("SetPrinterPreference start.");
    preferences.Dump();
    printSystemData_.UpdatePrinterPreferences(printerId, preferences);
    printSystemData_.SavePrinterFile(printerId);
    PrinterInfo printerInfo;
    if (!printSystemData_.QueryAddedPrinterInfoByPrinterId(printerId, printerInfo)) {
        PRINT_HILOGW("cannot find printer info by printerId");
        return E_PRINT_INVALID_PRINTER;
    }
    SendPrinterEventChangeEvent(PRINTER_EVENT_INFO_CHANGED, printerInfo);
    PRINT_HILOGI("SetPrinterPreference end.");
    return E_PRINT_NONE;
}

bool PrintServiceAbility::QueryAddedPrinterInfoByPrinterId(const std::string &printerId, PrinterInfo &printer)
{
    if (printSystemData_.QueryAddedPrinterInfoByPrinterId(printerId, printer)) {
        return true;
    }

    if (printerId.find(P2P_PRINTER) != std::string::npos) {
        auto printerInfoPtr = printSystemData_.QueryDiscoveredPrinterInfoById(printerId);
        if (printerInfoPtr != nullptr) {
            printer = *printerInfoPtr;
            return true;
        }
    }
    return false;
}

bool PrintServiceAbility::UpdatePrintJobOptionByPrinterId(PrintJob &printJob)
{
    PRINT_HILOGI("UpdatePrintJobOptionByPrinterId start.");
    PrinterInfo printerInfo;
    if (!QueryAddedPrinterInfoByPrinterId(printJob.GetPrinterId(), printerInfo)) {
        PRINT_HILOGW("cannot find printer info by printerId");
        return false;
    }
    std::string oldOption = printJob.GetOption();
    PRINT_HILOGD("Print job option: %{public}s", oldOption.c_str());
    Json::Value infoJson;
    if (!PrintJsonUtil::Parse(oldOption, infoJson)) {
        PRINT_HILOGW("old option not accepted");
        return false;
    }
    infoJson["printerName"] = printerInfo.GetPrinterName();
    infoJson["printerUri"] = printerInfo.GetUri();
    infoJson["alias"] = printerInfo.GetAlias();
    infoJson["printerMake"] = printerInfo.GetPrinterMake();
    UpdatePrintJobOptionWithPrinterPreferences(infoJson, printerInfo);

    PrintPageSize pageSize;
    printJob.GetPageSize(pageSize);
    UpdatePageSizeNameWithPrinterInfo(printerInfo, pageSize);
    printJob.SetPageSize(pageSize);
    std::string updatedOption = PrintJsonUtil::WriteString(infoJson);
    PRINT_HILOGD("Updated print job option: %{public}s", updatedOption.c_str());
    printJob.SetOption(updatedOption);
    return true;
}

std::shared_ptr<PrintJob> PrintServiceAbility::AddNativePrintJob(const std::string &jobId, PrintJob &printJob)
{
    PRINT_HILOGI("[Job Id: %{public}s] AddNativePrintJob", jobId.c_str());
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

#ifdef EDM_SERVICE_ENABLE
bool PrintServiceAbility::IsDisablePrint()
{
    bool isDisabled = false;
    OHOS::EDM::EnterpriseDeviceMgrProxy enterpriseDeviceMgrProxy;
    enterpriseDeviceMgrProxy.IsPolicyDisabled(NULL, JOB_BANNED_POLICY_CODE, isDisabled);
    PRINT_HILOGI("edm service result: %{public}d", isDisabled);
    return isDisabled;
}
#endif // EDM_SERVICE_ENABLE

int32_t PrintServiceAbility::StartNativePrintJob(PrintJob &printJob)
{
    PRINT_HILOGI("StartNativePrintJob start.");
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
    std::string callerPkg = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    ingressPackage = callerPkg;
    PRINT_HILOGE("ingressPackage is %{public}s", ingressPackage.c_str());
    std::string param = nativePrintJob->ConvertToJsonString();
    HisysEventUtil::reportBehaviorEvent(ingressPackage, HisysEventUtil::SEND_TASK, param);
    if (CheckPrintConstraint(printJob.GetOption(), printJob.GetJobId())) {
        PRINT_HILOGE("user is not allow print job");
        return E_PRINT_NO_PERMISSION;
    }
#ifdef EDM_SERVICE_ENABLE
    if (IsDisablePrint() && printJob.GetPrinterId() != VIRTUAL_PRINTER_ID) {
        ReportEventAndUpdateJobState(printJob.GetOption(), printJob.GetJobId());
        return E_PRINT_BANNED;
    }
#endif // EDM_SERVICE_ENABLE
    return StartPrintJobInternal(nativePrintJob);
}

#ifdef EDM_SERVICE_ENABLE
void PrintServiceAbility::ReportEventAndUpdateJobState(std::string option, std::string jobId)
{
    ReportBannedEvent(option);
    UpdatePrintJobState(jobId, PRINT_JOB_BLOCKED, PRINT_JOB_BLOCKED_BANNED);
    CallStatusBar();
}
#endif // EDM_SERVICE_ENABLE

#ifdef EDM_SERVICE_ENABLE
int32_t PrintServiceAbility::ReportBannedEvent(std::string option)
{
    PRINT_HILOGW("current print job has been banned by organization");
    Json::Value infoJson;
    std::string reportFileName = "";
    if (!PrintJsonUtil::Parse(option, infoJson)) {
        PRINT_HILOGE("report banned event failed, option not accepted");
        return E_PRINT_INVALID_PARAMETER;
    }
    reportFileName = infoJson["jobName"].asString();
    auto nowTime = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(nowTime.time_since_epoch()).count();
    std::stringstream ss;
    ss << timestamp;
    Json::Value contentJson;
    contentJson["bundlename"] = SPOOLER_BUNDLE_NAME;
    contentJson["filePath"] = reportFileName;
    contentJson["happenTime"] = ss.str();
    std::string content = PrintJsonUtil::WriteString(contentJson);
    OHOS::Security::SecurityGuard::EventInfo eventInfo(JOB_BANNED_EVENTID, JOB_BANNED_VERSION, content);
    OHOS::Security::SecurityGuard::NativeDataCollectKit nativeDataCollectKit;
    auto wrappedInfo = std::make_shared<OHOS::Security::SecurityGuard::EventInfo>(eventInfo);
    int32_t reportResult = nativeDataCollectKit.ReportSecurityInfo(wrappedInfo);
    PRINT_HILOGI("report security result: %{public}d", reportResult);
    return reportResult;
}
#endif // EDM_SERVICE_ENABLE

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
    PRINT_HILOGI("[Job Id: %{public}s] set job state to PRINT_JOB_QUEUED, [Printer: %{public}s]",
        jobId.c_str(), PrintUtils::AnonymizePrinterId(printerId).c_str());
    printJob->SetJobState(PRINT_JOB_QUEUED);
    UpdateQueuedJobList(jobId, printJob);
    printerJobMap_[printerId].insert(std::make_pair(jobId, true));
    if (CheckPrintConstraint(jobInfo.GetOption(), jobInfo.GetJobId())) {
        PRINT_HILOGE("user is not allow print job");
        return E_PRINT_NO_PERMISSION;
    }
#ifdef EDM_SERVICE_ENABLE
    if (IsDisablePrint() && jobInfo.GetPrinterId() != VIRTUAL_PRINTER_ID) {
        ReportEventAndUpdateJobState(jobInfo.GetOption(), jobInfo.GetJobId());
        return E_PRINT_BANNED;
    }
#endif // EDM_SERVICE_ENABLE
    return StartPrintJobInternal(printJob);
}

int32_t PrintServiceAbility::RestartPrintJob(const std::string &jobId)
{
    startPrintTime_ = std::chrono::high_resolution_clock::now();
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    // is restratable printJob & get jobinfo
    auto printJob = std::make_shared<PrintJob>();
    int32_t ret = QueryQueuedPrintJobById(jobId, *printJob);
    if (ret != E_PRINT_NONE) {
        ret = QueryHistoryPrintJobById(jobId, *printJob);
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Invalid job id.");
            return ret;
        }
    }

    // reopen fd from cache
    std::vector<uint32_t> fdList;
    OpenCacheFileFd(jobId, fdList);
    if (fdList.empty()) {
        PRINT_HILOGE("not find cache file");
        return E_PRINT_FILE_IO;
    }
    printJob->SetJobId(PrintUtils::GetPrintJobId());
    PRINT_HILOGI("[Job Id: %{public}s] RestartPrintJob", printJob->GetJobId().c_str());
    printJob->SetFdList(fdList);

    // start new printjob
    PRINT_HILOGI("set job state to PRINT_JOB_QUEUED");
    printJob->SetJobState(PRINT_JOB_QUEUED);
    AddToPrintJobList(printJob->GetJobId(), printJob);
    UpdateQueuedJobList(printJob->GetJobId(), printJob);
    printerJobMap_[printJob->GetPrinterId()].insert(std::make_pair(jobId, true));
    if (CheckPrintConstraint(printJob->GetOption(), jobId)) {
        PRINT_HILOGE("user is not allow print job");
        return E_PRINT_NO_PERMISSION;
    }
#ifdef EDM_SERVICE_ENABLE
    if (IsDisablePrint() && printJob->GetPrinterId() != VIRTUAL_PRINTER_ID) {
        ReportEventAndUpdateJobState(printJob->GetOption(), jobId);
        return E_PRINT_BANNED;
    }
#endif // EDM_SERVICE_ENABLE
    ret = StartPrintJobInternal(printJob);
    if (ret == E_PRINT_NONE) {
        PRINT_HILOGI("[Job Id: %{public}s] RestartPrintJob success, oldJobId: %{public}s",
            printJob->GetJobId().c_str(), jobId.c_str());
        CancelPrintJob(jobId);
    }
    return ret;
}

bool PrintServiceAbility::CheckPrintJob(PrintJob &jobInfo)
{
    PRINT_HILOGI("[Job Id: %{public}s] CheckPrintJob start", jobInfo.GetJobId().c_str());
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
    PRINT_HILOGI("[Job Id: %{public}s] enter UpdateQueuedJobList", jobId.c_str());
    RegisterSettingDataObserver();
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
    if (userId == INVALID_USER_ID) {
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
    PRINT_HILOGI("[Printer: %{public}s] SetLastUsedPrinter start", PrintUtils::AnonymizePrinterId(printerId).c_str());
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
    PRINT_HILOGI("[Job Id: %{public}s] Start send task to Extension PrintJob", jobId.c_str());
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
    PRINT_HILOGI("[Job Id: %{public}s] CancelPrintJob start", jobId.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return E_PRINT_INVALID_USERID;
    }
    auto printJob = std::make_shared<PrintJob>();
    auto jobIt = userData->queuedJobList_.find(jobId);
    if (jobIt == userData->queuedJobList_.end()) {
        if (QueryHistoryPrintJobById(jobId, *printJob) != E_PRINT_NONE) {
            PRINT_HILOGE("invalid job id");
            return E_PRINT_INVALID_PRINTJOB;
        }
    } else {
        printJob = jobIt->second;
    }
    if (printJob->GetJobState() >= PRINT_JOB_QUEUED) {
        std::string extensionId = PrintUtils::GetExtensionId(printJob->GetPrinterId());
        std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_CANCEL_PRINT);
        if (cid.find(PRINT_EXTENSION_BUNDLE_NAME) == string::npos) {
#ifdef CUPS_ENABLE
            DelayedSingleton<PrintCupsClient>::GetInstance()->CancelCupsJob(printJob->GetJobId());
#endif  // CUPS_ENABLE
            return E_PRINT_NONE;
        }
        if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
            PRINT_HILOGW("CancelPrintJob Not Register Yet!!!");
            UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED, PRINT_JOB_COMPLETED_CANCELLED);
            return E_PRINT_SERVER_FAILURE;
        }
        CancelPrintJobHandleCallback(userData, extCallbackMap_.find(cid)->second, jobId);
    } else {
        SetPrintJobCanceled(*printJob);
    }
    PRINT_HILOGI("[Job Id: %{public}s] CancelPrintJob end", jobId.c_str());
    return E_PRINT_NONE;
}

void PrintServiceAbility::CancelPrintJobHandleCallback(
    const std::shared_ptr<PrintUserData> userData, const sptr<IPrintExtensionCallback> cbFunc, const std::string &jobId)
{
    PRINT_HILOGI("[Job Id: %{public}s] CancelPrintJobHandleCallback start", jobId.c_str());
    auto tmpPrintJob = userData->queuedJobList_[jobId];
    auto callback = [=]() {
        if (cbFunc != nullptr && cbFunc->OnCallback(*tmpPrintJob) == false) {
            UpdatePrintJobState(jobId, PRINT_JOB_COMPLETED, PRINT_JOB_COMPLETED_CANCELLED);
        } else {
            PRINT_HILOGE("Callback function is null or callback failed.");
        }
    };
    if (helper_->IsSyncMode()) {
        callback();
    } else {
        serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    }
}

int32_t PrintServiceAbility::BlockPrintJob(const std::string &jobId)
{
    PRINT_HILOGI("[Job Id: %{public}s] BlockPrintJob start", jobId.c_str());
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

    PrintCupsClient::GetInstance()->InterruptCupsJob(jobId);
    PRINT_HILOGI("UpdatePrintJobState PRINT_JOB_BLOCKED");
    return E_PRINT_NONE;
}

void PrintServiceAbility::SetPrintJobCanceled(PrintJob &jobinfo)
{
    PRINT_HILOGI("[Job Id: %{public}s] SetPrintJobCanceled start", jobinfo.GetJobId().c_str());
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
    PRINT_HILOGI("CancelUserPrintJobs start, userId: %{public}d", userId);
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto removedUser = printUserMap_.find(userId);
    if (removedUser == printUserMap_.end()) {
        PRINT_HILOGE("User dose not exist.");
        return;
    }
    if (removedUser->second == nullptr) {
        PRINT_HILOGE("PrintUserData is nullptr.");
        return;
    }
    for (auto jobIt : removedUser->second->queuedJobList_) {
        PRINT_HILOGI("[Job Id: %{public}s] CancelUserPrintJobs", jobIt.first.c_str());
        int32_t ret = CancelPrintJob(jobIt.first);
        PRINT_HILOGI("CancelUserPrintJobs CancelPrintJob ret: %{public}d", ret);
        userJobMap_.erase(jobIt.first);
    }
    printUserMap_.erase(userId);
    PRINT_HILOGI("remove user-%{public}d success.", userId);
}

void PrintServiceAbility::BlockUserPrintJobs(const int32_t userId)
{
    PRINT_HILOGI("BlockUserPrintJobs start, userId: %{public}d", userId);
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto blockUser = printUserMap_.find(userId);
    if (blockUser == printUserMap_.end()) {
        PRINT_HILOGE("User dose not exist.");
        return;
    }
    if (blockUser->second == nullptr) {
        PRINT_HILOGE("PrintUserData is nullptr.");
        return;
    }
    for (auto jobIt : blockUser->second->queuedJobList_) {
        int32_t ret = BlockPrintJob(jobIt.first);
        PRINT_HILOGI("BlockUserPrintJobs BlockPrintJob ret: %{public}d", ret);
    }
    PRINT_HILOGI("block user-%{public}d success.", userId);
}

void PrintServiceAbility::NotifyCurrentUserChanged(const int32_t userId)
{
    PRINT_HILOGD("NotifyAppCurrentUserChanged begin");
    if (userId == INVALID_USER_ID) {
        currentUserId_ = GetCurrentUserId();
    } else {
        currentUserId_ = userId;
    }
    PRINT_HILOGI("currentUserId_ is: %{public}d", currentUserId_);
    auto userData = GetUserDataByUserId(currentUserId_);
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return;
    }
    auto status = DetermineUserJobStatus(userData->queuedJobList_);

    switch (status) {
        case PRINT_JOB_BLOCKED:
            CallStatusBar();
            NotifyAppJobQueueChanged(QUEUE_JOB_LIST_BLOCKED);
            break;
        case PRINT_JOB_COMPLETED:
            NotifyAppJobQueueChanged(QUEUE_JOB_LIST_HIDE);
            break;
        case PRINT_JOB_RUNNING:
            CallStatusBar();
            NotifyAppJobQueueChanged(QUEUE_JOB_LIST_PRINTING);
            break;
        default:
            break;
    }
    PRINT_HILOGD("NotifyAppCurrentUserChanged end");
}

bool PrintServiceAbility::SendQueuePrintJob(const std::string &printerId)
{
    if (printerJobMap_[printerId].empty()) {
        return false;
    }

    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return false;
    }
    auto jobId = printerJobMap_[printerId].begin()->first;
    auto jobIt = userData->queuedJobList_.find(jobId);
    if (jobIt == userData->queuedJobList_.end()) {
        PRINT_HILOGE("[Job Id: %{public}s] invalid print job", jobId.c_str());
        return false;
    }

    if (jobIt->second->GetJobState() != PRINT_JOB_PREPARED) {
        PRINT_HILOGE("[Job Id: %{public}s] job state isn't prepared", jobId.c_str());
        return false;
    }

    auto extensionId = PrintUtils::GetExtensionId(printerId);
    std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
#ifdef CUPS_ENABLE
    if (cid.find(PRINT_EXTENSION_BUNDLE_NAME) != string::npos) {
        PRINT_HILOGW("not eprint extension, no need SendQueuePrintJob");
        return false;
    }
#endif  // CUPS_ENABLE

    auto cbFunc = extCallbackMap_[cid];
    auto printJob = jobIt->second;
    auto callback = [=]() {
        PRINT_HILOGI("[Job Id: %{public}s] Start Next Print Job", jobId.c_str());
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
    return true;
}

bool PrintServiceAbility::CheckPrinterUriDifferent(const std::shared_ptr<PrinterInfo> &info)
{
    PrinterInfo addedPrinter;
    if (printSystemData_.QueryAddedPrinterInfoByPrinterId(info->GetPrinterId(), addedPrinter)) {
        std::string printerUri = info->GetUri();
        if (!printerUri.empty() && printerUri != addedPrinter.GetUri()) {
            PRINT_HILOGI("[Printer: %{public}s] CheckPrinterUriDifferent success", info->GetPrinterName().c_str());
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
    PRINT_HILOGI("AddPrinters started. Total size is %{public}zd", printSystemData_.GetDiscoveredPrinterCount());

    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGI("Add printer extensionId = %{public}s", extensionId.c_str());
    for (auto &info : printerInfos) {
        AddSinglePrinterInfo(info, extensionId);
    }
    PRINT_HILOGI("AddPrinters end. Total size is %{public}zd", printSystemData_.GetDiscoveredPrinterCount());
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
    PRINT_HILOGI("RemovePrinters started. Total size is %{public}zd", printSystemData_.GetDiscoveredPrinterCount());
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());

    bool anyPrinterRemoved = false;
    for (const auto &printerId : printerIds) {
        std::string globalPrinterId = PrintUtils::GetGlobalId(extensionId, printerId);
        PRINT_HILOGI("[Printer: %{public}s] RemovePrinters", PrintUtils::AnonymizePrinterId(globalPrinterId).c_str());

        if (RemoveSinglePrinterInfo(globalPrinterId)) {
            anyPrinterRemoved = true;
        }
    }
    if (!anyPrinterRemoved) {
        PRINT_HILOGE("Invalid printer ids");
        return E_PRINT_INVALID_PARAMETER;
    }
    PRINT_HILOGI("RemovePrinters end. Total size is %{public}zd", printSystemData_.GetDiscoveredPrinterCount());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::UpdatePrinters(const std::vector<PrinterInfo> &printerInfos)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGI("UpdatePrinters started. Total size is %{public}zd", printSystemData_.GetDiscoveredPrinterCount());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());

    for (const auto &info : printerInfos) {
        UpdateSinglePrinterInfo(info, extensionId);
    }
    PRINT_HILOGI("UpdatePrinters end. Total size is %{private}zd", printSystemData_.GetDiscoveredPrinterCount());
    return E_PRINT_NONE;
}

bool PrintServiceAbility::UpdatePrinterCapability(const std::string &printerId, const PrinterInfo &info)
{
    if (printerId.find(P2P_PRINTER) != std::string::npos) {
        PRINT_HILOGD("The printer is p2p: %{private}s", printerId.c_str());
        return true;
    }
    PRINT_HILOGI("UpdatePrinterCapability Enter");
    PrinterInfo printerInfo(info);
    printerInfo.SetPrinterStatus(PRINTER_STATUS_IDLE);
    printerInfo.SetPrinterId(printerId);
    if (!printSystemData_.IsPrinterAdded(printerId)) {
        BuildPrinterPreference(printerInfo);
        printSystemData_.InsertAddedPrinter(printerId, printerInfo);
        SendPrinterEventChangeEvent(PRINTER_EVENT_ADDED, printerInfo, true);
        SendPrinterChangeEvent(PRINTER_EVENT_ADDED, printerInfo);
    } else {
        PRINT_HILOGW("Printer added.");
    }
    SendPrinterEventChangeEvent(PRINTER_EVENT_LAST_USED_PRINTER_CHANGED, printerInfo);
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
    PRINT_HILOGI("[Printer: %{public}s] UpdatePrinterState started, state: [%{public}d]",
        PrintUtils::AnonymizePrinterId(printerExtId).c_str(), state);
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

int32_t PrintServiceAbility::UpdatePrintJobStateForNormalApp(
    const std::string &jobId, uint32_t state, uint32_t subState)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    return UpdatePrintJobState(jobId, state, subState);
}

int32_t PrintServiceAbility::UpdatePrintJobStateOnlyForSystemApp(
    const std::string &jobId, uint32_t state, uint32_t subState)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
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
    PRINT_HILOGI("[Job Id: %{public}s] CheckAndSendQueuePrintJob start", jobId.c_str());
    auto userData = GetUserDataByJobId(jobId);
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return E_PRINT_INVALID_USERID;
    }
    auto printJob = std::make_shared<PrintJob>();
    auto jobIt = userData->queuedJobList_.find(jobId);
    bool jobInQueue = true;
    if (jobIt == userData->queuedJobList_.end()) {
        jobInQueue = false;
        if (QueryHistoryPrintJobById(jobId, *printJob) != E_PRINT_NONE) {
            PRINT_HILOGD("Invalid print job id");
            return E_PRINT_INVALID_PRINTJOB;
        }
    } else {
        printJob = jobIt->second;
    }
    printJob->SetJobState(state);
    printJob->SetSubState(subState);
    if (state == PRINT_JOB_BLOCKED) {
        AddPrintJobToHistoryList(printJob);
    }
    SendPrintJobEvent(*printJob);
    notifyAdapterJobChanged(jobId, state, subState);
    CheckJobQueueBlocked(*printJob);

    auto printerId = printJob->GetPrinterId();
    if (state == PRINT_JOB_COMPLETED) {
        if (jobInQueue) {
            ClosePrintJobFd(jobIt->second);  // Close fd dependency primitive class.
            DeleteCacheFileFromUserData(jobId);
            printerJobMap_[printerId].erase(jobId);
            userData->queuedJobList_.erase(jobId);
            queuedJobList_.erase(jobId);
        }
        DeletePrintJobFromHistoryList(jobId);
        ReportPrinterIdle(printerId);
        if (IsQueuedJobListEmpty(jobId)) {
            ReportCompletedPrint(printerId);
        }
        SendQueuePrintJob(printerId);
        PrintCallerAppMonitor::GetInstance().RemovePrintJobFromMap(jobId);
    }
    PRINT_HILOGD("CheckAndSendQueuePrintJob end.");
    return E_PRINT_NONE;
}

void PrintServiceAbility::ClosePrintJobFd(const std::shared_ptr<PrintJob> &printJob)
{
    if (printJob == nullptr) {
        PRINT_HILOGE("printJob is nullptr.");
        return;
    }
    std::vector<uint32_t> fdList;
    printJob->GetFdList(fdList);
    for (uint32_t fd : fdList) {
        PRINT_HILOGI("close fd: %{public}d", fd);
        if (static_cast<int32_t>(fd) < 0 || close(fd) == -1) {
            PRINT_HILOGW("Invalid fd.");
        }
    }
    printJob->SetFdList(std::vector<uint32_t>());
}

void PrintServiceAbility::ReportPrinterIdle(const std::string &printerId)
{
    auto iter = printerJobMap_.find(printerId);
    if (iter == printerJobMap_.end() || iter->second.empty()) {
        auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(printerId);
        if (printerInfo == nullptr) {
            printerInfo = DelayedSingleton<PrintCupsClient>::GetInstance()->QueryUsbPrinterInfoByPrinterId(printerId);
        }
        if (printerInfo != nullptr) {
            printerInfo->SetPrinterStatus(PRINTER_STATUS_IDLE);
            printSystemData_.UpdatePrinterStatus(printerId, PRINTER_STATUS_IDLE);
            SendPrinterEventChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
            SendPrinterChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
        }
    }
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
}

void PrintServiceAbility::NotifyAppJobQueueChanged(const std::string &applyResult)
{
    PRINT_HILOGD("NotifyAppJobQueueChanged started. %{public}s ", applyResult.c_str());
    AAFwk::Want want;
    want.SetAction(ACTION_QUEUE_JOB_LIST_CHANGED);
    want.SetParam(QUEUE_JOB_LIST_CHANGED, applyResult);
    EventFwk::CommonEventData commonData{want};
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

    PRINT_HILOGD("UpdateExtensionInfo started. %{public}s, extInfo [%{public}s]", extensionId.c_str(), extInfo.c_str());
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
    PRINT_HILOGI("[Printer: %{public}s] QueryPrinterCapability started",
        PrintUtils::AnonymizePrinterId(printerId).c_str());
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

    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    PRINT_HILOGI("[Job Id: %{public}s] NotifyPrintServiceEvent, event: %{public}d", jobId.c_str(), event);
    switch (event) {
        case APPLICATION_CREATED:
            if (printJobList_.find(jobId) == printJobList_.end()) {
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
            PrintCallerAppMonitor::GetInstance().IncrementPrintCounter(jobId);
            break;
        case APPLICATION_CLOSED_FOR_STARTED:
            PrintCallerAppMonitor::GetInstance().DecrementPrintCounter(jobId);
            break;
        case APPLICATION_CLOSED_FOR_CANCELED:
            UnregisterPrintTaskCallback(jobId, PRINT_JOB_SPOOLER_CLOSED, PRINT_JOB_SPOOLER_CLOSED_FOR_CANCELED);
            PrintCallerAppMonitor::GetInstance().DecrementPrintCounter(jobId);
            break;
        default:
            PRINT_HILOGW("unsupported event");
            break;
    }
    return E_PRINT_NONE;
}

bool PrintServiceAbility::UnloadSystemAbility()
{
    {
        std::lock_guard<std::recursive_mutex> lock(apiMutex_);
        if (!queuedJobList_.empty()) {
            PRINT_HILOGE("There are still print jobs being executed.");
            return false;
        }
    }
    PRINT_HILOGI("unload task begin");
    NotifyAppJobQueueChanged(QUEUE_JOB_LIST_UNSUBSCRIBE);
    int32_t ret = DestroyExtension();
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("DestroyExtension failed.");
        return false;
    }
#ifdef CUPS_ENABLE
#ifdef ENTERPRISE_ENABLE
    if (IsEnterpriseEnable() && IsEnterprise()) {
        DelayedSingleton<PrintCupsClient>::GetInstance()->StopCupsdEnterpriseService();
    } else {
#endif  // ENTERPRISE_ENABLE
        DelayedSingleton<PrintCupsClient>::GetInstance()->StopCupsdService();
#ifdef ENTERPRISE_ENABLE
    }
#endif  // ENTERPRISE_ENABLE
#endif  // CUPS_ENABLE
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        PRINT_HILOGE("get samgr failed");
        return false;
    }
    ret = samgrProxy->UnloadSystemAbility(PRINT_SERVICE_ID);
    if (ret != ERR_OK) {
        PRINT_HILOGE("unload print system ability failed");
        return false;
    }
    PRINT_HILOGI("unload print system ability successfully");
    return true;
}

void PrintServiceAbility::DiscoveryCallerAppsMonitor()
{
    PRINT_HILOGI("start monitor discovery caller apps");
    bool running = true;
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(CHECK_CALLER_APP_INTERVAL));
        std::lock_guard<std::recursive_mutex> discoveryLock(discoveryMutex_);

        for (auto iter = discoveryCallerMap_.begin(); iter != discoveryCallerMap_.end();) {
            PRINT_HILOGI(
                "check discovery caller process, pid: %{public}d, bundleName: %{public}s",
                iter->first, iter->second.c_str());
            if (IsAppAlive(iter->second, iter->first)) {
                PRINT_HILOGI("discovery caller app still alive");
                ++iter;
            } else {
                PRINT_HILOGI("discovery caller app not alive, erase it");
                iter = discoveryCallerMap_.erase(iter);
            }
        }
        PRINT_HILOGI("discoveryCallerMap size: %{public}lu", discoveryCallerMap_.size());

        if (discoveryCallerMap_.empty()) {
            PRINT_HILOGI("All discovery caller apps exited, stopping discovery");
            StopDiscoveryInternal();
            discoveryCallerMonitorThread = false;
            running = false;
        }
    }
    PRINT_HILOGI("DiscoveryCallerAppsMonitor thread exited");
}

void PrintServiceAbility::StopDiscoveryInternal()
{
    PRINT_HILOGI("StopDiscoveryInternal start.");
    vendorManager.StopDiscovery();
    vendorManager.StopStatusMonitor();
    printSystemData_.ClearDiscoveredPrinterList();
    for (auto extension : extensionStateList_) {
        if (extension.second < PRINT_EXTENSION_LOADING) {
            continue;
        }
        extension.second = PRINT_EXTENSION_UNLOAD;
        std::string cid = PrintUtils::EncodeExtensionCid(extension.first, PRINT_EXTCB_STOP_DISCOVERY);
        if (extCallbackMap_.find(cid) == extCallbackMap_.end()) {
            PRINT_HILOGE("StopDiscoveryInternal Not Register, BUT State is LOADED");
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
    PRINT_HILOGI("StopDiscoveryInternal end.");
}

void PrintServiceAbility::StartDiscoveryCallerMonitorThread()
{
    std::lock_guard<std::recursive_mutex> discoveryLock(discoveryMutex_);
    if (!discoveryCallerMonitorThread) {
        PRINT_HILOGI("start discovery caller monitor thread");
        discoveryCallerMonitorThread = true;
        std::thread startDiscoveryCallerMonitorThread([this] { this->DiscoveryCallerAppsMonitor(); });
        startDiscoveryCallerMonitorThread.detach();
    }
}

void PrintServiceAbility::DelayEnterLowPowerMode()
{
    PRINT_HILOGI("delay enter low power mode");
    auto lowPowerTask = [this]() {
        std::lock_guard<std::recursive_mutex> lock(apiMutex_);
        enterLowPowerCount_--;
        PRINT_HILOGI("enter low power task, enterLowPowerCount_: %{public}u", enterLowPowerCount_);
        if (enterLowPowerCount_ > 0 || !isLowPowerMode_) {
            PRINT_HILOGW("Not need to enter low power mode");
            return;
        }
        if (StopDiscoverPrinter() != ERR_OK) {
            PRINT_HILOGE("Stop discovery failed, enter low power mode failed.");
        }
        PRINT_HILOGI("Enter low power mode successfully.");
    };
    if (serviceHandler_ == nullptr) {
        PRINT_HILOGE("serviceHandler_ is nullptr");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    isLowPowerMode_ = true;
    enterLowPowerCount_++;
    serviceHandler_->PostTask(lowPowerTask, ENTER_LOW_POWER_INTERVAL);
    PRINT_HILOGI("enterLowPowerCount_: %{public}u", enterLowPowerCount_);
}

void PrintServiceAbility::ExitLowPowerMode()
{
    PRINT_HILOGI("exit low power mode");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    if (!isLowPowerMode_) {
        PRINT_HILOGW("allready exit low power mode");
        return;
    }
    isLowPowerMode_ = false;
    std::vector<PrintExtensionInfo> extensionInfos;
    QueryAllExtension(extensionInfos);
    std::vector<std::string> extensionIds;
    for (const auto &extensionInfo : extensionInfos) {
        extensionIds.emplace_back(extensionInfo.GetExtensionId());
    }
    if (StartDiscoverPrinter(extensionIds) != ERR_OK) {
        PRINT_HILOGE("exit low power mode failed.");
        return;
    }
    PRINT_HILOGI("exit low power mode successfully");
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
    PrintCallerAppMonitor::GetInstance().IncrementPrintCounter("");
    PrintCallerAppMonitor::GetInstance().IncrementCallerAppCounter();
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
    PrintCallerAppMonitor::GetInstance().RemoveCallerAppFromMap();
    int64_t callerTokenId = static_cast<int64_t>(IPCSkeleton::GetCallingTokenID());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto iter = printUserDataMap_.find(callerTokenId);
    if (iter == printUserDataMap_.end() || iter->second == nullptr) {
        PRINT_HILOGE("Invalid token");
        return E_PRINT_INVALID_TOKEN;
    }
    iter->second->UnregisterPrinterCallback(type);
    PRINT_HILOGD("PrintServiceAbility::UnregisterPrinterCallback end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::RegisterExtCallback(
    const std::string &extensionCID, const sptr<IPrintExtensionCallback> &listener)
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

    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto extensionStateIt = extensionStateList_.find(extensionId);
    if (extensionStateIt == extensionStateList_.end()) {
        PRINT_HILOGE("Invalid extension id");
        return E_PRINT_INVALID_EXTENSION;
    }

    if (extensionStateIt->second != PRINT_EXTENSION_LOADING) {
        PRINT_HILOGE("Invalid Extension State [%{public}d]", extensionStateIt->second);
        return E_PRINT_INVALID_EXTENSION;
    }

    PRINT_HILOGI("PrintServiceAbility::RegisterExtCallback start.");
    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d]", callbackId);
        return E_PRINT_INVALID_PARAMETER;
    }

    if (listener == nullptr) {
        PRINT_HILOGE("Invalid listener");
        return E_PRINT_INVALID_PARAMETER;
    }

    if (extCallbackMap_.find(extensionCID) == extCallbackMap_.end()) {
        extCallbackMap_.insert(std::make_pair(extensionCID, listener));
    } else {
        PRINT_HILOGD("PrintServiceAbility::RegisterExtCallback Replace listener.");
        extCallbackMap_[extensionCID] = listener;
    }

    PRINT_HILOGD("PrintServiceAbility::RegisterExtCallback end.");
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
    auto it = extensionStateList_.find(extensionId);
    if (it == extensionStateList_.end()) {
        PRINT_HILOGE("Invalid extension id");
        return E_PRINT_INVALID_EXTENSION;
    }

    if (it->second != PRINT_EXTENSION_LOADING) {
        PRINT_HILOGE("Invalid Extension State");
        return E_PRINT_INVALID_EXTENSION;
    }
    it->second = PRINT_EXTENSION_LOADED;

    PRINT_HILOGD("Auto Stat Printer Discovery");
    auto callback = [=]() { DelayStartDiscovery(extensionId); };
    if (helper_ != nullptr && helper_->IsSyncMode()) {
        callback();
    } else if (serviceHandler_ != nullptr) {
        serviceHandler_->PostTask(callback, ASYNC_CMD_DELAY);
    } else {
        PRINT_HILOGW("serviceHandler_ is nullptr, cannot post task");
    }
    PRINT_HILOGD("PrintServiceAbility::LoadExtSuccess end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::On(const std::string taskId, const std::string &type, const sptr<IPrintCallback> &listener)
{
    ManualStart();
    std::string permission = PERMISSION_NAME_PRINT;
    std::string eventType = type;
    if (type == PRINTER_EVENT_TYPE || type == PRINTJOB_EVENT_TYPE || type == EXTINFO_EVENT_TYPE ||
        type == PRINT_QUERY_INFO_EVENT_TYPE) {
        permission = PERMISSION_NAME_PRINT_JOB;
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
    } else if (type == PRINTER_CHANGE_EVENT_TYPE || type == PRINTER_EVENT_TYPE || type == PRINTJOB_EVENT_TYPE||
        type == PRINT_QUERY_INFO_EVENT_TYPE) {
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
    PRINT_HILOGI("PrintServiceAbility::On started. type=%{public}s", eventType.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    constexpr int32_t MAX_LISTENERS_COUNT = 1000;
    if (registeredListeners_.size() > MAX_LISTENERS_COUNT) {
        PRINT_HILOGE("Exceeded the maximum number of registration.");
        return E_PRINT_GENERIC_FAILURE;
    }
    if (registeredListeners_.find(eventType) == registeredListeners_.end()) {
        registeredListeners_.insert(std::make_pair(eventType, listener));
    } else {
        PRINT_HILOGD("PrintServiceAbility::On Replace listener.");
        registeredListeners_[eventType] = listener;
    }
    HandlePrinterStateChangeRegister(eventType);
    HandlePrinterChangeRegister(eventType);
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::Off(const std::string taskId, const std::string &type)
{
    std::string permission = PERMISSION_NAME_PRINT;
    if (type == PRINTJOB_EVENT_TYPE || type == EXTINFO_EVENT_TYPE || type == PRINTER_EVENT_TYPE ||
        type == PRINT_QUERY_INFO_EVENT_TYPE) {
        permission = PERMISSION_NAME_PRINT_JOB;
    }
    std::string eventType = type;
    if (taskId != "") {
        eventType = PrintUtils::GetTaskEventId(taskId, type);
    }
    if (type == PRINTER_CHANGE_EVENT_TYPE || type == PRINTER_EVENT_TYPE || type == PRINTJOB_EVENT_TYPE ||
        type == PRINT_QUERY_INFO_EVENT_TYPE) {
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

    PRINT_HILOGI("PrintServiceAbility::Off started.");
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto iter = registeredListeners_.find(eventType);
    if (iter != registeredListeners_.end()) {
        PRINT_HILOGI("PrintServiceAbility::Off delete type=%{public}s object message.", eventType.c_str());
        registeredListeners_.erase(iter);
        if (PrintUtils::GetEventType(eventType) == PRINTER_CHANGE_EVENT_TYPE) {
            PrintCallerAppMonitor::GetInstance().DecrementPrintCounter("");
        }
        return E_PRINT_NONE;
    }
    PRINT_HILOGI("PrintServiceAbility::Off has already delete type=%{public}s delete.", eventType.c_str());
    return E_PRINT_NONE;
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

int32_t PrintServiceAbility::SendPrinterDiscoverEvent(int event, const PrinterInfo &info)
{
    int32_t num = 0;
    PRINT_HILOGD("[Printer: %{private}s] PrintServiceAbility::SendPrinterDiscoverEvent type, %{public}d",
        info.GetPrinterId().c_str(),
        event);
    for (auto &item : printUserDataMap_) {
        if (item.second != nullptr) {
            item.second->SendPrinterEvent(PRINTER_DISCOVER_EVENT_TYPE, event, info);
            num++;
        }
    }
    return num;
}

int32_t PrintServiceAbility::SendPrinterChangeEvent(int event, const PrinterInfo &info)
{
    int32_t num = 0;
    PRINT_HILOGD("[Printer: %{private}s] PrintServiceAbility::SendPrinterChangeEvent type, %{public}d",
        info.GetPrinterId().c_str(), event);
    for (auto &item : printUserDataMap_) {
        if (item.second != nullptr) {
            item.second->SendPrinterEvent(PRINTER_CHANGE_EVENT_TYPE, event, info);
            num++;
        }
    }
    return num;
}

void PrintServiceAbility::SendPrinterEvent(const PrinterInfo &info, const std::string userId)
{
    PRINT_HILOGD("[Printer: %{private}s] PrintServiceAbility::SendPrinterEvent type, %{public}d",
        info.GetPrinterId().c_str(),
        info.GetPrinterState());
    for (auto eventIt : registeredListeners_) {
        if (PrintUtils::GetEventType(eventIt.first) != PRINTER_EVENT_TYPE) {
            continue;
        }
        if (eventIt.second == nullptr) {
            PRINT_HILOGW("eventIt.second is nullptr");
            continue;
        }
        if (!userId.empty()) {
            AppExecFwk::BundleInfo bundleInfo;
            AppExecFwk::BundleMgrClient bundleMgrClient;
            std::string bundleName = PrintUtils::GetBundleName(info.GetPrinterId());
            int32_t userIdNum = 0;
            if (!PrintUtil::ConvertToInt(userId, userIdNum)) {
                PRINT_HILOGW("userId [%{private}s] ConvertToInt fail", userId.c_str());
                continue;
            }
            if (!bundleMgrClient.GetBundleInfo(bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT,
                bundleInfo, userIdNum)) {
                PRINT_HILOGW("user [%{private}s] has not installed [%{private}s]", userId.c_str(), bundleName.c_str());
                continue;
            }
        }
        PRINT_HILOGI("PrintServiceAbility::SendPrinterEvent find PRINTER_EVENT_TYPE");
        eventIt.second->OnCallback(info.GetPrinterState(), info);
    }
}

int32_t PrintServiceAbility::SendPrinterEventChangeEvent(
    PrinterEvent printerEvent, const PrinterInfo &info, bool isSignalUser)
{
    int32_t num = 0;
    PRINT_HILOGD("[Printer: %{public}s] PrintServiceAbility::SendPrinterEventChangeEvent, printerEvent: %{public}d",
        info.GetPrinterId().c_str(),
        printerEvent);
    for (auto eventIt : registeredListeners_) {
        if (PrintUtils::GetEventType(eventIt.first) != PRINTER_CHANGE_EVENT_TYPE || eventIt.second == nullptr) {
            continue;
        }
        PRINT_HILOGD("PrintServiceAbility::SendPrinterEventChangeEvent eventType = %{public}s", eventIt.first.c_str());
        if (isSignalUser && CheckUserIdInEventType(eventIt.first)) {
            PRINT_HILOGI("PrintServiceAbility::SendPrinterEventChangeEvent update info for a signal user");
            PrinterInfo newInfo(info);
            newInfo.SetIsLastUsedPrinter(true);
            eventIt.second->OnCallback(printerEvent, newInfo);
            num++;
        } else if (printerEvent == PRINTER_EVENT_LAST_USED_PRINTER_CHANGED) {
            if (CheckUserIdInEventType(eventIt.first)) {
                PRINT_HILOGI("PrintServiceAbility::SendPrinterEventChangeEvent last used printer event");
                eventIt.second->OnCallback(printerEvent, info);
                num++;
            }
        } else {
            eventIt.second->OnCallback(printerEvent, info);
            num++;
        }
    }
    return num;
}

void PrintServiceAbility::SendPrintJobEvent(const PrintJob &jobInfo)
{
    PRINT_HILOGI("[Job Id: %{public}s] PrintServiceAbility::SendPrintJobEvent, state: %{public}d, subState: %{public}d",
        jobInfo.GetJobId().c_str(),
        jobInfo.GetJobState(),
        jobInfo.GetSubState());
    for (auto eventIt : registeredListeners_) {
        if (PrintUtils::GetEventType(eventIt.first) != PRINTJOB_EVENT_TYPE || eventIt.second == nullptr) {
            continue;
        }
        if (CheckUserIdInEventType(eventIt.first)) {
            PrintJob callbackJobInfo = jobInfo;
            callbackJobInfo.SetFdList(std::vector<uint32_t>());  // State callback don't need fd.
            eventIt.second->OnCallback(jobInfo.GetJobState(), callbackJobInfo);
        }
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

int32_t PrintServiceAbility::SendExtensionEvent(const std::string &extensionId, const std::string &extInfo)
{
    int32_t num = 0;
    PRINT_HILOGD("PrintServiceAbility::SendExtensionEvent type %{public}s", extInfo.c_str());
    auto eventIt = registeredListeners_.find(EXTINFO_EVENT_TYPE);
    if (eventIt != registeredListeners_.end() && eventIt->second != nullptr) {
        eventIt->second->OnCallback(extensionId, extInfo);
        num++;
    }
    return num;
}

void PrintServiceAbility::SetHelper(const std::shared_ptr<PrintServiceHelper> &helper)
{
    helper_ = helper;
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(helper_);
}

void PrintServiceAbility::CheckJobQueueBlocked(const PrintJob &jobInfo)
{
    PRINT_HILOGD("CheckJobQueueBlocked started, isJobQueueBlocked_ = %{public}s",
        isJobQueueBlocked_ ? "true" : "false");
    PRINT_HILOGD("[Job Id: %{public}s] CheckJobQueueBlocked, jobState: %{public}d",
        jobInfo.GetJobId().c_str(), jobInfo.GetJobState());
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
    PRINT_HILOGD("CheckJobQueueBlocked end, isJobQueueBlocked_ = %{public}s", isJobQueueBlocked_ ? "true" : "false");
}

int32_t PrintServiceAbility::PrintByAdapter(
    const std::string jobName, const PrintAttributes &printAttributes, std::string &taskId)
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

int32_t PrintServiceAbility::StartGetPrintFile(
    const std::string &jobId, const PrintAttributes &printAttributes, const uint32_t fd)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("[Job Id: %{public}s] PrintServiceAbility::StartGetPrintFile start, fd: %{public}u",
        jobId.c_str(), fd);
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
        PRINT_HILOGW("PrintServiceAbility find event: %{public}s not found", PRINT_ADAPTER_EVENT_TYPE.c_str());
    }
    PRINT_HILOGI("PrintServiceAbility::StartGetPrintFile end");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::NotifyPrintService(const std::string &jobId, const std::string &type)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    if (type == "0" || type == NOTIFY_INFO_SPOOLER_CLOSED_FOR_STARTED) {
        PRINT_HILOGI("[Job Id: %{public}s] Notify Spooler Closed for started", jobId.c_str());
        notifyAdapterJobChanged(jobId, PRINT_JOB_SPOOLER_CLOSED, PRINT_JOB_SPOOLER_CLOSED_FOR_STARTED);
        PrintCallerAppMonitor::GetInstance().DecrementPrintCounter(jobId);
        return E_PRINT_NONE;
    }

    if (type == NOTIFY_INFO_SPOOLER_CLOSED_FOR_CANCELLED) {
        PRINT_HILOGI("[Job Id: %{public}s] Notify Spooler Closed for canceled", jobId.c_str());
        notifyAdapterJobChanged(jobId, PRINT_JOB_SPOOLER_CLOSED, PRINT_JOB_SPOOLER_CLOSED_FOR_CANCELED);
        PrintCallerAppMonitor::GetInstance().DecrementPrintCounter(jobId);
        return E_PRINT_NONE;
    }
    return E_PRINT_INVALID_PARAMETER;
}

void PrintServiceAbility::notifyAdapterJobChanged(
    const std::string jobId, const uint32_t state, const uint32_t subState)
{
    if (state != PRINT_JOB_BLOCKED && state != PRINT_JOB_COMPLETED && state != PRINT_JOB_SPOOLER_CLOSED) {
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    auto attrIt = printAttributesList_.find(jobId);
    if (attrIt != printAttributesList_.end()) {
        printAttributesList_.erase(attrIt);
    }

    PRINT_HILOGI("[Job Id: %{public}s] get adapterListenersByJobId_", jobId.c_str());
    UnregisterPrintTaskCallback(jobId, state, subState);
    auto eventIt = adapterListenersByJobId_.find(jobId);
    if (eventIt == adapterListenersByJobId_.end() || eventIt->second == nullptr) {
        return;
    }

    uint32_t printAdapterListeningState = GetListeningState(state, subState);
    PRINT_HILOGI("notifyAdapterJobChanged for subState: %{public}d, listeningState: %{public}d",
        subState,
        printAdapterListeningState);
    eventIt->second->OnCallbackAdapterJobStateChanged(jobId, state, printAdapterListeningState);

    if (subState == PRINT_JOB_SPOOLER_CLOSED_FOR_CANCELED || state == PRINT_JOB_COMPLETED) {
        auto unregisterTask = [this, jobId]() {
            std::lock_guard<std::recursive_mutex> lock(apiMutex_);
            auto eventIt = adapterListenersByJobId_.find(jobId);
            if (eventIt == adapterListenersByJobId_.end() || eventIt->second == nullptr) {
                return;
            }
            PRINT_HILOGI("[Job Id: %{public}s] erase adapterListenersByJobId_", jobId.c_str());
            adapterListenersByJobId_.erase(jobId);
        };
        serviceHandler_->PostTask(unregisterTask, UNREGISTER_CALLBACK_INTERVAL);
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
        PRINT_HILOGE("no permission to access print service, ErrorCode: [%{public}d]", E_PRINT_NO_PERMISSION);
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
    if (!StartPluginPrintExtAbility(want)) {
        PRINT_HILOGE("Failed to start PluginPrintIconExtAbility");
        return E_PRINT_SERVER_FAILURE;
    }
    return E_PRINT_NONE;
}

bool PrintServiceAbility::StartExtensionAbility(const AAFwk::Want &want)
{
    if (helper_ == nullptr) {
        PRINT_HILOGE("Invalid print service helper.");
        return false;
    }
    PRINT_HILOGI("enter PrintServiceAbility::StartExtensionAbility");
    return helper_->StartExtensionAbility(want);
}

bool PrintServiceAbility::StartPluginPrintExtAbility(const AAFwk::Want &want)
{
    if (helper_ == nullptr) {
        PRINT_HILOGE("Invalid print service helper.");
        return false;
    }
    PRINT_HILOGI("enter PrintServiceAbility::StartExtensionAbility");
    bool ret = helper_->StartPluginPrintExtAbility(want);
    auto timeoutCheck = [this]() {
        if (helper_ == nullptr) {
            PRINT_HILOGE("timeoutCheck, Invalid print service helper.");
            return;
        }
        if (!helper_->CheckPluginPrintConnected()) {
            PRINT_HILOGE("can't connect extension ability, cancel all printJob.");
            std::vector<std::string> jobIdlListToCancel;
            {
                std::lock_guard<std::recursive_mutex> lock(apiMutex_);
                for (const auto& jobIt : queuedJobList_) {
                    jobIdlListToCancel.push_back(jobIt.second->GetJobId());
                }
            }
            for (const auto& jobId : jobIdlListToCancel) {
                CancelPrintJob(jobId);
            }
        }
    };
    if (ret) {
        serviceHandler_->PostTask(timeoutCheck, CONNECT_PLUGIN_PRINT_TIMEOUT);
    }
    return ret;
}

std::shared_ptr<PrintUserData> PrintServiceAbility::GetCurrentUserData()
{
    int32_t userId = GetCurrentUserId();
    if (userId == INVALID_USER_ID) {
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
    if (userId <= 0 && helper_ != nullptr) {
        PRINT_HILOGD("print sa calling, use current active userId");
        std::vector<int32_t> userIds;
        helper_->QueryAccounts(userIds);
        if (userIds.empty()) {
            PRINT_HILOGE("get use current active userId failed");
            userId = -1;
        } else {
            userId = userIds[0];
        }
    }
    PRINT_HILOGI("Current userId = %{public}d", userId);
    return userId;
}

std::string PrintServiceAbility::GetCallerUserName()
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t localId = -1;
    auto errCode = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, localId);
    PRINT_HILOGI("GetOsAccountLocalIdFromUid errCode = %{public}d", errCode);
    PRINT_HILOGD("uid: %{private}d, localId: %{private}d", uid, localId);
    AccountSA::OsAccountInfo osAccountInfo;
    errCode = AccountSA::OsAccountManager::QueryOsAccountById(localId, osAccountInfo);
    PRINT_HILOGI("QueryOsAccountById errCode = %{public}d", errCode);
    PRINT_HILOGD("localName: %{private}s", osAccountInfo.GetLocalName().c_str());
    AccountSA::DomainAccountInfo domainInfo;
    osAccountInfo.GetDomainInfo(domainInfo);
    PRINT_HILOGD("domainName: %{private}s", domainInfo.accountName_.c_str());
    if (domainInfo.accountName_.empty()) {
        return DEFAULT_USER_NAME;
    }
    return domainInfo.accountName_;
}

std::shared_ptr<PrintUserData> PrintServiceAbility::GetUserDataByJobId(const std::string jobId)
{
    int32_t userId = GetUserIdByJobId(jobId);
    PRINT_HILOGI("the job is belong to user-%{public}d.", userId);
    if (userId == E_PRINT_INVALID_PRINTJOB) {
        auto userData = GetCurrentUserData();
        if (userData == nullptr) {
            PRINT_HILOGE("Get user data failed.");
            return nullptr;
        }
        if (userData->ContainsHistoryPrintJob(printSystemData_.QueryAddedPrinterIdList(), jobId)) {
            return userData;
        }
        for (auto it = printUserMap_.begin(); it != printUserMap_.end(); it++) {
            if ((it->second)->ContainsHistoryPrintJob(printSystemData_.QueryAddedPrinterIdList(), jobId)) {
                return it->second;
            }
        }
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
    for (std::map<std::string, int32_t>::iterator it = userJobMap_.begin(); it != userJobMap_.end(); ++it) {
        PRINT_HILOGD("[Job Id: %{public}s], userId: %{private}d.", it->first.c_str(), it->second);
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
    if (userId == INVALID_USER_ID) {
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
    PRINT_HILOGI("[Job Id: %{public}s] AddToPrintJobList start", jobId.c_str());
    UpdatePrintUserMap();
    printJobList_.insert(std::make_pair(jobId, printjob));
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
    PRINT_HILOGD("[Job Id: %{public}s] RegisterAdapterListener for", jobId.c_str());
    auto eventIt = registeredListeners_.find(PRINT_ADAPTER_EVENT_TYPE);
    if (eventIt != registeredListeners_.end()) {
        PRINT_HILOGI("[Job Id: %{public}s] adapterListenersByJobId_ set adapterListenersByJobId_", jobId.c_str());
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
    PRINT_HILOGI("[Printer: %{public}s] SetDefaultPrinter start.", PrintUtils::AnonymizePrinterId(printerId).c_str());
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
        PRINT_HILOGE("is not default printer");
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
        PRINT_HILOGE("is not last used printer.");
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
    PRINT_HILOGI("[Printer: %{public}s] DeletePrinterFromCups start", printerName.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
#ifdef CUPS_ENABLE
    std::string standardName = PrintUtil::StandardizePrinterName(printerName);
    DelayedSingleton<PrintCupsClient>::GetInstance()->DeleteCupsPrinter(standardName.c_str());
#endif  // CUPS_ENABLE
    std::string printerId = printSystemData_.QueryPrinterIdByStandardizeName(printerName);
    vendorManager.MonitorPrinterStatus(printerId, false);
    DeletePrinterFromUserData(printerId);
    NotifyAppDeletePrinter(printerId);
    printSystemData_.DeleteAddedPrinter(printerId, printerName);
    RemoveSinglePrinterInfo(printerId);
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::AddPrinterToDiscovery(const PrinterInfo &printerInfo)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    if (PrintUtil::startsWith(printerInfo.GetPrinterId(), "mdns://") &&
        vendorManager.FindDriverByVendorName(VENDOR_BSUNI_DRIVER) != nullptr) {
        PRINT_HILOGD("[Printer: %{public}s] AddPrinterToDiscovery skip", printerInfo.GetPrinterId().c_str());
        return E_PRINT_NONE;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    PRINT_HILOGI("[Printer: %{public}s] AddPrinterToDiscovery started. Current total size is %{public}zd",
        printerInfo.GetPrinterName().c_str(), printSystemData_.GetDiscoveredPrinterCount());
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGI("[Printer: %{public}s] extensionId = %{public}s",
        printerInfo.GetPrinterName().c_str(), extensionId.c_str());

    int32_t result = AddSinglePrinterInfo(printerInfo, extensionId);

    PRINT_HILOGD(
        "AddPrinterToDiscovery end. New total size is %{public}zd", printSystemData_.GetDiscoveredPrinterCount());
    return result;
}

int32_t PrintServiceAbility::UpdatePrinterInDiscovery(const PrinterInfo &printerInfo)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    PRINT_HILOGI("[Printer: %{public}s] UpdatePrinterInDiscovery start", printerInfo.GetPrinterName().c_str());
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
    PRINT_HILOGI("[Printer: %{public}s] RemovePrinterFromDiscovery start",
        PrintUtils::AnonymizePrinterId(printerId).c_str());
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
    auto monitorParam = std::make_shared<JobMonitorParam>(nullptr, "", 0, printerUri, "", printerId, nullptr);
    PRINT_HILOGD("[Printer: %{public}s] printer type is %{public}d", printerId.c_str(), mdnsPrinter);
    // 连接类型为mdns且为spooler显示的已经连接的打印机才判断是否离线
    if (!printerUri.empty() && mdnsPrinter &&
        DelayedSingleton<PrintCupsClient>::GetInstance()->CheckPrinterOnline(monitorParam, waitTime)) {
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
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }

    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    PRINT_HILOGI("[Printer: %{public}s] UpdatePrinterInSystem start", printerInfo.GetPrinterName().c_str());
    std::string extensionId = DelayedSingleton<PrintBMSHelper>::GetInstance()->QueryCallerBundleName();
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());
    std::string printerId = printerInfo.GetPrinterId();
    if (printerId.find(PRINTER_ID_DELIMITER) == std::string::npos) {
        printerId = PrintUtils::GetGlobalId(extensionId, printerId);
    }

    PrinterInfo printer;
    if (!printSystemData_.QueryAddedPrinterInfoByPrinterId(printerId, printer)) {
        PRINT_HILOGE("can not find printer in system");
        return E_PRINT_INVALID_PRINTER;
    }
    if (printerInfo.HasAlias()) {
        printer.SetAlias(printerInfo.GetAlias());
        printSystemData_.UpdatePrinterAlias(printerId, printerInfo.GetAlias());
        printSystemData_.SavePrinterFile(printerId);
    }

    SendPrinterEventChangeEvent(PRINTER_EVENT_INFO_CHANGED, printer);
    PRINT_HILOGI("UpdatePrinterInSystem end");
    return E_PRINT_NONE;
}

bool PrintServiceAbility::QueryPPDInformation(const std::string &makeModel, std::string &ppdName)
{
#ifdef CUPS_ENABLE
    return DelayedSingleton<PrintCupsClient>::GetInstance()->QueryPPDInformation(makeModel, ppdName);
#endif
    return false;
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
    userData->DeletePrintJobFromHistoryListByPrinterId(printerId);
    std::string defaultPrinterId = userData->GetDefaultPrinter();
    bool ret = userData->CheckIfUseLastUsedPrinterForDefault();
    PRINT_HILOGI("DeletePrinterFromUserData defaultPrinterId %{private}s.", defaultPrinterId.c_str());
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
    bool hasBlocked = std::any_of(jobList.begin(), jobList.end(), [](const auto &pair) {
        return pair.second->GetJobState() == PRINT_JOB_BLOCKED;
    });
    if (hasBlocked) {
        return PRINT_JOB_BLOCKED;
    }
    bool allComplete = std::all_of(jobList.begin(), jobList.end(), [](const auto &pair) {
        return pair.second->GetJobState() == PRINT_JOB_COMPLETED;
    });
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
    Json::Value opsJson;
    if (!PrintJsonUtil::Parse(ops, opsJson)) {
        PRINT_HILOGW("ops can not parse to json object");
        return;
    }
    opsJson["nextDefaultPrinter"] = dafaultPrinterId;
    printerInfo.SetOption(PrintJsonUtil::WriteString(opsJson));
    SendPrinterEventChangeEvent(PRINTER_EVENT_DELETED, printerInfo);
    SendPrinterChangeEvent(PRINTER_EVENT_DELETED, printerInfo);

    std::string lastUsedPrinterId = userData->GetLastUsedPrinter();
    if (!lastUsedPrinterId.empty()) {
        PrinterInfo lastUsedPrinterInfo;
        printSystemData_.QueryPrinterInfoById(lastUsedPrinterId, lastUsedPrinterInfo);
        PRINT_HILOGI("NotifyAppDeletePrinter lastUsedPrinterId = %{private}s", lastUsedPrinterId.c_str());
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
    PRINT_HILOGI("DiscoverUsbDevices printers size: %{public}zu", printers.size());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::DiscoverBackendPrinters(std::vector<PrinterInfo> &printers)
{
    PRINT_HILOGD("DiscoverBackendPrinters started.");
#ifdef CUPS_ENABLE
    int32_t ret = DelayedSingleton<PrintCupsClient>::GetInstance()->DiscoverBackendPrinters(printers);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("DiscoverBackendPrinters failed.");
        return ret;
    }
#endif  // CUPS_ENABLE
    PRINT_HILOGD("DiscoverBackendPrinters printers size: %{public}zu", printers.size());
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::AddSinglePrinterInfo(const PrinterInfo &info, const std::string &extensionId)
{
    auto infoPtr = std::make_shared<PrinterInfo>(info);
    infoPtr->SetPrinterId(PrintUtils::GetGlobalId(extensionId, infoPtr->GetPrinterId()));
    PRINT_HILOGI("[Printer: %{public}s] AddSinglePrinterInfo start",
        PrintUtils::AnonymizePrinterId(infoPtr->GetPrinterId()).c_str());
    if (printSystemData_.QueryDiscoveredPrinterInfoById(infoPtr->GetPrinterId()) == nullptr) {
        PRINT_HILOGI("new printer, add it");
        infoPtr->DumpInfo();
        printSystemData_.AddPrinterToDiscovery(infoPtr);
    }
    infoPtr->SetPrinterState(PRINTER_ADDED);

    SendPrinterDiscoverEvent(PRINTER_ADDED, *infoPtr);
    SendPrinterEvent(*infoPtr, std::to_string(GetCurrentUserId()));

    if (printSystemData_.IsPrinterAdded(infoPtr->GetPrinterId()) &&
        !printSystemData_.CheckPrinterBusy(infoPtr->GetPrinterId())) {
        if (CheckPrinterUriDifferent(infoPtr)) {
            if (UpdateAddedPrinterInCups(infoPtr->GetPrinterId(), infoPtr->GetUri())) {
                printSystemData_.UpdatePrinterUri(infoPtr);
                printSystemData_.SavePrinterFile(infoPtr->GetPrinterId());
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
    PRINT_HILOGI("[Printer: %{public}s] UpdateSinglePrinterInfo start", info.GetPrinterName().c_str());
    std::string printExtId = info.GetPrinterId();
    printExtId = PrintUtils::GetGlobalId(extensionId, printExtId);

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
        isCapabilityUpdated = UpdatePrinterCapability(printExtId, *printerInfo);
    }

    if (isCapabilityUpdated) {
        SendPrinterEvent(*printerInfo);
        SendPrinterDiscoverEvent(PRINTER_UPDATE_CAP, *printerInfo);
        printSystemData_.SavePrinterFile(printerInfo->GetPrinterId());
    }

    return isCapabilityUpdated;
}

bool PrintServiceAbility::RemoveSinglePrinterInfo(const std::string &printerId)
{
    PRINT_HILOGI("[Printer: %{public}s] RemoveSinglePrinterInfo start",
        PrintUtils::AnonymizePrinterId(printerId).c_str());
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
    auto globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, info.GetPrinterId());
    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(globalPrinterId);
    if (printerInfo == nullptr) {
        PRINT_HILOGI("new printer, add it");
        info.DumpInfo();
        printerInfo = std::make_shared<PrinterInfo>(info);
        if (printerInfo == nullptr) {
            PRINT_HILOGW("allocate printer info fail");
            return false;
        }
        OHOS::Print::PrinterInfo printer;
        if (printSystemData_.QueryAddedPrinterInfoByPrinterId(globalPrinterId, printer)) {
            printerInfo->SetPrinterName(printer.GetPrinterName());
        }
        printerInfo->SetPrinterId(globalPrinterId);
        printSystemData_.AddPrinterToDiscovery(printerInfo);
    }
    printerInfo->SetPrinterState(PRINTER_ADDED);
    SendPrinterDiscoverEvent(PRINTER_ADDED, *printerInfo);
    SendPrinterEvent(*printerInfo);
    if (printSystemData_.IsPrinterAdded(printerInfo->GetPrinterId()) &&
        !printSystemData_.CheckPrinterBusy(printerInfo->GetPrinterId())) {
        if (CheckPrinterUriDifferent(printerInfo) &&
            UpdateAddedPrinterInCups(printerInfo->GetPrinterId(), printerInfo->GetUri())) {
            printSystemData_.UpdatePrinterUri(printerInfo);
            printSystemData_.SavePrinterFile(printerInfo->GetPrinterId());
        }
        printerInfo->SetPrinterStatus(PRINTER_STATUS_IDLE);
        printSystemData_.UpdatePrinterStatus(printerInfo->GetPrinterId(), PRINTER_STATUS_IDLE);
        SendPrinterEventChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
        SendPrinterChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
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
    OHOS::Print::PrinterInfo printer;
    if (printSystemData_.QueryAddedPrinterInfoByPrinterId(globalPrinterId, printer)) {
        printerInfo->SetPrinterName(printer.GetPrinterName());
    }
    return true;
}

bool PrintServiceAbility::RemoveVendorPrinterFromDiscovery(
    const std::string &globalVendorName, const std::string &printerId)
{
    PRINT_HILOGI("RemovePrinterFromDiscovery");
    auto globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, printerId);
    return RemoveSinglePrinterInfo(globalPrinterId);
}

bool PrintServiceAbility::AddVendorPrinterToCupsWithPpd(const std::string &globalVendorName,
    const std::string &printerId, const std::string &ppdName, const std::string &ppdData)
{
    auto globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, printerId);
    auto printerInfo = QueryConnectingPrinterInfoById(globalPrinterId);
    if (!DoAddPrinterToCups(printerInfo, ppdName, ppdData)) {
        PRINT_HILOGW("AddPrinterToCups fail.");
        return false;
    }
    OnPrinterAddedToCups(printerInfo, ppdName);
    return true;
}

std::string PrintServiceAbility::GetConnectUri(PrinterInfo &printerInfo, std::string connectProtocol)
{
    std::string printerUri = printerInfo.GetUri();
    char scheme[HTTP_MAX_URI] = {0}; /* Method portion of URI */
    char username[HTTP_MAX_URI] = {0}; /* Username portion of URI */
    char host[HTTP_MAX_URI] = {0}; /* Host portion of URI */
    char resource[HTTP_MAX_URI] = {0}; /* Resource portion of URI */
    int port = 0; /* Port portion of URI */
    httpSeparateURI(HTTP_URI_CODING_ALL, printerUri.c_str(), scheme, sizeof(scheme), username, sizeof(username),
        host, sizeof(host), &port, resource, sizeof(resource));
    std::string printerIp;
    printerIp.assign(host);
    std::string optionStr = printerInfo.GetOption();
    Json::Value option;
    if (!PrintJsonUtil::Parse(optionStr, option)) {
        PRINT_HILOGE("Failed to parse option JSON");
        return printerUri;
    }
    if (connectProtocol == "ipp") {
        if (PrintJsonUtil::IsMember(option, "ipp") &&option["ipp"].isString()) {
            printerUri = option["ipp"].asString();
        } else {
            printerUri = "ipp://" + printerIp + ":631/ipp/print";
        }
    } else if (connectProtocol == "ipps") {
        if (PrintJsonUtil::IsMember(option, "ipps") && option["ipps"].isString()) {
            printerUri = option["ipps"].asString();
        } else {
            printerUri = "ipps://" + printerIp + ":443/ipp/print";
        }
    } else if (connectProtocol == "lpd") {
        if (PrintJsonUtil::IsMember(option, "lpd") && option["lpd"].isString()) {
            printerUri = option["lpd"].asString();
        } else {
            printerUri = "lpd://" +printerIp + ":515";
        }
    } else if (connectProtocol == "socket") {
        if (PrintJsonUtil::IsMember(option, "socket") && option["socket"].isString()) {
            printerUri = option["socket"].asString();
        } else {
            printerUri = "socket://" + printerIp + ":9100";
        }
    }
    return printerUri;
}

bool PrintServiceAbility::DoAddPrinterToCups(
    std::shared_ptr<PrinterInfo> printerInfo, const std::string &ppdName, const std::string &ppdData)
{
    if (printerInfo == nullptr || !printerInfo->HasUri()) {
        PRINT_HILOGW("printerInfo is null or invalid.");
        return false;
    }
    std::string printerUri = printerInfo->GetUri();

    std::string connectProtocol = vendorManager.GetConnectingProtocol();
    if (!connectProtocol.empty() && connectProtocol != "auto") {
        printerUri = GetConnectUri(*printerInfo, connectProtocol);
    }
    std::string printerName = RenamePrinterWhenAdded(*printerInfo);
    PRINT_HILOGI(
        "[Printer: %{public}s] DoAddPrinterToCups start, printerMake: %{public}s, "
        "printerUri: %{public}s, ppdName: %{public}s",
        printerName.c_str(), printerInfo->GetPrinterMake().c_str(),
        PrintUtils::AnonymizePrinterUri(printerUri).c_str(), ppdName.c_str());
#ifdef CUPS_ENABLE
    if (!DoAddPrinterToCupsEnable(printerUri, printerName, printerInfo, ppdName, ppdData)) {
        return false;
    }
#endif  // CUPS_ENABLE
    printerInfo->SetPrinterName(printerName);
    return true;
}

bool PrintServiceAbility::DoAddPrinterToCupsEnable(const std::string &printerUri, const std::string &printerName,
    std::shared_ptr<PrinterInfo> printerInfo, const std::string &ppdName, const std::string &ppdData)
{
    auto printCupsClient = DelayedSingleton<PrintCupsClient>::GetInstance();
    if (printCupsClient == nullptr) {
        PRINT_HILOGW("printCupsClient is null.");
        return false;
    }
    int32_t ret = E_PRINT_NONE;
    bool needUpdateCapability = false;
    std::string option = printerInfo->GetOption();
    Json::Value optionJson;
    PrintJsonUtil::Parse(option, optionJson);
    if (ppdData.empty()) {
        if (ppdName.empty()) {
            if (!printerInfo->HasCapability() || !printerInfo->HasPrinterMake()) {
                PRINT_HILOGW("empty capability or invalid printer maker");
                return false;
            }
            optionJson["driver"] = "IPPEVERYWHERE";
            ret = printCupsClient->AddPrinterToCups(printerUri, printerName, printerInfo->GetPrinterMake());
        } else {
            needUpdateCapability = true;
            optionJson["driver"] = "VENDOR";
            ret = printCupsClient->AddPrinterToCupsWithSpecificPpd(printerUri, printerName, ppdName);
        }
    } else {
        if (!printerInfo->HasCapability()) {
            PRINT_HILOGW("empty capability");
            return false;
        }
        optionJson["driver"] = "BSUNI";
        ret = printCupsClient->AddPrinterToCupsWithPpd(printerUri, printerName, ppdName, ppdData);
    }
    printerInfo->SetOption(PrintJsonUtil::WriteString(optionJson));
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGW("AddPrinterToCups error = %{public}d.", ret);
        return false;
    }
    if (needUpdateCapability) {
        PrinterCapability printerCaps;
        ret = printCupsClient->QueryPrinterCapabilityFromPPD(printerName, printerCaps, ppdName);
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGW("QueryPrinterCapabilityFromPPD error = %{public}d.", ret);
        }
        printerInfo->SetCapability(printerCaps);
    }
    return true;
}

void PrintServiceAbility::OnPrinterAddedToCups(std::shared_ptr<PrinterInfo> printerInfo, const std::string &ppdName)
{
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printerInfo is null");
        return;
    }
    PRINT_HILOGI("[Printer: %{public}s] OnPrinterAddedToCups start", printerInfo->GetPrinterName().c_str());
    auto globalPrinterId = printerInfo->GetPrinterId();
    printerInfo->SetPrinterStatus(PRINTER_STATUS_IDLE);
    printerInfo->SetPrinterState(PRINTER_CONNECTED);
    printerInfo->SetPrinterStatus(PRINTER_STATUS_IDLE);
    std::string ppdHashCode = DelayedSingleton<PrintCupsClient>::GetInstance()->GetPpdHashCode(ppdName);
    printerInfo->SetPpdHashCode(ppdHashCode);
    if (printSystemData_.IsPrinterAdded(globalPrinterId)) {
        SendPrinterEventChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
        SendPrinterChangeEvent(PRINTER_EVENT_STATE_CHANGED, *printerInfo);
    } else {
        BuildPrinterPreference(*printerInfo);
        printSystemData_.InsertAddedPrinter(globalPrinterId, *printerInfo);
        printSystemData_.SavePrinterFile(printerInfo->GetPrinterId());
        SendPrinterEventChangeEvent(PRINTER_EVENT_ADDED, *printerInfo, true);
        SendPrinterChangeEvent(PRINTER_EVENT_ADDED, *printerInfo);
    }
    printerInfo->SetPrinterState(PRINTER_UPDATE_CAP);
    SendPrinterDiscoverEvent(PRINTER_UPDATE_CAP, *printerInfo);
    SendPrinterEvent(*printerInfo);
    SetLastUsedPrinter(globalPrinterId);
    SendPrinterDiscoverEvent(PRINTER_CONNECTED, *printerInfo);
    vendorManager.ClearConnectingPrinter();
    vendorManager.ClearConnectingProtocol();
    vendorManager.ClearConnectingPpdName();
    vendorManager.MonitorPrinterStatus(globalPrinterId, true);
}

bool PrintServiceAbility::RemoveVendorPrinterFromCups(const std::string &globalVendorName, const std::string &printerId)
{
    PRINT_HILOGI("[Printer: %{public}s] RemovePrinterFromCups start",
        PrintUtils::AnonymizePrinterId(printerId).c_str());
    auto globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, printerId);
    PrinterInfo printer;
    if (!printSystemData_.QueryAddedPrinterInfoByPrinterId(globalPrinterId, printer)) {
        PRINT_HILOGW("cannot find printer");
        return false;
    }
#ifdef CUPS_ENABLE
    std::string standardName = PrintUtil::StandardizePrinterName(printer.GetPrinterName());
    auto ret = DelayedSingleton<PrintCupsClient>::GetInstance()->DeleteCupsPrinter(standardName.c_str());
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGW("DeleteCupsPrinter error = %{public}d.", ret);
        return false;
    }
#endif  // CUPS_ENABLE
    vendorManager.MonitorPrinterStatus(globalPrinterId, false);
    DeletePrinterFromUserData(globalPrinterId);
    NotifyAppDeletePrinter(globalPrinterId);
    printSystemData_.DeleteAddedPrinter(globalPrinterId, printer.GetPrinterName());
    return true;
}

bool PrintServiceAbility::AddIpPrinterToSystemData(const std::string &globalVendorName, const PrinterInfo &info)
{
    PRINT_HILOGI("AddIpPrinterToSystemData");
    auto globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, info.GetPrinterId());
    auto printerInfo = printSystemData_.QueryIpPrinterInfoById(globalPrinterId);
    if (printerInfo == nullptr || (!info.GetUri().empty() && printerInfo->GetUri() != info.GetUri())) {
        PRINT_HILOGI("new printer, add it");
        info.DumpInfo();
        printerInfo = std::make_shared<PrinterInfo>(info);
        if (printerInfo == nullptr) {
            PRINT_HILOGW("allocate printer info fail");
            return false;
        }
        OHOS::Print::PrinterInfo printer;
        if (printSystemData_.QueryAddedPrinterInfoByPrinterId(globalPrinterId, printer)) {
            printerInfo->SetPrinterName(printer.GetPrinterName());
        }
        printerInfo->SetPrinterId(globalPrinterId);
        printSystemData_.AddIpPrinterToList(printerInfo);
    }
    return true;
}

bool PrintServiceAbility::AddIpPrinterToCupsWithPpd(const std::string &globalVendorName, const std::string &printerId,
    const std::string &ppdName, const std::string &ppdData)
{
    auto globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, printerId);
    auto printerInfo = printSystemData_.QueryIpPrinterInfoById(globalPrinterId);
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printerInfo is null");
        return false;
    }
    if (!DoAddPrinterToCups(printerInfo, ppdName, ppdData)) {
        PRINT_HILOGW("AddPrinterToCups fail.");
        return false;
    }
    printerInfo->SetPrinterStatus(PRINTER_STATUS_IDLE);
    printerInfo->SetPrinterState(PRINTER_CONNECTED);
    printerInfo->SetPrinterStatus(PRINTER_STATUS_IDLE);
    std::string ppdHashCode = DelayedSingleton<PrintCupsClient>::GetInstance()->GetPpdHashCode(ppdName);
    printerInfo->SetPpdHashCode(ppdHashCode);
    BuildPrinterPreference(*printerInfo);
    printSystemData_.InsertAddedPrinter(globalPrinterId, *printerInfo);
    printSystemData_.SavePrinterFile(globalPrinterId);
    SetLastUsedPrinter(globalPrinterId);
    SendPrinterEventChangeEvent(PRINTER_EVENT_ADDED, *printerInfo, true);
    SendPrinterChangeEvent(PRINTER_EVENT_ADDED, *printerInfo);
    vendorManager.ClearConnectingPrinter();
    vendorManager.ClearConnectingProtocol();
    vendorManager.ClearConnectingPpdName();
    vendorManager.MonitorPrinterStatus(globalPrinterId, true);
    printSystemData_.RemoveIpPrinterFromList(globalPrinterId);
    return true;
}

std::vector<std::string> PrintServiceAbility::QueryAddedPrintersByIp(const std::string &printerIp)
{
    return printSystemData_.QueryAddedPrintersByIp(printerIp);
}

bool PrintServiceAbility::OnVendorStatusUpdate(
    const std::string &globalVendorName, const std::string &printerId, const PrinterVendorStatus &status)
{
    PRINT_HILOGD("OnVendorStatusUpdate state: %{public}d", static_cast<int32_t>(status.state));
    auto globalPrinterId = PrintUtils::GetGlobalId(globalVendorName, printerId);
    PRINT_HILOGD("[Printer: %{public}s] OnVendorStatusUpdate", globalPrinterId.c_str());
    printSystemData_.UpdatePrinterStatus(globalPrinterId, static_cast<PrinterStatus>(status.state));
    PrinterInfo printerInfo;
    if (!printSystemData_.QueryAddedPrinterInfoByPrinterId(globalPrinterId, printerInfo)) {
        PRINT_HILOGD("cannot find added printer info");
        return false;
    }
    bool isIppPrinter = strstr(printerInfo.GetUri().c_str(), "ipp") != nullptr;
    if (!isIppPrinter && static_cast<PrinterStatus>(status.state) == PRINTER_UNAVAILABLE) {
        PRINT_HILOGD("Non-ipp printer, state query may not be supported. Ignore state of shutdown.");
        return true;
    }
    printerInfo.SetPrinterStatus(static_cast<uint32_t>(status.state));
    SendPrinterEventChangeEvent(PRINTER_EVENT_STATE_CHANGED, printerInfo);
    SendPrinterChangeEvent(PRINTER_EVENT_STATE_CHANGED, printerInfo);
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
        if (!StartAbility(want) || !StartExtensionAbility(want)) {
            PRINT_HILOGE("Failed to load extension %{public}s", ability.second.name.c_str());
            continue;
        }
        extensionStateList_[ability.second.bundleName] = PRINT_EXTENSION_LOADING;
    }
    PRINT_HILOGI("StartDiscoverPrinter end.");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::StartPrintJobInternal(const std::shared_ptr<PrintJob> &printJob)
{
    if (printJob == nullptr) {
        PRINT_HILOGW("printJob is null");
        return E_PRINT_SERVER_FAILURE;
    }
    PRINT_HILOGI("StartPrintJobInternal, option: %{public}s",
        PrintUtils::AnonymizeJobOption(printJob->GetOption()).c_str());
    if (isEprint(printJob->GetPrinterId())) {
        auto extensionId = PrintUtils::GetExtensionId(printJob->GetPrinterId());
        std::string cid = PrintUtils::EncodeExtensionCid(extensionId, PRINT_EXTCB_START_PRINT);
        auto cbIter = extCallbackMap_.find(cid);
        if (cbIter == extCallbackMap_.end()) {
            return E_PRINT_SERVER_FAILURE;
        }
        if (!FlushCacheFileToUserData(printJob->GetJobId())) {
            PRINT_HILOGW("Flush cache file failed");
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
        DelayedSingleton<PrintCupsClient>::GetInstance()->AddCupsPrintJob(*printJob, GetCallerUserName());
        CallStatusBar();
#endif  // CUPS_ENABLE
    }
    PRINT_HILOGI("StartNativePrintJob end.");
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
    PRINT_HILOGI("TryConnectPrinterByIp start");
    Json::Value connectParamJson;
    if (!PrintJsonUtil::Parse(params, connectParamJson)) {
        PRINT_HILOGW("invalid params");
        return E_PRINT_INVALID_PRINTER;
    }
    if (!PrintJsonUtil::IsMember(connectParamJson, "ip") || !connectParamJson["ip"].isString()) {
        PRINT_HILOGW("ip missing");
        return E_PRINT_INVALID_PRINTER;
    }
    std::string ip = connectParamJson["ip"].asString();
    PRINT_HILOGI("ip: %{public}s", PrintUtils::AnonymizeIp(ip).c_str());
    std::string protocol = "auto";
    if (PrintJsonUtil::IsMember(connectParamJson, "protocol") && connectParamJson["protocol"].isString()) {
        protocol = connectParamJson["protocol"].asString();
    }
    printSystemData_.ClearPrintEvents(ip, CONNECT_PRINT_EVENT_TYPE);
    vendorManager.SetConnectingPrinter(IP_AUTO, ip);
    if (!vendorManager.ConnectPrinterByIp(ip, protocol)) {
        PRINT_HILOGW("ConnectPrinterByIp fail");
        return E_PRINT_SERVER_FAILURE;
    }
    PRINT_HILOGI("connecting printer by ip success");
    return E_PRINT_NONE;
}

void PrintServiceAbility::HandlePrinterStateChangeRegister(const std::string &eventType)
{
    if (PrintUtils::GetEventType(eventType) == PRINTER_EVENT_TYPE) {
        PRINT_HILOGI("begin HandlePrinterStateChangeRegister");
        std::map<std::string, std::shared_ptr<PrinterInfo>> discoveredPrinterInfoList_ =
            printSystemData_.GetDiscoveredPrinterInfo();
        for (const auto &pair : discoveredPrinterInfoList_) {
            std::string key = pair.first;
            std::shared_ptr<PrinterInfo> printerInfoPtr = pair.second;
            if (printerInfoPtr == nullptr) {
                PRINT_HILOGW("printerInfoPtr is nullptr");
                continue;
            }
            SendPrinterEvent(*printerInfoPtr, std::to_string(GetCurrentUserId()));
        }
        PRINT_HILOGI("end HandlePrinterStateChangeRegister");
    }
}

void PrintServiceAbility::HandlePrinterChangeRegister(const std::string &eventType)
{
    if (PrintUtils::GetEventType(eventType) == PRINTER_CHANGE_EVENT_TYPE) {
        PRINT_HILOGD("begin HandlePrinterChangeRegister, StartDiscoverPrinter");
        std::vector<PrintExtensionInfo> extensionInfos;
        QueryAllExtension(extensionInfos);
        std::vector<std::string> extensionIds;
        StartDiscoverPrinter(extensionIds);
        PrintCallerAppMonitor::GetInstance().IncrementPrintCounter("");
    }
}

bool PrintServiceAbility::UpdateAddedPrinterInCups(const std::string &printerId, const std::string &printerUri)
{
    PrinterInfo printer;
    if (printSystemData_.QueryAddedPrinterInfoByPrinterId(printerId, printer)) {
        std::string standardName = PrintUtil::StandardizePrinterName(printer.GetPrinterName());
        return DelayedSingleton<PrintCupsClient>::GetInstance()->ModifyCupsPrinterUri(standardName, printerUri);
    }
    return false;
}

std::string PrintServiceAbility::RenamePrinterWhenAdded(const PrinterInfo &info)
{
    PRINT_HILOGI("RenamePrinterWhenAdded start.");
    static uint32_t repeatNameLimit = 10;
    if (printSystemData_.IsPrinterAdded(info.GetPrinterId())) {  // 相同ID已添加，沿用之前的名字，更新信息
        return info.GetPrinterName();
    }
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

std::shared_ptr<PrinterInfo> PrintServiceAbility::QueryConnectingPrinterInfoById(const std::string &printerId)
{
    if (vendorManager.GetConnectingMethod(printerId) == IP_AUTO) {
        return printSystemData_.QueryIpPrinterInfoById(printerId);
    } else {
        return printSystemData_.QueryDiscoveredPrinterInfoById(printerId);
    }
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

void PrintServiceAbility::UnregisterPrintTaskCallback(
    const std::string &jobId, const uint32_t state, const uint32_t subState)
{
    if (subState != PRINT_JOB_SPOOLER_CLOSED_FOR_CANCELED && state != PRINT_JOB_COMPLETED) {
        PRINT_HILOGW("The job is not completed.");
        return;
    }
    auto unregisterTask = [this, jobId]() {
        for (auto event : PRINT_TASK_EVENT_LIST) {
            int32_t ret = Off(jobId, event);
            if (ret != E_PRINT_NONE) {
                PRINT_HILOGW(
                    "UnregisterPrintTaskCallback failed, ret = %{public}d, jobId = %{public}s, event = %{public}s",
                    ret,
                    jobId.c_str(),
                    event.c_str());
            }
        }
    };
    if (serviceHandler_ == nullptr) {
        PRINT_HILOGE("serviceHandler_ is nullptr");
        return;
    }
    serviceHandler_->PostTask(unregisterTask, UNREGISTER_CALLBACK_INTERVAL);
}

void PrintServiceAbility::BuildPrinterPreference(PrinterInfo &printerInfo)
{
    PrinterCapability cap;
    printerInfo.GetCapability(cap);
    PrinterPreferences preferences;
    printSystemData_.BuildPrinterPreference(cap, preferences);
    if (printerInfo.GetPrinterId().find(EPRINTID) != std::string::npos) {
        preferences.SetDefaultColorMode(PRINT_COLOR_MODE_MONOCHROME);
    }
    printerInfo.SetPreferences(preferences);
}

bool PrintServiceAbility::FlushCacheFileToUserData(const std::string &jobId)
{
    auto userData = GetUserDataByJobId(jobId);
    if (userData == nullptr) {
        PRINT_HILOGE("get userDate failed");
        return false;
    }
    return userData->FlushCacheFileToUserData(jobId);
}

bool PrintServiceAbility::DeleteCacheFileFromUserData(const std::string &jobId)
{
    auto userData = GetUserDataByJobId(jobId);
    if (userData == nullptr) {
        userData = GetCurrentUserData();
        if (userData == nullptr) {
            PRINT_HILOGE("get userDate failed");
            return false;
        }
    }
    return userData->DeleteCacheFileFromUserData(jobId);
}

bool PrintServiceAbility::OpenCacheFileFd(const std::string &jobId, std::vector<uint32_t> &fdList)
{
    auto userData = GetUserDataByJobId(jobId);
    if (userData == nullptr) {
        PRINT_HILOGE("get userDate failed");
        return false;
    }
    return userData->OpenCacheFileFd(jobId, fdList);
}

int32_t PrintServiceAbility::QueryQueuedPrintJobById(const std::string &printJobId, PrintJob &printJob)
{
    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return E_PRINT_INVALID_USERID;
    }
    return userData->QueryQueuedPrintJobById(printJobId, printJob);
}

int32_t PrintServiceAbility::QueryHistoryPrintJobById(const std::string &printJobId, PrintJob &printJob)
{
    PRINT_HILOGI("QueryHistoryPrintJobById start.");
    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return E_PRINT_INVALID_USERID;
    }
    return userData->QueryHistoryPrintJobById(printJobId, printJob);
}

bool PrintServiceAbility::AddPrintJobToHistoryList(const std::shared_ptr<PrintJob> &printjob)
{
    PRINT_HILOGI("AddPrintJobToHistoryList start.");
    auto currentUser = GetUserDataByJobId(printjob->GetJobId());
    if (currentUser == nullptr) {
        PRINT_HILOGE("Current user is not added.");
        return false;
    }
    return currentUser->AddPrintJobToHistoryList(printjob->GetPrinterId(), printjob->GetJobId(), printjob);
}

bool PrintServiceAbility::DeletePrintJobFromHistoryList(const std::string jobId)
{
    PRINT_HILOGI("DeletePrintJobFromHistoryList start.");
    auto currentUser = GetCurrentUserData();
    if (currentUser == nullptr) {
        PRINT_HILOGE("Current user is not added.");
        return false;
    }
    return currentUser->DeletePrintJobFromHistoryList(jobId);
}

void PrintServiceAbility::UpdatePageSizeNameWithPrinterInfo(PrinterInfo &printerInfo, PrintPageSize &pageSize)
{
    if (!PrintPageSize::FindPageSizeById(pageSize.GetId(), pageSize)) {
        PrinterCapability printerCapability;
        printerInfo.GetCapability(printerCapability);
        std::vector<PrintPageSize> supportedPageSizeList;
        printerCapability.GetSupportedPageSize(supportedPageSizeList);

        for (const auto &supportedPageSize : supportedPageSizeList) {
            if (supportedPageSize.GetId() == pageSize.GetId()) {
                PRINT_HILOGI("PrintJob Set PageSize id = %{public}s, name = %{public}s",
                    supportedPageSize.GetId().c_str(),
                    supportedPageSize.GetName().c_str());
                pageSize.SetName(supportedPageSize.GetName());
                break;
            }
        }
    }
}

void PrintServiceAbility::UpdatePrintJobOptionWithPrinterPreferences(Json::Value &jobOptions, PrinterInfo &printerInfo)
{
    PrinterPreferences preferences;
    printerInfo.GetPreferences(preferences);

    if (!jobOptions.isMember("isReverse") || !jobOptions["isReverse"].isBool()) {
        jobOptions["isReverse"] = preferences.GetDefaultReverse();
    }
    if (!jobOptions.isMember("isCollate") || !jobOptions["isCollate"].isBool()) {
        jobOptions["isCollate"] = preferences.GetDefaultCollate();
    }

    Json::Value preferencesJson = ConvertModifiedPreferencesToJson(preferences);
    if (preferencesJson.isNull()) {
        PRINT_HILOGW("cannot find any modified preferences");
        return;
    }
    jobOptions["advancedOptions"] = preferencesJson;
}

Json::Value PrintServiceAbility::ConvertModifiedPreferencesToJson(PrinterPreferences &preferences)
{
    std::string option = preferences.GetOption();
    PRINT_HILOGD("Print job option: %{public}s", option.c_str());
    Json::Value opsJson;
    if (!PrintJsonUtil::Parse(option, opsJson)) {
        PRINT_HILOGW("parse preferences options error");
        return Json::nullValue;
    }
    return opsJson;
}

void PrintServiceAbility::RefreshPrinterInfoByPpd()
{
#ifdef CUPS_ENABLE
    std::vector<std::string> printerIdList = printSystemData_.QueryAddedPrinterIdList();
    for (auto &printerId : printerIdList) {
        PrinterInfo printerInfo;
        if (!printSystemData_.QueryAddedPrinterInfoByPrinterId(printerId, printerInfo)) {
            continue;
        }
        PrinterCapability printerCaps;
        std::string ppdName;
        QueryPPDInformation(printerInfo.GetPrinterMake(), ppdName);
        if (ppdName.empty() || printerId.find(EPRINTID) != std::string::npos) {
            RefreshPrinterPageSize(printerInfo);
            BuildPrinterPreference(printerInfo);
        } else {
            int32_t ret = DelayedSingleton<PrintCupsClient>::GetInstance()->QueryPrinterCapabilityFromPPD(
                printerInfo.GetPrinterName(), printerCaps, ppdName);
            if (ret != E_PRINT_NONE) {
                PRINT_HILOGE("QueryPrinterCapabilityFromPPD error = %{public}d.", ret);
                continue;
            }
            printerInfo.SetCapability(printerCaps);
            BuildPrinterPreference(printerInfo);
        }
        std::string ppdHashCode = DelayedSingleton<PrintCupsClient>::GetInstance()->GetPpdHashCode(ppdName);
        printerInfo.SetPpdHashCode(ppdHashCode);
        printSystemData_.InsertAddedPrinter(printerId, printerInfo);
        printSystemData_.SavePrinterFile(printerId);
    }
#endif  // CUPS_ENABLE
}

int32_t PrintServiceAbility::ConnectUsbPrinter(const std::string &printerId)
{
    PRINT_HILOGI("[Printer: %{public}s] ConnectUsbPrinter start", PrintUtils::AnonymizePrinterId(printerId).c_str());
    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(printerId);
    if (printerInfo == nullptr) {
        PRINT_HILOGE("can not find the printer");
        return E_PRINT_INVALID_PRINTER;
    }
    if (!printerInfo->HasPrinterMake()) {
        PRINT_HILOGE("can not find printer make");
        return E_PRINT_INVALID_PRINTER;
    }
#ifdef CUPS_ENABLE
    std::string make = printerInfo->GetPrinterMake();
    auto ret = DelayedSingleton<PrintCupsClient>::GetInstance()->AddPrinterToCups(
        printerInfo->GetUri(), printerInfo->GetPrinterName(), make);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("AddPrinterToCups error = %{public}d.", ret);
        return ret;
    }
    PrinterCapability printerCaps;
    std::string ppdName;
    QueryPPDInformation(make, ppdName);
    ret = DelayedSingleton<PrintCupsClient>::GetInstance()->QueryPrinterCapabilityFromPPD(
        printerInfo->GetPrinterName(), printerCaps, ppdName);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("QueryPrinterCapabilityFromPPD error = %{public}d.", ret);
        return ret;
    }
    printerInfo->SetCapability(printerCaps);
    std::string ppdHashCode = DelayedSingleton<PrintCupsClient>::GetInstance()->GetPpdHashCode(ppdName);
    printerInfo->SetPpdHashCode(ppdHashCode);
    UpdatePrinterCapability(printerId, *printerInfo);

    printerInfo->SetPrinterState(PRINTER_UPDATE_CAP);
    SendPrinterEvent(*printerInfo);
    SendPrinterDiscoverEvent(PRINTER_UPDATE_CAP, *printerInfo);
    printSystemData_.SavePrinterFile(printerId);
#endif  // CUPS_ENABLE
    PRINT_HILOGI("ConnectUsbPrinter end");
    return E_PRINT_NONE;
}

void PrintServiceAbility::RefreshPrinterPageSize(PrinterInfo &printerInfo)
{
    PrinterCapability cap;
    printerInfo.GetCapability(cap);
    std::vector<PrintPageSize> pageSizeList;
    cap.GetSupportedPageSize(pageSizeList);
    pageSizeList.erase(std::remove_if(pageSizeList.begin(),
        pageSizeList.end(),
        [](PrintPageSize &pageSize) { return !pageSize.ConvertToPwgStyle(); }),
        pageSizeList.end());
    cap.SetSupportedPageSize(pageSizeList);
    printerInfo.SetCapability(cap);
}

#ifdef ENTERPRISE_ENABLE
void PrintServiceAbility::UpdateIsEnterprise()
{
    if (!IsEnterpriseEnable()) {
        PRINT_HILOGI("IsEnterpriseEnable false.");
        return;
    }
    int32_t localId = -1;
    AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(localId);
    lastUserId_ = localId;
    AccountSA::DomainAccountInfo domainInfo;
    auto ret = AccountSA::OsAccountManager::GetOsAccountDomainInfo(localId, domainInfo);
    PRINT_HILOGI("GetOsAccountDomainInfo ret = %{public}d", ret);
    if (ret == 0 && !domainInfo.accountName_.empty()) {
        isEnterprise_ = true;
    } else {
        isEnterprise_ = false;
    }
}

bool PrintServiceAbility::IsEnterprise()
{
    return isEnterprise_;
}

bool PrintServiceAbility::IsEnterpriseEnable()
{
    std::string enterpriseEnable = OHOS::system::GetParameter(ENTERPRISE_SPACE_PARAM, "");
    return enterpriseEnable == IS_ENTERPRISE_ENABLE;
}

bool PrintServiceAbility::RefreshPrinterStatusOnSwitchUser()
{
    if (!IsEnterpriseEnable()) {
        PRINT_HILOGW("IsEnterpriseEnable false.");
        return false;
    }

    PRINT_HILOGD("RefreshPrinterStatusOnSwitchUser");
    BlockUserPrintJobs(lastUserId_);
    UpdateIsEnterprise();
    if (IsEnterpriseEnable() && IsEnterprise()) {
        PrintCupsClient::GetInstance()->StopCupsdService();
    } else {
        PrintCupsClient::GetInstance()->StopCupsdEnterpriseService();
    }
    printSystemData_.Init();
    PrintCupsClient::GetInstance()->InitCupsResources();
    return true;
}
#endif  // ENTERPRISE_ENABLE

bool PrintServiceAbility::CheckPrintConstraint(std::string option, std::string jobId)
{
    bool unablePrint = false;
    int userId = GetCurrentUserId();
    auto ret = AccountSA::OsAccountManager::CheckOsAccountConstraintEnabled(userId, PRINT_CONSTRAINT, unablePrint);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("CheckOsAccountConstarintEnabled error = %{public}d.", ret);
    }
    PRINT_HILOGD("print constraint for user %{public}d is %{public}d.", userId, unablePrint);
#ifdef EDM_SERVICE_ENABLE
    if (unablePrint) {
        ReportEventAndUpdateJobState(option, jobId);
    }
#endif // EDM_SERVICE_ENABLE
    return unablePrint;
}

bool PrintServiceAbility::IsAppAlive(const std::string &bundleName, int32_t pid)
{
    auto callerAppInfo = std::make_shared<PrintCallerAppInfo>(pid, bundleName);
    return PrintCallerAppMonitor::GetInstance().IsAppAlive(callerAppInfo);
}

bool PrintServiceAbility::IsPrinterPpdUpdateRequired(
    const std::string &standardPrinterName, const std::string &ppdHashCode)
{
    std::string lastPrinterPpdHashCode;
    if (!printSystemData_.QueryPpdHashCodeByPrinterName(standardPrinterName, lastPrinterPpdHashCode)) {
        PRINT_HILOGD("PrintSystemData does not save printerPpdHashCode");
        return true;
    }
    if (lastPrinterPpdHashCode == ppdHashCode) {
        PRINT_HILOGD("The content of ppdhashCode is the same as the previous ppdhashCode");
        return false;
    }
    return true;
}

int32_t PrintServiceAbility::AnalyzePrintEvents(const std::string &printerId, const std::string &type,
    std::string &detail)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    detail = printSystemData_.AnalyzePrintEvents(printerId, type);
    return E_PRINT_NONE;
}

void PrintServiceAbility::AddPrintEvent(const std::string &printerId, const std::string &eventType, int32_t eventCode)
{
    printSystemData_.AddPrintEvent(printerId, eventType, eventCode);
}

void PrintServiceAbility::RegisterSettingDataObserver()
{
    if (!IsPcModeSupported()) {
        PRINT_HILOGW("Dose not support pc mode.");
        return;
    }
    PRINT_HILOGI("Support pc mode.");
    int32_t userId = GetCurrentUserId();
    if (userId == INVALID_USER_ID) {
        PRINT_HILOGE("Invalid user id.");
        return;
    }
    std::shared_ptr<PrintServiceHelper> helper = helper_;
    PrintSettingDataObserver::ObserverCallback observerCallback = [helper, userId]() {
        PRINT_HILOGI("observerCallback enter");
        if (helper == nullptr) {
            PRINT_HILOGE("Invalid print service helper.");
            return;
        }
        std::string value = PrintSettingDataHelper::GetInstance().Query(WINDOW_PCMODE_SWITCH_STATUS, userId, false);
        if (value.empty()) {
            PRINT_HILOGE("Query settings data failed.");
            return;
        }
        PRINT_HILOGI("observerCallback pcmode value: %{public}s", value.c_str());
        if (value == "false") {
            helper->DisconnectAbility();
        }
    };
    PrintSettingDataHelper::GetInstance().RegisterSettingDataObserver(
        WINDOW_PCMODE_SWITCH_STATUS, observerCallback, userId, false);
}

bool PrintServiceAbility::IsPcModeSupported()
{
    return system::GetParameter(PARAMETER_SUPPORT_WINDOW_PCMODE_SWITCH, "false") == "true";
}

int32_t PrintServiceAbility::AuthPrintJob(const std::string &jobId, const std::string &userName,
    char *userPasswd)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("[Job Id: %{public}s] AuthPrintJob start", jobId.c_str());
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);

    auto userData = GetCurrentUserData();
    if (userData == nullptr) {
        PRINT_HILOGE("Get user data failed.");
        return E_PRINT_INVALID_USERID;
    }
    auto printJob = std::make_shared<PrintJob>();
    auto jobIt = userData->queuedJobList_.find(jobId);
    if (jobIt == userData->queuedJobList_.end()) {
        if (QueryHistoryPrintJobById(jobId, *printJob) != E_PRINT_NONE) {
            PRINT_HILOGE("invalid job id");
            return E_PRINT_INVALID_PRINTJOB;
        }
    } else {
        printJob = jobIt->second;
    }

    auto printerInfo = printSystemData_.QueryDiscoveredPrinterInfoById(printJob->GetPrinterId());
    if (printerInfo == nullptr) {
        PRINT_HILOGE("can not find the printer");
        return E_PRINT_INVALID_PRINTER;
    }
#ifdef CUPS_ENABLE
    bool ret = DelayedSingleton<PrintCupsClient>::GetInstance()->AuthCupsPrintJob(printJob->GetJobId(),
        printerInfo->GetUri(), userName, userPasswd);
#endif // CUPS_ENABLE
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::QueryAllPrinterPpds(std::vector<PpdInfo> &printerPpdList)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service, ErrorCode: [%{public}d]", E_PRINT_NO_PERMISSION);
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("QueryAllPrinterPpds Enter");
    DelayedSingleton<PrintCupsClient>::GetInstance()->GetAllPPDFile(printerPpdList);
    PRINT_HILOGI("GetAllPPDFile count = %{public}zu", printerPpdList.size());
    PpdInfo info;
    info.SetPpdInfo("Generic", "System Default Driver", BSUNI_PPD_NAME);
    printerPpdList.push_back(info);
    return E_PRINT_NONE;
}

bool PrintServiceAbility::OnQueryCallBackEvent(const PrinterInfo &info)
{
    PRINT_HILOGI("Start CallBack Printerinfo");
    std::vector<PpdInfo> ppdInfos;
    std::string makeModel = info.GetPrinterMake();
    if (makeModel.empty()) {
        PRINT_HILOGE("Cannot Find makeModel");
    } else {
        if (!DelayedSingleton<PrintCupsClient>::GetInstance()->QueryAllPPDInformation(makeModel, ppdInfos)) {
            PRINT_HILOGE("Cannot Find Ppds");
        }
    }

    if (vendorManager.IsBsunidriverSupport(info)) {
        PpdInfo genericPpd;
        genericPpd.SetPpdInfo("Generic", "System Default Driver", BSUNI_PPD_NAME);
        ppdInfos.push_back(genericPpd);
    }

    for (auto eventIt : registeredListeners_) {
        if (PrintUtils::GetEventType(eventIt.first) != PRINT_QUERY_INFO_EVENT_TYPE) {
            continue;
        }
        if (eventIt.second == nullptr) {
            PRINT_HILOGD("eventIt.second is nullptr");
            continue;
        }
        eventIt.second->OnCallback(info, ppdInfos);
    }
    return true;
}

int32_t PrintServiceAbility::QueryPrinterInfoByIp(const std::string &printerIp)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service, ErrorCode: [%{public}d]", E_PRINT_NO_PERMISSION);
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("QueryPrinterInfoByIp Enter");
    printSystemData_.ClearPrintEvents(printerIp, CONNECT_PRINT_EVENT_TYPE);
    vendorManager.ClearConnectingPrinter();
    vendorManager.ClearConnectingProtocol();
    vendorManager.ClearConnectingPpdName();
    vendorManager.SetQueryPrinter(IP_AUTO, printerIp);
    std::string protocol = "auto";
    if (!vendorManager.ConnectPrinterByIp(printerIp, protocol)) {
        PRINT_HILOGW("ConnectPrinterByIp failed");
        return E_PRINT_SERVER_FAILURE;
    }
    PRINT_HILOGD("connecting printer by ip success");
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::ConnectPrinterByIpAndPpd(const std::string &printerIp, const std::string &protocol,
    const std::string &ppdName)
{
    ManualStart();
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service, ErrorCode: [%{public}d]", E_PRINT_NO_PERMISSION);
        return E_PRINT_NO_PERMISSION;
    }
    PRINT_HILOGI("ConnectPrinterByIpAndPpd Enter");
    printSystemData_.ClearPrintEvents(printerIp, CONNECT_PRINT_EVENT_TYPE);
    if (!vendorManager.ConnectPrinterByIpAndPpd(printerIp, protocol, ppdName)) {
        PRINT_HILOGW("ConnectPrinterByIpAndPpd failed");
            return E_PRINT_SERVER_FAILURE;
    }
    return E_PRINT_NONE;
}

int32_t PrintServiceAbility::SavePdfFileJob(const std::string &jobId, uint32_t fd)
{
    if (!CheckPermission(PERMISSION_NAME_PRINT_JOB)) {
        PRINT_HILOGE("no permission to access print service");
        return E_PRINT_NO_PERMISSION;
    }
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    int32_t userId = GetCurrentUserId();
    if (GetUserIdByJobId(jobId) != userId) {
        PRINT_HILOGE("Current user %{private}d is not the owner of the job %{private}s", userId, jobId.c_str());
        return E_PRINT_INVALID_USERID;
    }
#ifdef CUPS_ENABLE
    return DelayedSingleton<PrintCupsClient>::GetInstance()->CopyJobOutputFile(jobId, fd, true);
#endif // CUPS_ENABLE
    return E_PRINT_SERVER_FAILURE;
}

int32_t PrintServiceAbility::CheckPreferencesConflicts(const std::string &printerId, const std::string &changedType,
    const PrinterPreferences &printerPreference, std::vector<std::string> &conflictingOptions)
{
    PRINT_HILOGD("PrintServiceAbility CheckPreferencesConflicts in.");

#ifdef CUPS_ENABLE
    std::string ppdName;
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    int32_t ret = GetPpdNameByPrinterId(printerId, ppdName);
    if (ret != E_PRINT_NONE) {
        return ret;
    }

    return DelayedSingleton<PrintCupsClient>::GetInstance()->
        CheckPreferencesConflicts(ppdName, printerPreference, changedType, conflictingOptions);
#else
    return E_PRINT_NONE;
#endif
}

int32_t PrintServiceAbility::CheckPrintJobConflicts(const std::string &changedType,
    const PrintJob &printJob, std::vector<std::string> &conflictingOptions)
{
    PRINT_HILOGD("PrintServiceAbility CheckPrintJobConflicts in.");

#ifdef CUPS_ENABLE
    std::string ppdName;
    std::lock_guard<std::recursive_mutex> lock(apiMutex_);
    int32_t ret = GetPpdNameByPrinterId(printJob.GetPrinterId(), ppdName);
    if (ret != E_PRINT_NONE) {
        return ret;
    }

    PrintJob dupJob(printJob);
    UpdatePrintJobOptionByPrinterId(dupJob);

    return DelayedSingleton<PrintCupsClient>::GetInstance()->
        CheckPrintJobConflicts(ppdName, dupJob, changedType, conflictingOptions);
#else
    return E_PRINT_NONE;
#endif
}

int32_t PrintServiceAbility::GetPpdNameByPrinterId(const std::string& printerId, std::string& ppdName)
{
    PrinterInfo printerInfo;
    int ret = QueryPrinterInfoByPrinterId(printerId, printerInfo);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("QueryPrinterInfo failed! Id=%{public}s", printerId.c_str());
        return ret;
    }

    if (!QueryPPDInformation(printerInfo.GetPrinterMake(), ppdName)) {
        PRINT_HILOGE("Query printer ppd info failed! Id=%{public}s", printerId.c_str());
        return E_PRINT_INVALID_PRINTER;
    }

    return E_PRINT_NONE;
}

}  // namespace OHOS::Print
