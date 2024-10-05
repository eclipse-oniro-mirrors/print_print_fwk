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

#ifndef PRINT_SERVICE_ABILITY_H
#define PRINT_SERVICE_ABILITY_H

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <nlohmann/json.hpp>

#include "ability_manager_client.h"
#include "event_handler.h"
#include "extension_ability_info.h"
#include "iprint_callback.h"
#include "iremote_object.h"
#include "print_constant.h"
#include "print_service_stub.h"
#include "system_ability.h"
#include "print_security_guard_manager.h"
#include "print_service_helper.h"
#include "print_user_data.h"
#include "print_system_data.h"
#include "print_attribute_preference.h"
#include "vendor_manager.h"

namespace OHOS::Print {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class IKeyguardStateCallback;

class PrintServiceAbility : public SystemAbility, public PrintServiceStub, public IPrintServiceAbility {
    DECLARE_SYSTEM_ABILITY(PrintServiceAbility);

public:
    DISALLOW_COPY_AND_MOVE(PrintServiceAbility);
    PrintServiceAbility(int32_t systemAbilityId, bool runOnCreate);
    PrintServiceAbility();
    ~PrintServiceAbility();
    static sptr<PrintServiceAbility> GetInstance();
    int32_t StartService() override;
    int32_t StartPrint(const std::vector<std::string> &fileList,
        const std::vector<uint32_t> &fdList, std::string &taskId) override;
    int32_t StopPrint(const std::string &taskId) override;
    int32_t ConnectPrinter(const std::string &printerId) override;
    int32_t DisconnectPrinter(const std::string &printerId) override;
    int32_t StartDiscoverPrinter(const std::vector<std::string> &extensionList) override;
    int32_t StopDiscoverPrinter() override;
    int32_t QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos) override;
    int32_t StartPrintJob(PrintJob &jobinfo) override;
    int32_t CancelPrintJob(const std::string &jobId) override;
    int32_t AddPrinters(const std::vector<PrinterInfo> &printerInfos) override;
    int32_t RemovePrinters(const std::vector<std::string> &printerIds) override;
    int32_t UpdatePrinters(const std::vector<PrinterInfo> &printerInfos) override;
    int32_t UpdatePrinterState(const std::string &printerId, uint32_t state) override;
    int32_t UpdatePrintJobStateOnlyForSystemApp(const std::string &jobId, uint32_t state, uint32_t subState) override;
    int32_t UpdateExtensionInfo(const std::string &extInfo) override;
    int32_t RequestPreview(const PrintJob &jobinfo, std::string &previewResult) override;
    int32_t QueryPrinterCapability(const std::string &printerId) override;
    int32_t On(const std::string taskId, const std::string &type, const sptr<IPrintCallback> &listener) override;
    int32_t Off(const std::string taskId, const std::string &type) override;
    int32_t RegisterPrinterCallback(const std::string &type, const sptr<IPrintCallback> &listener) override;
    int32_t UnregisterPrinterCallback(const std::string &type) override;
    int32_t RegisterExtCallback(const std::string &extensionCID,
        const sptr<IPrintExtensionCallback> &listener) override;
    int32_t UnregisterAllExtCallback(const std::string &extensionId) override;
    int32_t LoadExtSuccess(const std::string &extensionId) override;
    int32_t QueryAllPrintJob(std::vector<PrintJob> &printJobs) override;
    int32_t QueryPrintJobById(std::string &printJobId, PrintJob &printjob) override;
    int32_t AddPrinterToCups(const std::string &printerUri, const std::string &printerName,
        const std::string &printerMake) override;
    int32_t QueryPrinterCapabilityByUri(const std::string &printerUri, const std::string &printerId,
        PrinterCapability &printerCaps) override;
    void SetHelper(const std::shared_ptr<PrintServiceHelper> &helper);
    int32_t PrintByAdapter(const std::string jobName, const PrintAttributes &printAttributes,
        std::string &taskId) override;
    int32_t StartGetPrintFile(const std::string &jobId, const PrintAttributes &printAttributes,
        const uint32_t fd) override;
    int32_t NotifyPrintService(const std::string &jobId, const std::string &type) override;

    int32_t QueryPrinterInfoByPrinterId(const std::string &printerId, PrinterInfo &info) override;

    int32_t QueryAddedPrinter(std::vector<std::string> &printerNameList) override;

    int32_t QueryPrinterProperties(const std::string &printerId, const std::vector<std::string> &keyList,
        std::vector<std::string> &valueList) override;
    int32_t StartNativePrintJob(PrintJob &printJob) override;
    int32_t UpdatePrintJobState(const std::string &jobId, uint32_t state, uint32_t subState);
    void CancelUserPrintJobs(const int32_t userId);
    void NotifyCurrentUserChanged(const int32_t userId);
    int32_t NotifyPrintServiceEvent(std::string &jobId, uint32_t event) override;
    int32_t GetPrinterPreference(const std::string &printerId, std::string &printerPreference) override;
    int32_t SetPrinterPreference(const std::string &printerId, const std::string &printerPreference) override;
    int32_t SetDefaultPrinter(const std::string &printerId, uint32_t type) override;
    int32_t DeletePrinterFromCups(const std::string &printerUri, const std::string &printerName,
        const std::string &printerMake) override;
    int32_t DiscoverUsbPrinters(std::vector<PrinterInfo> &printers) override;
    int32_t AddPrinterToDiscovery(const PrinterInfo &printerInfo) override;
    int32_t UpdatePrinterInDiscovery(const PrinterInfo &printerInfo) override;
    int32_t RemovePrinterFromDiscovery(const std::string &printerId) override;

protected:
    void OnStart() override;
    void OnStop() override;

private:
    int32_t Init();
    void InitServiceHandler();
    void ManualStart();
    std::string GetPrintJobOrderId();
    bool StartAbility(const AAFwk::Want &want);
    PrintExtensionInfo ConvertToPrintExtensionInfo(const AppExecFwk::ExtensionAbilityInfo &extInfo);
    bool DelayStartDiscovery(const std::string &extensionId);
    void SendPrinterDiscoverEvent(int event, const PrinterInfo &info);
    void SendPrinterChangeEvent(int event, const PrinterInfo &info);
    void SendPrinterEvent(const PrinterInfo &info);
    void SendPrinterEventChangeEvent(PrinterEvent printerEvent, const PrinterInfo &info);
    void SendPrintJobEvent(const PrintJob &jobInfo);
    void SendExtensionEvent(const std::string &extensionId, const std::string &extInfo);
    bool CheckPermission(const std::string &permissionName);
    void SendQueuePrintJob(const std::string &printerId);
    void NotifyAppJobQueueChanged(const std::string &applyResult);
    bool isEprint(const std::string &printerId);
    void ReportHisysEvent(const std::shared_ptr<PrintJob> &jobInfo, const std::string &printerId, uint32_t subState);
    void ReportCompletedPrint(const std::string &printerId);
    void CheckJobQueueBlocked(const PrintJob &jobInfo);
    int32_t CallSpooler(const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList,
        std::string &taskId);
    void notifyAdapterJobChanged(const std::string jobId, const uint32_t state, const uint32_t subState);
    bool checkJobState(uint32_t state, uint32_t subState);
    int32_t CheckAndSendQueuePrintJob(const std::string &jobId, uint32_t state, uint32_t subState);
    void UpdateQueuedJobList(const std::string &jobId, const std::shared_ptr<PrintJob> &printJob);
    void StartPrintJobCB(const std::string &jobId, const std::shared_ptr<PrintJob> &printJob);
    void RegisterAdapterListener(const std::string &jobId);
    int32_t AdapterGetFileCallBack(const std::string &jobId, uint32_t state, uint32_t subState);
    bool UpdatePrintJobOptionByPrinterId(PrintJob &printJob);
    std::shared_ptr<PrintJob> AddNativePrintJob(const std::string &jobId, PrintJob &printJob);
    int32_t CallStatusBar();
    bool StartPluginPrintIconExtAbility(const AAFwk::Want &want);
    bool IsPrinterJobMapEmpty();
    int32_t GetCurrentUserId();
    void UpdatePrintUserMap();
    void AddToPrintJobList(std::string jobId, const std::shared_ptr<PrintJob> &printjob);
    std::shared_ptr<PrintUserData> GetCurrentUserData();
    int32_t GetUserIdByJobId(const std::string jobId);
    std::shared_ptr<PrintUserData> GetUserDataByJobId(const std::string jobId);
    bool IsQueuedJobListEmpty(const std::string &jobId);
    void SetPrintJobCanceled(PrintJob &jobinfo);
    void UnloadSystemAbility();
    void ReduceAppCount();
    void InitPreferenceMap();
    bool WritePreferenceToFile();
    bool WritePrinterPreference(const std::string &printerId, PrinterCapability &printerCaps);
    bool WriteEprinterPreference(const std::string &printerId, PrinterCapability &printerCaps);
    bool ReadPreferenceFromFile(const std::string &printerId, std::string& printPreference);
    int32_t BuildPrinterPreference(PrinterCapability &cap, PrinterPreference &printPreference);
    void BuildPrinterPreferenceByDefault(nlohmann::json& capOpt, PreferenceSetting &printerDefaultAttr);
    void BuildPrinterPreferenceByOption(std::string& key, std::string& supportedOpts,
        std::vector<std::string>& optAttrs);
    void BuildPrinterAttrComponentByJson(std::string& key, nlohmann::json& jsonArrObject,
        std::vector<std::string> &printerAttrs);
    bool CheckIsDefaultPrinter(const std::string &printerId);
    bool CheckIsLastUsedPrinter(const std::string &printerId);
    void SetLastUsedPrinter(const std::string &printerId);
    int32_t DestroyExtension();
    void DeletePrinterFromUserData(const std::string &printerId);
    std::shared_ptr<PrintUserData> GetUserDataByUserId(int32_t userId);
    PrintJobState DetermineUserJobStatus(const std::map<std::string, std::shared_ptr<PrintJob>> &jobList);
    void NotifyAppDeletePrinterWithDefaultPrinter(const std::string &printerId);
    void ChangeDefaultPrinterForDelete(std::shared_ptr<PrintUserData> &userData, const std::string &printerId);
    bool UpdatePrinterCapability(const std::string &printerId, const PrinterInfo &info);
    bool UpdatePrinterSystemData(const PrinterInfo &info);
    uint32_t GetListeningState(const uint32_t subState);
    uint32_t GetListeningState(uint32_t state, uint32_t subState);
    bool CheckPrintJob(PrintJob &jobInfo);
    bool CheckPrinterUriDifferent(const std::shared_ptr<PrinterInfo> &info);
    int32_t AddSinglePrinterInfo(const PrinterInfo &info, const std::string &extensionId);
    bool UpdateSinglePrinterInfo(const PrinterInfo &info, const std::string &extensionId);
    bool RemoveSinglePrinterInfo(const std::string &printerId);
    void HandlePrinterStateChangeRegister(const std::string &eventType);
    void HandlePrinterChangeRegister(const std::string &eventType);
public:
    bool AddVendorPrinterToDiscovery(const std::string &globalVendorName, const PrinterInfo &info) override;
    bool UpdateVendorPrinterToDiscovery(const std::string &globalVendorName, const PrinterInfo &info) override;
    bool RemoveVendorPrinterFromDiscovery(const std::string &globalVendorName, const std::string &printerId) override;
    bool AddVendorPrinterToCupsWithPpd(const std::string &globalVendorName, const std::string &printerId,
        const std::string &ppdData) override;
    bool RemoveVendorPrinterFromCups(const std::string &vendorName, const std::string &printerId) override;
    bool OnVendorStatusUpdate(const std::string &globalVendorName, const std::string &printerId,
        const PrinterVendorStatus &status) override;
    bool QueryPrinterCapabilityByUri(const std::string &uri, PrinterCapability &printerCap) override;
    bool QueryPrinterStatusByUri(const std::string &uri, PrinterStatus &status) override;
private:
    int32_t StartExtensionDiscovery(const std::vector<std::string> &extensionIds);
    int32_t StartPrintJobInternal(const std::shared_ptr<PrintJob> &printJob);
    int32_t QueryVendorPrinterInfo(const std::string &globalPrinterId, PrinterInfo &info);
    int32_t TryConnectPrinterByIp(const std::string &params);

private:
    PrintSecurityGuardManager securityGuardManager_;
    ServiceRunningState state_;
    static std::mutex instanceLock_;
    static sptr<PrintServiceAbility> instance_;
    static std::shared_ptr<AppExecFwk::EventHandler> serviceHandler_;
    static std::chrono::time_point<std::chrono::high_resolution_clock> startPrintTime_;
    static std::string ingressPackage;

    std::recursive_mutex apiMutex_;
    std::map<std::string, sptr<IPrintCallback>> registeredListeners_;
    std::map<std::string, sptr<IPrintCallback>> adapterListenersByJobId_;
    std::map<std::string, sptr<IPrintExtensionCallback>> extCallbackMap_;

    std::map<std::string, AppExecFwk::ExtensionAbilityInfo> extensionList_;
    std::map<std::string, PrintExtensionState> extensionStateList_;
    std::map<std::string, std::shared_ptr<PrintJob>> printJobList_;
    std::map<std::string, std::shared_ptr<PrintJob>> queuedJobList_;
    std::map<std::string, std::string, JobIdCmp> jobOrderList_;
    std::map<std::string, PrintAttributes> printAttributesList_;

    std::map<std::string, std::unordered_map<std::string, bool>> printerJobMap_;

    std::string spoolerBundleName_;
    std::string spoolerAbilityName_;

    std::mutex lock_;
    uint64_t currentJobOrderId_;
    std::shared_ptr<PrintServiceHelper> helper_;

    bool isJobQueueBlocked_;
    std::map<int64_t, std::shared_ptr<PrintUserData>> printUserDataMap_;
    PrintSystemData printSystemData_;
    std::map<int32_t, std::shared_ptr<PrintUserData>> printUserMap_;
    std::map<std::string, int32_t> userJobMap_;
    int32_t currentUserId_;

    uint32_t printAppCount_;
    uint32_t unloadCount_;
    std::map<std::string, std::string> printerIdAndPreferenceMap_;
    VendorManager vendorManager;
};
}  // namespace OHOS::Print
#endif  // PRINT_SYSTEM_ABILITY_H
