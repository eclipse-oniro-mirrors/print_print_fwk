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

namespace OHOS::Print {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
static int32_t curRequestCode_ = 0;
class IKeyguardStateCallback;

struct AdapterParam {
    std::string documentName;
    bool isCheckFdList;
    PrintAttributes printAttributes;
};

class PrintServiceAbility : public SystemAbility, public PrintServiceStub {
    DECLARE_SYSTEM_ABILITY(PrintServiceAbility);

public:
    DISALLOW_COPY_AND_MOVE(PrintServiceAbility);
    PrintServiceAbility(int32_t systemAbilityId, bool runOnCreate);
    PrintServiceAbility();
    ~PrintServiceAbility();
    static sptr<PrintServiceAbility> GetInstance();
    int32_t StartPrint(const std::vector<std::string> &fileList,
        const std::vector<uint32_t> &fdList, std::string &taskId) override;
    int32_t StartPrint(const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList,
        std::string &taskId, const sptr<IRemoteObject> &token) override;
    int32_t StopPrint(const std::string &taskId) override;
    int32_t ConnectPrinter(const std::string &printerId) override;
    int32_t DisconnectPrinter(const std::string &printerId) override;
    int32_t StartDiscoverPrinter(const std::vector<std::string> &extensionList) override;
    int32_t StopDiscoverPrinter() override;
    int32_t QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos) override;
    int32_t StartPrintJob(const PrintJob &jobinfo) override;
    int32_t CancelPrintJob(const std::string &jobId) override;
    int32_t AddPrinters(const std::vector<PrinterInfo> &printerInfos) override;
    int32_t RemovePrinters(const std::vector<std::string> &printerIds) override;
    int32_t UpdatePrinters(const std::vector<PrinterInfo> &printerInfos) override;
    int32_t UpdatePrinterState(const std::string &printerId, uint32_t state) override;
    int32_t UpdatePrintJobState(const std::string &jobId, uint32_t state, uint32_t subState) override;
    int32_t UpdateExtensionInfo(const std::string &extInfo) override;
    int32_t RequestPreview(const PrintJob &jobinfo, std::string &previewResult) override;
    int32_t QueryPrinterCapability(const std::string &printerId) override;
    int32_t On(const std::string taskId, const std::string &type, const sptr<IPrintCallback> &listener) override;
    int32_t Off(const std::string taskId, const std::string &type) override;
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
        std::string &taskId, const sptr<IRemoteObject> &token) override;
    int32_t StartGetPrintFile(const std::string &jobId, const PrintAttributes &printAttributes,
        const uint32_t fd) override;
    int32_t NotifyPrintService(const std::string &jobId, const std::string &type) override;

protected:
    void OnStart() override;
    void OnStop() override;

private:
    int32_t Init();
    void InitServiceHandler();
    void ManualStart();
    std::string GetPrintJobId();
    bool StartAbility(const AAFwk::Want &want);
    bool KillAbility(const std::string bundleName);
    void KillAllAbility();
    bool StartPrintServiceExtension(const AAFwk::Want &want, int32_t curRequestCode_);
    PrintExtensionInfo ConvertToPrintExtensionInfo(const AppExecFwk::ExtensionAbilityInfo &extInfo);
    bool DelayStartDiscovery(const std::string &extensionId);
    void SendPrinterEvent(const PrinterInfo &info);
    void SendPrintJobEvent(const PrintJob &jobInfo);
    void SendExtensionEvent(const std::string &extensionId, const std::string &extInfo);
    bool CheckPermission(const std::string &permissionName);
    void SendQueuePrintJob(const std::string &printerId);
    void BuildFDParam(const std::vector<uint32_t> &fdList, AAFwk::Want &want);
    void DestroyExtension(const std::string &printerId);
    void NotifyAppJobQueueChanged(const std::string &applyResult);
    std::shared_ptr<PrinterInfo> getPrinterInfo(const std::string printerId);
    bool isEprint(const std::string &printerId);
    void ReportHisysEvent(const std::shared_ptr<PrintJob> &jobInfo, const std::string &printerId, uint32_t subState);
    void ReportCompletedPrint(const std::string &printerId);
    void CheckJobQueueBlocked(const PrintJob &jobInfo);
    int32_t CallSpooler(const std::vector<std::string> &fileList,
        const std::vector<uint32_t> &fdList, std::string &taskId, const std::shared_ptr<AdapterParam> &adapterParam);
    int32_t CallSpooler(const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList,
        std::string &taskId, const sptr<IRemoteObject> &token, const std::shared_ptr<AdapterParam> &adapterParam);
    void notifyAdapterJobChanged(const std::string jobId, const uint32_t state, const uint32_t subState);
    bool checkJobState(uint32_t state, uint32_t subState);
    int32_t CheckAndSendQueuePrintJob(const std::string &jobId, uint32_t state, uint32_t subState);
    void UpdateQueuedJobList(const std::string &jobId, const std::shared_ptr<PrintJob> &printJob);
    void StartPrintJobCB(const std::string &jobId, const std::shared_ptr<PrintJob> &printJob);
    void CreateDefaultAdapterParam(const std::shared_ptr<AdapterParam> &adapterParam);
    void BuildAdapterParam(
        const std::shared_ptr<AdapterParam> &adapterParam, AAFwk::Want &want, const std::string &jobId);
    void BuildPrintAttributesParam(const std::shared_ptr<AdapterParam> &adapterParam, AAFwk::Want &want);
    void ParseAttributesObjectParamForJson(const PrintAttributes &attrParam, nlohmann::json &attrJson);
    int32_t AdapterGetFileCallBack(const std::string &jobId, uint32_t state, uint32_t subState);

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
    std::map<std::string, PrintAttributes> printAttributesList_;

    std::map<std::string, std::shared_ptr<PrinterInfo>> printerInfoList_;
    std::map<std::string, std::unordered_map<std::string, bool>> printerJobMap_;

    std::string spoolerBundleName_;
    std::string spoolerAbilityName_;

    std::mutex lock_;
    uint64_t currentJobId_;
    std::shared_ptr<PrintServiceHelper> helper_;

    bool isJobQueueBlocked_;
};
}  // namespace OHOS::Print
#endif  // PRINT_SYSTEM_ABILITY_H
