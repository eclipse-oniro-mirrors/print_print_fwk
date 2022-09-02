/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "event_handler.h"
#include "iremote_object.h"
#include "system_ability.h"
#include "print_notify_interface.h"
#include "print_service_stub.h"


namespace OHOS::Print {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class IKeyguardStateCallback;

class PrintServiceAbility : public SystemAbility, public PrintServiceStub {
    DECLARE_SYSTEM_ABILITY(PrintServiceAbility);

public:
    DISALLOW_COPY_AND_MOVE(PrintServiceAbility);
    PrintServiceAbility(int32_t systemAbilityId, bool runOnCreate);
    PrintServiceAbility();
    ~PrintServiceAbility();
    static sptr<PrintServiceAbility> GetInstance();
    int32_t StartPrint() override;
    bool On(const std::string &type, uint32_t &state, PrinterInfo &info, const sptr<PrintNotifyInterface> &listener) override;
    bool Off(const std::string &type) override;
    bool AddPrinters(const std::vector<PrinterInfo>& arrayPrintInfo) override;
    bool RemovePrinters(const std::vector<PrinterInfo>& arrayPrintInfo) override;
    bool ConnectPrinter(uint32_t printerId) override;
    bool DisconnectPrinter(uint32_t printerId) override;
    bool QueryAllExtension(std::vector<PrinterExtensionInfo> &arrayExtensionInfo) override;
    bool StartDiscoverPrinter(const std::vector<uint32_t>& extensionList) override;
    bool StopDiscoverPrinter() override;
    bool StartPrintJob(const PrintJob& jobinfo) override; 
    bool CancelPrintJob(const PrintJob& jobinfo) override;
    bool UpdatePrinterState(uint32_t printerId, uint32_t state) override;
    bool UpdatePrinterJobState(uint32_t jobId, uint32_t state) override;
    bool RequestPreview(const PrintJob& jobinfo, std::string &previewResult) override;
    bool QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability) override;
    bool CheckPermission() override;
    bool RegisterExtCallback(uint32_t callbackId, const sptr<PrintExtcbInterface> &listener) override;
    bool UnregisterAllExtCallback() override;
    
    static void DataWriteInfo(PrinterInfo info, MessageParcel &data);
    static void DataWriteJob(PrintJob job, MessageParcel &data);
    static void NotifyPrintStateHandler(const std::string& type, uint32_t state, PrinterInfo info);
    static void NotifyJobStateHandler(const std::string& type, uint32_t state, PrintJob job);

protected:
    void OnStart() override;
    void OnStop() override;

private:
    int32_t Init();
    void InitServiceHandler();
    void ManualStart();
    int32_t GetTaskId();

private:
    ServiceRunningState state_;
    static std::mutex instanceLock_;
    static sptr<PrintServiceAbility> instance_;
    static std::shared_ptr<AppExecFwk::EventHandler> serviceHandler_;
    std::map<std::string, sptr<PrintNotifyInterface>> registeredListeners_;
    std::map<uint32_t, sptr<PrintExtcbInterface>> extCallbackMap_;
    std::vector<sptr<PrintNotifyInterface>> unlockVecListeners_;
    std::mutex listenerMapMutex_;
    std::mutex lock_;
    const int32_t startTime_ = 1900;
    const int32_t extraMonth_ = 1;
    int32_t currentTaskId_;
};
} // namespace OHOS::Print
#endif // PRINT_SYSTEM_ABILITY_H
