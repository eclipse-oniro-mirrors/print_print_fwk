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

#ifndef PRINT_MANAGER_H
#define PRINT_MANAGER_H

#include <map>
#include <mutex>
#include <condition_variable>
#include "iremote_object.h"
#include "refbase.h"
#include "print_extension_Info.h"
#include "print_notify_stub.h"
#include "print_job.h"
#include "print_service_interface.h"
#include "print_info.h"

namespace OHOS::Print {
class PrintSaDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit PrintSaDeathRecipient();
    ~PrintSaDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &object) override;
};

class PrintManager : public RefBase {
public:
    PrintManager();
    bool LoadPrintServer();
    void LoadServerSuccess();
    void LoadServerFail();
    ~PrintManager();
    static sptr<PrintManager> GetInstance();
    bool CheckPermission();
    
    void OnRemoteSaDied(const wptr<IRemoteObject> &object);

    //Client Napi
    int32_t Dummy();
    bool Print(uint32_t taskId);
    bool QueryAllExtension(std::vector<PrinterExtensionInfo> &arrayExtensionInfo);
    bool StartDiscoverPrinter(std::vector<uint32_t> extensionList);
    bool StopDiscoverPrinter();
    bool AddPrinters(std::vector<PrintInfo> arrayPrintInfo);
    bool RemovePrinters(std::vector<PrintInfo> arrayPrintInfo);
    bool ConnectPrinter(uint32_t printerId);
    bool DisconnectPrinter(uint32_t printerId);
    bool StartPrintJob(PrintJob jobinfo);
    bool CancelPrintJob(PrintJob jobinfo);
    bool UpdatePrinterState(uint32_t printerId, uint32_t state);
    bool UpdatePrinterJobState(uint32_t jobId, uint32_t state);
    bool RequestPreview(PrintJob jobinfo, std::string &previewResult);
    bool QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability);

    bool On(uint32_t taskId, const std::string& type, const sptr<PrintNotifyInterface>& listener);
    bool Off(uint32_t taskId, const std::string& type);

private:
    sptr<PrintServiceInterface> GetPrintServiceProxy();

private:
    static std::mutex instanceLock_;
    static sptr<PrintManager> instance_;
    sptr<PrintServiceInterface> printServiceProxy_;
    sptr<PrintSaDeathRecipient> deathRecipient_;
};
} // namespace OHOS::Print
#endif // PRINT_MANAGER_H
