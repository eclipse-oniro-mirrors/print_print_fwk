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

#include <condition_variable>
#include <map>
#include <mutex>

#include "iremote_object.h"
#include "print_extcb_stub.h"
#include "print_extension_info.h"
#include "print_job.h"
#include "print_notify_interface.h"
#include "print_service_interface.h"
#include "printer_info.h"
#include "refbase.h"

namespace OHOS::Print {
class PrintSaDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit PrintSaDeathRecipient();
    ~PrintSaDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &object) override;
};

class PrintManagerClient : public RefBase {
public:
    PrintManagerClient();
    bool LoadPrintServer();
    void LoadServerSuccess();
    void LoadServerFail();
    ~PrintManagerClient();
    static sptr<PrintManagerClient> GetInstance();
    bool CheckPermission();

    void OnRemoteSaDied(const wptr<IRemoteObject> &object);

    // Client Napi
    int32_t StartPrint();
    bool QueryAllExtension(std::vector<PrinterExtensionInfo> &arrayExtensionInfo);
    bool StartDiscoverPrinter(std::vector<uint32_t> extensionList);
    bool StopDiscoverPrinter();
    bool AddPrinters(std::vector<PrinterInfo> arrayPrintInfo);
    bool RemovePrinters(std::vector<PrinterInfo> arrayPrintInfo);
    bool ConnectPrinter(uint32_t printerId);
    bool DisconnectPrinter(uint32_t printerId);
    bool StartPrintJob(PrintJob jobinfo);
    bool CancelPrintJob(PrintJob jobinfo);
    bool UpdatePrinterState(uint32_t printerId, uint32_t state);
    bool UpdatePrinterJobState(uint32_t jobId, uint32_t state);
    bool RequestPreview(PrintJob jobinfo, std::string &previewResult);
    bool QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability);

    bool On(const std::string &type, uint32_t &state, PrinterInfo &info, const sptr<PrintNotifyInterface> &listener);
    bool Off(const std::string &type);

    bool RegisterExtCallback(uint32_t callbackId, PrintExtCallback cb);
    bool RegisterExtCallback(uint32_t callbackId, PrintJobCallback cb);
    bool RegisterExtCallback(uint32_t callbackId, PrinterCallback cb);
    bool UnregisterAllExtCallback();

private:
    sptr<PrintServiceInterface> GetPrintServiceProxy();

private:
    static std::mutex instanceLock_;
    static sptr<PrintManagerClient> instance_;
    sptr<PrintServiceInterface> printServiceProxy_;
    sptr<PrintSaDeathRecipient> deathRecipient_;

    std::map<uint32_t, sptr<PrintExtcbStub>> extCallbackMap_;
};
} // namespace OHOS::Print
#endif // PRINT_MANAGER_H
