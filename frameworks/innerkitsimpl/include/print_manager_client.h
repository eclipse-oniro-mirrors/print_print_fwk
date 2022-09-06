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

#ifndef PRINT_MANAGER_CLIENT_H
#define PRINT_MANAGER_CLIENT_H

#include <condition_variable>
#include <map>
#include <mutex>

#include "iprint_callback.h"
#include "iprint_service.h"
#include "iremote_object.h"
#include "print_extension_callback_stub.h"
#include "print_extension_info.h"
#include "print_job.h"
#include "print_sa_death_recipient.h"
#include "printer_info.h"
#include "refbase.h"

namespace OHOS::Print {
class PrintManagerClient : public RefBase {
public:
    PrintManagerClient();
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
    bool StartPrintJob(const PrintJob &jobinfo);
    bool CancelPrintJob(const PrintJob &jobinfo);
    bool UpdatePrinterState(uint32_t printerId, uint32_t state);
    bool UpdatePrinterJobState(uint32_t jobId, uint32_t state);
    bool RequestPreview(const PrintJob &jobinfo, std::string &previewResult);
    bool QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability);

    bool On(const std::string &type, uint32_t &state, PrinterInfo &info, const sptr<IPrintCallback> &listener);
    bool Off(const std::string &type);

    bool RegisterExtCallback(uint32_t callbackId, PrintExtCallback cb);
    bool RegisterExtCallback(uint32_t callbackId, PrintJobCallback cb);
    bool RegisterExtCallback(uint32_t callbackId, PrinterCallback cb);
    bool RegisterExtCallback(uint32_t callbackId, PrinterCapabilityCallback cb);
    bool UnregisterAllExtCallback();
    bool LoadServer();
    void LoadServerSuccess();
    void LoadServerFail();

private:
    sptr<IPrintService> GetPrintServiceProxy();

private:
    static std::mutex instanceLock_;
    static sptr<PrintManagerClient> instance_;
    sptr<IPrintService> printServiceProxy_;
    sptr<PrintSaDeathRecipient> deathRecipient_;

    std::map<uint32_t, sptr<PrintExtensionCallbackStub>> extCallbackMap_;

    std::mutex loadMutex_;
    std::mutex conditionMutex_;
    std::condition_variable syncCon_;
    bool ready_ = false;
    static constexpr int LOAD_SA_TIMEOUT_MS = 15000;
};
} // namespace OHOS::Print
#endif // PRINT_MANAGER_CLIENT_H