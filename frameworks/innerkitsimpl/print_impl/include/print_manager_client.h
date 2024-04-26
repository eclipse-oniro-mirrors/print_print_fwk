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
#ifdef PDFIUM_ENABLE
#include "fpdfview.h"
#endif // PDFIUM_ENABLE

namespace OHOS::Print {
class PrintManagerClient : public RefBase {
public:
    PrintManagerClient();
    ~PrintManagerClient();
    static sptr<PrintManagerClient> GetInstance();

    void OnRemoteSaDied(const wptr<IRemoteObject> &object);

    int32_t StartPrint(const std::vector<std::string> &fileList,
        const std::vector<uint32_t> &fdList, std::string &taskId);
    int32_t StopPrint(const std::string &taskId);
    int32_t StartPrint(const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList,
        std::string &taskId, const sptr<IRemoteObject> &token);
    int32_t QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos);
    int32_t StartDiscoverPrinter(const std::vector<std::string> &extensionList);
    int32_t StopDiscoverPrinter();
    int32_t AddPrinters(const std::vector<PrinterInfo> &printerInfos);
    int32_t RemovePrinters(const std::vector<std::string> &printerIds);
    int32_t UpdatePrinters(const std::vector<PrinterInfo> &printerInfos);
    int32_t ConnectPrinter(const std::string &printerId);
    int32_t DisconnectPrinter(const std::string &printerId);
    int32_t StartPrintJob(const PrintJob &jobinfo);
    int32_t CancelPrintJob(const std::string &jobId);
    int32_t UpdatePrinterState(const std::string &printerId, uint32_t state);
    int32_t UpdatePrintJobState(const std::string &jobId, uint32_t state, uint32_t subState);
    int32_t UpdateExtensionInfo(const std::string &extensionId);
    int32_t RequestPreview(const PrintJob &jobinfo, std::string &previewResult);
    int32_t QueryPrinterCapability(const std::string &printerId);
    int32_t QueryAllPrintJob(std::vector<PrintJob> &printJobs);
    int32_t QueryPrintJobById(std::string &printJobId, PrintJob &printjob);
    int32_t AddPrinterToCups(const std::string &printerUri, const std::string &printerName,
        const std::string &printerMake);
    int32_t QueryPrinterCapabilityByUri(const std::string &printerUri, const std::string &printerId,
        PrinterCapability &printerCaps);

    int32_t On(const std::string &taskId, const std::string &type, const sptr<IPrintCallback> &listener);
    int32_t Off(const std::string &taskId, const std::string &type);
    int32_t Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
        const std::shared_ptr<PrintAttributes> &printAttributes);
    int32_t Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
        const std::shared_ptr<PrintAttributes> &printAttributes, void* contextToken);
    int32_t Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
        const PrintAttributes &printAttributes);
    int32_t Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
        const PrintAttributes &printAttributes, void* contextToken);
    int32_t Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
        const PrintAttributes &printAttributes, std::string &taskId);
    int32_t Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
        const PrintAttributes &printAttributes, std::string &taskId, void* contextToken);
    int32_t StartGetPrintFile(const std::string &jobId, const PrintAttributes &printAttributes,
        const uint32_t fd);
    int32_t NotifyPrintService(const std::string &jobId, const std::string &type);
#ifdef PDFIUM_ENABLE
    int32_t PdfRenderInit(const std::string filePath, const std::string sandBoxPath, std::string &basePngName,
        int32_t &pageCount, FPDF_DOCUMENT &doc);
    int32_t PdfRenderDestroy(const std::string basePngName, const int32_t pageCount, FPDF_DOCUMENT &doc);
    int32_t GetPdfPageSize(const int32_t pageIndex, uint32_t &width, uint32_t &height, FPDF_DOCUMENT &doc);
    int32_t RenderPdfToPng(const std::string basePngName, const int32_t pageIndex, std::string &imagePath,
        FPDF_DOCUMENT &doc);
#endif // PDFIUM_ENABLE

    int32_t RegisterExtCallback(const std::string &extensionId, uint32_t callbackId, PrintExtCallback cb);
    int32_t RegisterExtCallback(const std::string &extensionId, uint32_t callbackId, PrintJobCallback cb);
    int32_t RegisterExtCallback(const std::string &extensionId, uint32_t callbackId, PrinterCallback cb);
    int32_t RegisterExtCallback(const std::string &extensionId, uint32_t callbackId, PrinterCapabilityCallback cb);
    int32_t UnregisterAllExtCallback(const std::string &extensionId);
    int32_t LoadExtSuccess(const std::string &extensionId);

    void LoadServerSuccess();
    void LoadServerFail();
    void SetProxy(const sptr<IRemoteObject> &obj);
    void ResetProxy();

private:
    bool LoadServer();
    bool GetPrintServiceProxy();
    int32_t runBase(const char* callerFunName, std::function<int32_t(sptr<IPrintService>)> func);
#define CALL_COMMON_CLIENT(func) runBase(__func__, func)

private:
    static std::mutex instanceLock_;
    static sptr<PrintManagerClient> instance_;
    std::mutex proxyLock_;
    sptr<IPrintService> printServiceProxy_;
    sptr<PrintSaDeathRecipient> deathRecipient_;

    std::map<std::string, sptr<PrintExtensionCallbackStub>> extCallbackMap_;

    std::mutex loadMutex_;
    std::mutex conditionMutex_;
    std::condition_variable syncCon_;
    bool ready_ = false;
    static constexpr int LOAD_SA_TIMEOUT_MS = 15000;
};
}  // namespace OHOS::Print
#endif  // PRINT_MANAGER_CLIENT_H
