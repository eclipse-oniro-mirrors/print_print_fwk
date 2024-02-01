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

#ifndef PRINT_SERVICE_PROXY_H
#define PRINT_SERVICE_PROXY_H

#include "iprint_service.h"
#include "iremote_proxy.h"

namespace OHOS::Print {
class PrintServiceProxy : public IRemoteProxy<IPrintService> {
public:
    explicit PrintServiceProxy(const sptr<IRemoteObject> &object);
    ~PrintServiceProxy() = default;
    DISALLOW_COPY_AND_MOVE(PrintServiceProxy);
    int32_t StartPrint(const std::vector<std::string> &fileList,
        const std::vector<uint32_t> &fdList, std::string &taskId) override;
    int32_t StopPrint(const std::string &taskId) override;
    int32_t StartPrint(const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList,
        std::string &taskId, const sptr<IRemoteObject> &token) override;
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
    int32_t UpdateExtensionInfo(const std::string &extensionId) override;
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
    int32_t PrintByAdapter(const std::string printJobName, const PrintAttributes &printAttributes,
        std::string &taskId, const sptr<IRemoteObject> &token) override;
    int32_t StartGetPrintFile(const std::string &jobId, const PrintAttributes &printAttributes,
        const uint32_t fd) override;
    int32_t NotifyPrintService(const std::string &jobId, const std::string &type) override;

private:
    int32_t GetResult(int retCode, MessageParcel &reply);
    static inline BrokerDelegator<PrintServiceProxy> delegator_;
};
}  // namespace OHOS::Print
#endif  // PRINT_SERVICE_PROXY_H
