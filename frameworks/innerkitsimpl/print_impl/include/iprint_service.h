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

#ifndef PRINT_SERVICE_INTERFACE_H
#define PRINT_SERVICE_INTERFACE_H

#include <string>
#include <vector>

#include "iprint_callback.h"
#include "iprint_extension_callback.h"
#include "iremote_broker.h"
#include "print_extension_info.h"
#include "print_job.h"
#include "printer_info.h"
#include "iprint_ipc_interface_code.h"

namespace OHOS::Print {
class IPrintService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Print.IPrintService");
    virtual int32_t StartPrint(const std::vector<std::string> &fileList,
        const std::vector<uint32_t> &fdList, std::string &taskId) = 0;
    virtual int32_t StartPrint(const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList,
        std::string &taskId, const sptr<IRemoteObject> &token) = 0;
    virtual int32_t StopPrint(const std::string &taskId) = 0;
    virtual int32_t ConnectPrinter(const std::string &printerId) = 0;
    virtual int32_t DisconnectPrinter(const std::string &printerId) = 0;
    virtual int32_t StartDiscoverPrinter(const std::vector<std::string> &extensionList) = 0;
    virtual int32_t StopDiscoverPrinter() = 0;
    virtual int32_t QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos) = 0;
    virtual int32_t StartPrintJob(const PrintJob &jobInfo) = 0;
    virtual int32_t CancelPrintJob(const std::string &jobId) = 0;
    virtual int32_t AddPrinters(const std::vector<PrinterInfo> &printerInfos) = 0;
    virtual int32_t RemovePrinters(const std::vector<std::string> &printerIds) = 0;
    virtual int32_t UpdatePrinters(const std::vector<PrinterInfo> &printerInfos) = 0;
    virtual int32_t UpdatePrinterState(const std::string &printerId, uint32_t state) = 0;
    virtual int32_t UpdatePrintJobState(const std::string &jobId, uint32_t state, uint32_t subState) = 0;
    virtual int32_t UpdateExtensionInfo(const std::string &extensionId) = 0;
    virtual int32_t RequestPreview(const PrintJob &jobinfo, std::string &previewResult) = 0;
    virtual int32_t QueryPrinterCapability(const std::string &printerId) = 0;
    virtual int32_t On(const std::string taskId, const std::string &type, const sptr<IPrintCallback> &listener) = 0;
    virtual int32_t Off(const std::string taskId, const std::string &type) = 0;
    virtual int32_t RegisterExtCallback(const std::string &extensionCID,
        const sptr<IPrintExtensionCallback> &listener) = 0;
    virtual int32_t UnregisterAllExtCallback(const std::string &extensionId) = 0;
    virtual int32_t LoadExtSuccess(const std::string &extensionId) = 0;
    virtual int32_t QueryAllPrintJob(std::vector<PrintJob> &printJobs) = 0;
    virtual int32_t QueryPrintJobById(std::string &printJobId, PrintJob &printjob) = 0;
    virtual int32_t AddPrinterToCups(const std::string &printerUri, const std::string &printerName,
        const std::string &printerMake) = 0;
    virtual int32_t QueryPrinterCapabilityByUri(const std::string &printerUri, const std::string &printerId,
        PrinterCapability &printerCaps) = 0;
    virtual int32_t PrintByAdapter(const std::string jobName, const PrintAttributes &printAttributes,
        std::string &taskId, const sptr<IRemoteObject> &token) = 0;
    virtual int32_t StartGetPrintFile(const std::string &jobId, const PrintAttributes &printAttributes,
        const uint32_t fd) = 0;
    virtual int32_t NotifyPrintService(const std::string &jobId, const std::string &type) = 0;
};
} // namespace OHOS::Print
#endif // PRINT_SERVICE_INTERFACE_H