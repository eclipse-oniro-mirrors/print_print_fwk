/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef PRINT_ENTRY_H
#define PRINT_ENTRY_H

#include <memory>
#include <string>
#include <stdint.h>
#include "ui_content.h"
#include "modal_ui_extension_config.h"
#include "want.h"
#include "ipc_skeleton.h"
#include "bundle_mgr_client.h"
#include "iremote_object.h"
#include "print_utils.h"
#include "print_extension_info.h"
#include "print_job.h"
#include "printer_info.h"
#include "print_attributes.h"
#include "print_resolution.h"
#include "print_margin.h"
#include "print_page_size.h"
#include "print_preview_attribute.h"
#include "print_range.h"
#include "print_resolution.h"
#include "printer_capability.h"
#include "printer_info.h"
#include "printer_preferences.h"
#include "iprint_callback.h"

namespace OHOS::Print {
class PrintEntry {
public:
    static PrintEntry& GetInstance();
    PrintEntry(const PrintEntry&) = delete;
    PrintEntry& operator=(const PrintEntry&) = delete;
    
    int32_t StartPrintWithContext(const std::vector<std::string>& files, std::shared_ptr<AbilityRuntime::Context> ctx);
    int32_t StartPrintWithAttributes(const std::string& jobName, std::shared_ptr<AbilityRuntime::Context> ctx,
        const PrintAttributes& attributes, const sptr<IPrintCallback> &listener);
    int32_t On(const std::string& type, const sptr<IPrintCallback> &listener);
    int32_t Off(const std::string& type);
    int32_t QueryAllExtension(std::vector<PrintExtensionInfo>& extensionInfos);
    int32_t StartDiscoverPrinter(const std::vector<std::string>& extensionList);
    int32_t StopDiscoverPrinter();
    int32_t ConnectPrinter(const std::string& printerId);
    int32_t DisconnectPrinter(const std::string& printerId);
    int32_t QueryPrinterCapability(const std::string& printerId);
    int32_t StartPrintJob(PrintJob& jobInfo);
    int32_t CancelPrintJob(const std::string& jobId);
    int32_t RequestPrintPreview(PrintJob& jobInfo, int32_t& result);
    int32_t AddPrinters(const std::vector<PrinterInfo>& printers);
    int32_t RemovePrinters(const std::vector<std::string>& printerIds);
    int32_t UpdatePrinters(const std::vector<PrinterInfo>& printers);
    int32_t UpdatePrinterState(const std::string& printerId, uint32_t state);
    int32_t UpdatePrintJobState(const std::string& jobId, uint32_t state, uint32_t subState);
    int32_t UpdateExtensionInfo(const std::string& info);
    int32_t QueryAllPrintJobs(std::vector<PrintJob>& jobs);
    int32_t QueryPrintJobList(std::vector<PrintJob>& jobs);
    int32_t QueryPrintJobById(std::string& jobId, PrintJob& job);
    int32_t StartGettingPrintFile(const std::string& jobId, const PrintAttributes& attrs, uint32_t fd);
    int32_t NotifyPrintService(const std::string &jobId, const std::string &type);
    int32_t GetAddedPrinters(std::vector<std::string>& printers);
    int32_t GetPrinterInfoById(const std::string& printerId, PrinterInfo& info);
    int32_t NotifyPrintServiceEvent(uint32_t event);
    int32_t AddPrinterToDiscovery(const PrinterInfo& printerInfo);
    int32_t UpdatePrinterInDiscovery(const PrinterInfo& printerInfo);
    int32_t RemovePrinterFromDiscovery(const std::string& printerId);
    int32_t QueryPrinterInfoByPrinterId(const std::string &printerId, PrinterInfo &info);
    
private:
    PrintEntry() = default;
    ~PrintEntry() = default;
    uint32_t CallSpooler(const std::shared_ptr<AdapterParam>& adapterParam,
        const std::vector<std::string>& files, std::shared_ptr<AbilityRuntime::Context> ctx);
    OHOS::Ace::UIContent* GetUIContent(std::shared_ptr<OHOS::AbilityRuntime::Context> ctx);
};
}  // namespace OHOS::Print
#endif  // PRINT_ENTRY_H
