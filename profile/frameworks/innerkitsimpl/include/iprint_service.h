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

namespace OHOS::Print {
class IPrintService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Print.IPrintService");
    virtual int32_t StartPrint(const std::vector<std::string> &fileList, std::string &taskId) = 0;
    virtual int32_t StopPrint(const std::string &taskId) = 0;
    virtual int32_t ConnectPrinter(const std::string &printerId) = 0;
    virtual int32_t DisconnectPrinter(const std::string &printerId) = 0;
    virtual int32_t StartDiscoverPrinter(const std::vector<std::string> &extensionList) = 0;
    virtual int32_t StopDiscoverPrinter() = 0;
    virtual int32_t QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos) = 0;
    virtual int32_t StartPrintJob(const PrintJob &jobInfo) = 0;
    virtual int32_t CancelPrintJob(const PrintJob &jobInfo) = 0;
    virtual int32_t AddPrinters(const std::vector<PrinterInfo> &printerInfos) = 0;
    virtual int32_t RemovePrinters(const std::vector<std::string> &printerIds) = 0;
    virtual int32_t UpdatePrinters(const std::vector<PrinterInfo> &printerInfos) = 0;    
    virtual int32_t UpdatePrinterState(const std::string &printerId, uint32_t state) = 0;
    virtual int32_t UpdatePrintJobState(const std::string &jobId, uint32_t state, uint32_t subState) = 0;
    virtual int32_t UpdateExtensionInfo(const std::string &extensionId, const std::string &extInfo) = 0;
    virtual int32_t RequestPreview(const PrintJob &jobinfo, std::string &previewResult) = 0;
    virtual int32_t QueryPrinterCapability(const std::string &printerId, PrinterCapability &printerCapability) = 0;
    virtual int32_t On(const std::string &type, const sptr<IPrintCallback> &listener) = 0;
    virtual int32_t Off(const std::string &type) = 0;
    virtual int32_t RegisterExtCallback(const std::string extensionCID,
        const sptr<IPrintExtensionCallback> &listener) = 0;
    virtual int32_t UnregisterAllExtCallback(const std::string &extensionId) = 0;
    virtual int32_t Read(std::vector<uint8_t> &fileRead, const std::string &uri, uint32_t offset, uint32_t max) = 0;
};

enum {
    CMD_START_PRINT,
    CMD_STOP_PRINT,
    CMD_CONNECTPRINTER,
    CMD_DISCONNECTPRINTER,
    CMD_STARTDISCOVERPRINTER,
    CMD_STOPDISCOVERPRINTER,
    CMD_QUERYALLEXTENSION,
    CMD_STARTPRINTJOB,
    CMD_CANCELPRINTJOB,
    CMD_ADDPRINTERS,
    CMD_REMOVEPRINTERS,
    CMD_UPDATEPRINTERS,    
    CMD_UPDATEPRINTERSTATE,
    CMD_UPDATEPRINTJOBSTATE,
    CMD_UPDATEEXTENSIONINFO,    
    CMD_REQUESTPREVIEW,
    CMD_QUERYPRINTERCAPABILITY,
    CMD_ON,
    CMD_OFF,
    CMD_REG_EXT_CB,
    CMD_UNREG_EXT_CB,
    CMD_READ_DATA,
};
} // namespace OHOS::Print
#endif // PRINT_SERVICE_INTERFACE_H