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

#ifndef PRINT_SERVICE_INTERFACE_H
#define PRINT_SERVICE_INTERFACE_H

#include <string>
#include "print_notify_interface.h"
#include "print_extension_Info.h"
#include "print_info.h"
#include "print_job.h"
#include "iremote_broker.h"

namespace OHOS::Print {
class PrintServiceInterface : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Print.PrintServiceInterface");
    virtual int32_t Dummy() = 0;
    virtual bool ConnectPrinter(uint32_t printerId) = 0;
    virtual bool DisconnectPrinter(uint32_t printerId) = 0;
    virtual bool StartDiscoverPrinter(std::vector<uint32_t> extensionList) = 0;
    virtual bool StopDiscoverPrinter() = 0;
    virtual bool QueryAllExtension(std::vector<PrinterExtensionInfo> &arrayExtensionInfo) = 0;
    virtual bool StartPrintJob(PrintJob jobinfo) = 0;
    virtual bool CancelPrintJob(PrintJob jobinfo) = 0;
    virtual bool AddPrinters(std::vector<PrintInfo> arrayPrintInfo) = 0;
    virtual bool RemovePrinters(std::vector<PrintInfo> arrayPrintInfo) = 0;
    virtual bool UpdatePrinterState(uint32_t printerId, uint32_t state) = 0;
    virtual bool UpdatePrinterJobState(uint32_t jobId, uint32_t state) = 0;
    virtual bool RequestPreview(PrintJob jobinfo, std::string &previewResult) = 0;
    virtual bool QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability) = 0;
    virtual bool CheckPermission() = 0;
    virtual bool On(uint32_t taskId, const std::string &type, const sptr<PrintNotifyInterface> &listener) = 0;
    virtual bool Off(uint32_t taskId, const std::string &type) = 0;
};

enum {
    CMD_DUMMY,
    CMD_CONNECTPRINTER,
    CMD_DISCONNECTPRINTER,
    CMD_STARTDISCOVERPRINTER,
    CMD_STOPDISCOVERPRINTER,
    CMD_QUERYALLEXTENSION,
    CMD_STARTPRINTJOB,
    CMD_CANCELPRINTJOB,
    CMD_ADDPRINTERS,
    CMD_REMOVEPRINTERS,
    CMD_UPDATEPRINTERSTATE,
    CMD_UPDATEPRINTERJOBSTATE,
    CMD_REQUESTPREVIEW,
    CMD_QUERYPRINTERCAPABILITY,
    CMD_CHECKPERMISSION,
    CMD_ON,
    CMD_OFF,
};
} // namespace OHOS::Print
#endif // PRINT_SERVICE_INTERFACE_H