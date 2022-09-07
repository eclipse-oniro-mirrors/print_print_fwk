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

#include "print_service_stub.h"

#include "ipc_skeleton.h"
#include "iprint_service.h"
#include "message_parcel.h"
#include "print_common.h"
#include "print_extension_info.h"
#include "print_job.h"
#include "print_log.h"

namespace OHOS::Print {
using namespace OHOS::HiviewDFX;

PrintServiceStub::PrintServiceStub()
{
    cmdMap_[CMD_START_PRINT] = &PrintServiceStub::OnStartPrint;
    cmdMap_[CMD_CONNECTPRINTER] = &PrintServiceStub::OnConnectPrinter;
    cmdMap_[CMD_DISCONNECTPRINTER] = &PrintServiceStub::OnDisconnectPrinter;
    cmdMap_[CMD_STARTDISCOVERPRINTER] = &PrintServiceStub::OnStartDiscoverPrinter;
    cmdMap_[CMD_STOPDISCOVERPRINTER] = &PrintServiceStub::OnStopDiscoverPrint;
    cmdMap_[CMD_QUERYALLEXTENSION] = &PrintServiceStub::OnQueryAllExtension;
    cmdMap_[CMD_STARTPRINTJOB] = &PrintServiceStub::OnStartPrintJob;
    cmdMap_[CMD_CANCELPRINTJOB] = &PrintServiceStub::OnCancelPrintJob;
    cmdMap_[CMD_ADDPRINTERS] = &PrintServiceStub::OnAddPrinters;
    cmdMap_[CMD_REMOVEPRINTERS] = &PrintServiceStub::OnRemovePrinters;
    cmdMap_[CMD_UPDATEPRINTERSTATE] = &PrintServiceStub::OnUpdatePrinterState;
    cmdMap_[CMD_UPDATEPRINTERJOBSTATE] = &PrintServiceStub::OnUpdatePrinterJobState;
    cmdMap_[CMD_REQUESTPREVIEW] = &PrintServiceStub::OnRequestPreview;
    cmdMap_[CMD_QUERYPRINTERCAPABILITY] = &PrintServiceStub::OnQueryPrinterCapability;
    cmdMap_[CMD_CHECKPERMISSION] = &PrintServiceStub::OnCheckPermission;
    cmdMap_[CMD_ON] = &PrintServiceStub::OnEventOn;
    cmdMap_[CMD_OFF] = &PrintServiceStub::OnEventOff;
    cmdMap_[CMD_REG_EXT_CB] = &PrintServiceStub::OnRegisterExtCallback;
    cmdMap_[CMD_UNREG_EXT_CB] = &PrintServiceStub::OnUnregisterAllExtCallback;
}

int32_t PrintServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PRINT_HILOGD("OnRemoteRequest started, code = %{public}d", code);
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        PRINT_HILOGE("Remote descriptor not the same as local descriptor.");
        return E_PRINT_IPC_ERROR;
    }

    auto itFunc = cmdMap_.find(code);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(data, reply);
        }
    }
    PRINT_HILOGW("default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool PrintServiceStub::OnStartPrint(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStartPrint in");
    bool result = StartPrint();
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnStartPrint out");
    return true;
}

bool PrintServiceStub::OnConnectPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnConnectPrinter in");
    bool result = ConnectPrinter(data.ReadInt32());
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnConnectPrinter out");
    return true;
}

bool PrintServiceStub::OnDisconnectPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnDisconnectPrinter in");
    bool result = DisconnectPrinter(data.ReadInt32());
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnDisconnectPrinter out");
    return true;
}

bool PrintServiceStub::OnStartDiscoverPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStartDiscoverPrinter in");
    std::vector<uint32_t> extensionList;
    uint32_t extensionListLength = data.ReadUint32();

    for (uint32_t i = 0; i < extensionListLength; i++) {
        extensionList.push_back(data.ReadUint32());
        PRINT_HILOGD("OnStartDiscoverPrinter = %{public}d", extensionList[i]);
    }

    bool result = StartDiscoverPrinter(extensionList);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnStartDiscoverPrinter out");
    return true;
}

bool PrintServiceStub::OnStopDiscoverPrint(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStopDiscoverPrint in");
    bool result = StopDiscoverPrinter();
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnStopDiscoverPrint out");
    return true;
}

bool PrintServiceStub::OnQueryAllExtension(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryAllExtension in");
    std::vector<PrintExtensionInfo> printerInfo;
    bool result = QueryAllExtension(printerInfo);
    if (result) {
        uint32_t printerInfoLegth = printerInfo.size();
        reply.WriteUint32(printerInfoLegth);

        for (uint32_t i = 0; i < printerInfoLegth; i++) {
            PRINT_HILOGI("PrintServiceProxy, ExtensionId = %{public}d", printerInfo[i].GetExtensionId());
            PRINT_HILOGI("PrintServiceProxy, VendorId = %{public}d", printerInfo[i].GetVendorId());
            PRINT_HILOGI("PrintServiceProxy, VendorName = %{public}s", printerInfo[i].GetVendorName().c_str());
            PRINT_HILOGI("PrintServiceProxy, VendorIcon = %{public}d", printerInfo[i].GetVendorIcon());
            PRINT_HILOGI("PrintServiceProxy, Version = %{public}s", printerInfo[i].GetVersion().c_str());

            reply.WriteUint32(printerInfo[i].GetExtensionId());
            reply.WriteUint32(printerInfo[i].GetVendorId());
            reply.WriteString(printerInfo[i].GetVendorName());
            reply.WriteUint32(printerInfo[i].GetVendorIcon());
            reply.WriteString(printerInfo[i].GetVersion());
        }
    }
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnQueryAllExtension out");
    return true;
}

bool PrintServiceStub::OnStartPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStartPrintJob in");
    PrintJob jobinfo;
    jobinfo.BuildFromParcel(data);
    jobinfo.Dump();
    bool result = StartPrintJob(jobinfo);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnStartPrintJob out");
    return true;
}

bool PrintServiceStub::OnCancelPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnCancelPrintJob in");
    PrintJob jobinfo;
    jobinfo.BuildFromParcel(data);
    jobinfo.Dump();

    bool result = CancelPrintJob(jobinfo);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnCancelPrintJob out");
    return true;
}

bool PrintServiceStub::OnAddPrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnAddPrinters in");
    std::vector<PrinterInfo> arrayPrintInfo;
    uint32_t arrayPrintInfoLength = data.ReadUint32();
    PRINT_HILOGD("OnStartDiscoverPrinter arrayPrintInfoLength = %{public}d", arrayPrintInfoLength);

    for (uint32_t i = 0; i < arrayPrintInfoLength; i++) {
        PrinterInfo printerInfo;
        MakePrinterInfo(data, printerInfo);
        arrayPrintInfo.push_back(printerInfo);
    }

    bool result = AddPrinters(arrayPrintInfo);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnAddPrinters out");
    return true;
}

bool PrintServiceStub::OnRemovePrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRemovePrinters in");
    std::vector<PrinterInfo> arrayPrintInfo;
    uint32_t arrayPrintInfoLength = data.ReadUint32();
    PRINT_HILOGD("OnStartDiscoverPrinter arrayPrintInfoLength = %{public}d", arrayPrintInfoLength);

    for (uint32_t i = 0; i < arrayPrintInfoLength; i++) {
        PrinterInfo printerInfo;
        MakePrinterInfo(data, printerInfo);
        arrayPrintInfo.push_back(printerInfo);
    }

    bool result = RemovePrinters(arrayPrintInfo);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnRemovePrinters out");
    return true;
}

bool PrintServiceStub::OnUpdatePrinterState(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterState in");
    uint32_t printerId = data.ReadUint32();
    uint32_t state = data.ReadUint32();
    PRINT_HILOGD("OnUpdatePrinterState printerId = %{public}d", printerId);
    PRINT_HILOGD("OnUpdatePrinterState state = %{public}d", state);
    bool result = UpdatePrinterState(printerId, state);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterState out");
    return true;
}

bool PrintServiceStub::OnUpdatePrinterJobState(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterJobState in");
    uint32_t jobId = data.ReadUint32();
    uint32_t state = data.ReadUint32();
    PRINT_HILOGD("OnUpdatePrinterJobState printerId = %{public}d", jobId);
    PRINT_HILOGD("OnUpdatePrinterJobState state = %{public}d", state);
    bool result = UpdatePrinterJobState(jobId, state);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterJobState out");
    return true;
}

bool PrintServiceStub::OnRequestPreview(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRequestPreview in");
    PrintJob jobinfo;
    jobinfo.BuildFromParcel(data);
    jobinfo.Dump();

    std::string previewResult = "";
    bool result = RequestPreview(jobinfo, previewResult);
    reply.WriteString(previewResult);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnRequestPreview out");
    return true;
}

bool PrintServiceStub::OnQueryPrinterCapability(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapability in");
    uint32_t printerId = data.ReadUint32();
    PRINT_HILOGD("printerId : %{public}d", printerId);
    PrinterCapability printerCapability;
    bool result = QueryPrinterCapability(printerId, printerCapability);
    printerCapability.ConvertToParcel(reply);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapability out");
    return true;
}

bool PrintServiceStub::OnCheckPermission(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnCheckPermission in");
    bool result = CheckPermission();
    if (!reply.WriteBool(result)) {
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnCheckPermission out");
    return true;
}

bool PrintServiceStub::OnEventOn(MessageParcel &data, MessageParcel &reply)
{
    uint32_t taskId = data.ReadUint32();
    std::string type = data.ReadString();
    PRINT_HILOGD("PrintServiceStub::OnEventOn taskId = %{public}d type=%{public}s ", taskId, type.c_str());
    if (type.empty()) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn type is null.");
        return false;
    }
    return true;
}

bool PrintServiceStub::OnEventOff(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnEventOff in");
    uint32_t taskId = data.ReadUint32();
    std::string type = data.ReadString();
    PRINT_HILOGD("PrintServiceStub::OnEventOff taskId = %{public}d type=%{public}s ", taskId, type.c_str());
    bool result = Off(type);
    if (!reply.WriteBool(result)) {
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnEventOff out");
    return true;
}

bool PrintServiceStub::OnRegisterExtCallback(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback in");
    uint32_t callbackId = data.ReadUint32();
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback remote is nullptr");
        if (!reply.WriteInt32(ERR_NONE)) {
            return false;
        }
        return true;
    }
    sptr<IPrintExtensionCallback> listener = iface_cast<IPrintExtensionCallback>(remote);
    if (listener.GetRefPtr() == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback listener is null");
        return false;
    }
    PrinterInfo info;
    bool result = RegisterExtCallback(callbackId, listener);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback fail");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback out");
    return true;
}

bool PrintServiceStub::OnUnregisterAllExtCallback(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback in");
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnUnregisterAllExtCallback remote is nullptr");
        if (!reply.WriteInt32(ERR_NONE)) {
            return false;
        }
        return true;
    }
    sptr<IPrintExtensionCallback> listener = iface_cast<IPrintExtensionCallback>(remote);
    if (listener.GetRefPtr() == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnUnregisterAllExtCallback listener is null");
        return false;
    }
    PrinterInfo info;
    bool result = UnregisterAllExtCallback();
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("PrintServiceStub::OnUnregisterAllExtCallback fail");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnUnregisterAllExtCallback out");
    return true;
}

void PrintServiceStub::MakePrintJob(MessageParcel &data, PrintJob &printJob)
{
    uint32_t fileLength = data.ReadUint32();
    std::vector<std::string> files;
    uint32_t index = 0;
    for (index = 0; index < fileLength; index++) {
        files.push_back(data.ReadString());
    }
    printJob.SetFiles(files);
    printJob.SetJobId(data.ReadUint32());
    printJob.SetPrintId(data.ReadUint32());
    printJob.SetJobState(data.ReadUint32());
    printJob.SetCopyNumber(data.ReadUint32());
    PrintRange range;
    range.SetStartPage(data.ReadUint32());
    range.SetEndPage(data.ReadUint32());
    uint32_t pageLength = data.ReadUint32();
    std::vector<uint32_t> rangePages;
    for (index = 0; index < pageLength; index++) {
        rangePages.push_back(data.ReadUint32());
    }
    range.SetPages(rangePages);
    printJob.SetPageRange(range);
    printJob.SetIsSequential(data.ReadUint32());
    PrintPageSize pageSize;
    pageSize.SetId(data.ReadString());
    pageSize.SetName(data.ReadString());
    pageSize.SetWidth(data.ReadUint32());
    pageSize.SetHeight(data.ReadUint32());
    printJob.SetPageSize(pageSize);
    printJob.SetIsLandscape(data.ReadUint32());
    printJob.SetColorMode(data.ReadUint32());
    printJob.SetDuplexMode(data.ReadUint32());
    PrintMargin minMargin;
    minMargin.SetTop(data.ReadUint32());
    minMargin.SetBottom(data.ReadUint32());
    minMargin.SetLeft(data.ReadUint32());
    minMargin.SetRight(data.ReadUint32());
    printJob.SetMargin(minMargin);
    PreviewAttribute previewAttr;
    previewAttr.SetResult(data.ReadString());
    range.Reset();
    range.SetStartPage(data.ReadUint32());
    range.SetEndPage(data.ReadUint32());
    uint32_t previewPageLength = data.ReadUint32();
    std::vector<uint32_t> previewRangePages;
    for (index = 0; index < previewPageLength; index++) {
        previewRangePages.push_back(data.ReadUint32());
    }
    range.SetPages(previewRangePages);
    previewAttr.SetPreviewRange(range);
    printJob.SetPreview(previewAttr);
}

void PrintServiceStub::MakePrinterInfo(MessageParcel &data, PrinterInfo &printerInfo)
{
    printerInfo.SetPrinterId(data.ReadUint32());
    printerInfo.SetPrinterName(data.ReadString());
    printerInfo.SetPrinterIcon(data.ReadUint32());
    printerInfo.SetPrinterState(data.ReadUint32());
    printerInfo.SetDescription(data.ReadString());
    uint32_t pageSizeLength = data.ReadUint32();
    uint32_t resolutionLength = data.ReadUint32();
    PRINT_HILOGI("OnAddPrinters pageSizeLength = %{public}d", pageSizeLength);
    PRINT_HILOGI("OnAddPrinters resolutionLength = %{public}d", resolutionLength);
    PrinterCapability cap;
    PrintMargin minMargin;

    minMargin.SetTop(data.ReadUint32());
    minMargin.SetBottom(data.ReadUint32());
    minMargin.SetLeft(data.ReadUint32());
    minMargin.SetRight(data.ReadUint32());
    cap.SetMinMargin(minMargin);

    if (pageSizeLength > 0) {
        std::vector<PrintPageSize> pageSizeList;
        for (uint32_t i = 0; i < pageSizeLength; i++) {
            PrintPageSize pageSize;
            pageSize.SetId(data.ReadString());
            pageSize.SetName(data.ReadString());
            pageSize.SetWidth(data.ReadUint32());
            pageSize.SetHeight(data.ReadUint32());
            pageSizeList.push_back(pageSize);
        }
        cap.SetPageSize(pageSizeList);
    }

    if (resolutionLength > 0) {
        std::vector<PrintResolution> resolutionList;
        for (uint32_t i = 0; i < resolutionLength; i++) {
            PrintResolution res;
            res.SetId(data.ReadUint32());
            res.SetHorizontalDpi(data.ReadUint32());
            res.SetVerticalDpi(data.ReadUint32());
            resolutionList.push_back(res);
        }
        cap.SetResolution(resolutionList);
    }

    cap.SetColorMode(data.ReadUint32());
    cap.SetDuplexMode(data.ReadUint32());
    printerInfo.SetCapability(cap);
    printerInfo.Dump();
}
} // namespace OHOS::Print
