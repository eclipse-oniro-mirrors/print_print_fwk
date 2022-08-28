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

#include "print_service_stub.h"
#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "print_extension_Info.h"
#include "print_common.h"
#include "print_job.h"
#include "print_service_interface.h"
#include "log.h"
#include <vector>

namespace OHOS::Print {
using namespace OHOS::HiviewDFX;

int32_t PrintServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PRINT_HILOGD("OnRemoteRequest started, code = %{public}d", code);
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        PRINT_HILOGE("Remote descriptor not the same as local descriptor.");
        return E_PRINT_TRANSACT_ERROR;
    }
    switch (code) {
        case CMD_DUMMY:
            return OnDummy(data, reply);
        case CMD_CONNECTPRINTER:
            return OnConnectPrinter(data, reply);
        case CMD_DISCONNECTPRINTER:
            return OnDisconnectPrinter(data, reply);
        case CMD_STARTDISCOVERPRINTER:
            return OnStartDiscoverPrinter(data, reply);
        case CMD_STOPDISCOVERPRINTER:
            return OnStopDiscoverPrint(data, reply);
        case CMD_QUERYALLEXTENSION:
            return OnQueryAllExtension(data, reply);       
        case CMD_STARTPRINTJOB:
            return OnStartPrintJob(data, reply);
        case CMD_CANCELPRINTJOB:
            return OnCancelPrintJob(data, reply);
        case CMD_ADDPRINTERS:
            return OnAddPrinters(data, reply);
        case CMD_REMOVEPRINTERS:
            return OnRemovePrinters(data, reply);
        case CMD_UPDATEPRINTERSTATE:
            return OnUpdatePrinterState(data, reply);
        case CMD_UPDATEPRINTERJOBSTATE:
            return OnUpdatePrinterJobState(data, reply);
        case CMD_REQUESTPREVIEW:
            return OnRequestPreview(data, reply);
        case CMD_QUERYPRINTERCAPABILITY:
            return OnQueryPrinterCapability(data, reply);
        case CMD_CHECKPERMISSION:
            return OnCheckPermission(data, reply);
        case CMD_ON:
            return OnEventOn(data, reply);
        case CMD_OFF:
            return OnEventOff(data, reply);
        default:
            PRINT_HILOGE("Default value received, check needed.");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return E_PRINT_OK;
}

bool PrintServiceStub::OnDummy(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
    int32_t fd  = data.ReadFileDescriptor();
    PRINT_HILOGI("Get FD from client, fd [%{public}d]", fd);
    int32_t result = Dummy();
    if (!reply.WriteInt32(result)) {
        PRINT_HILOGE("WriteBool failed");
        return false;
    }
    return true;
}

bool PrintServiceStub::OnConnectPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
    bool result = ConnectPrinter(data.ReadInt32());
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    return true;
}

bool PrintServiceStub::OnDisconnectPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
    bool result = DisconnectPrinter(data.ReadInt32());
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    return true;
}

bool PrintServiceStub::OnStartDiscoverPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
    std::vector<uint32_t> extensionList;
    uint32_t extensionListLength = data.ReadUint32();

    for(uint32_t i = 0; i < extensionListLength; i++)
    {
        extensionList.push_back(data.ReadUint32());
        PRINT_HILOGD("OnStartDiscoverPrinter = %{public}d", extensionList[i]);
    }
    
    bool result = StartDiscoverPrinter(extensionList);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    return true;
}

bool PrintServiceStub::OnStopDiscoverPrint(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
     bool result = StopDiscoverPrinter();
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    return true;
}

bool PrintServiceStub::OnQueryAllExtension(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
    std::vector<PrinterExtensionInfo> printerInfo;
    bool result = QueryAllExtension(printerInfo);
    if (result) {
        uint32_t printerInfoLegth = printerInfo.size();
        reply.WriteUint32(printerInfoLegth);

        for(uint32_t i = 0; i < printerInfoLegth; i++)
            {
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
    return true;
}

bool PrintServiceStub::OnStartPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
    PrintJob jobinfo;
    uint32_t fileLength = data.ReadUint32();
    for(uint32_t i = 0; i < fileLength; i++)
    {
        jobinfo.GetFiles().push_back(data.ReadString());

    }
    jobinfo.SetJobId(data.ReadUint32());
    jobinfo.SetPrintId(data.ReadUint32());
    jobinfo.SetJobState(data.ReadUint32());
    jobinfo.SetCopyNumber(data.ReadUint32());
    
    jobinfo.GetPageRange().SetStartPage(data.ReadUint32());
    jobinfo.GetPageRange().SetEndPage(data.ReadUint32());
    uint32_t pageLength = data.ReadUint32();
    for(uint32_t i = 0; i < pageLength; i++)
    {
         jobinfo.GetPageRange().SetPages(data.ReadUint32());
    }

    jobinfo.SetIsSequential(data.ReadUint32());

    jobinfo.GetPageSize().SetId(data.ReadUint32());
    jobinfo.GetPageSize().SetName(data.ReadString());
    jobinfo.GetPageSize().SetWidth(data.ReadUint32());
    jobinfo.GetPageSize().SetHeight(data.ReadUint32());

    jobinfo.SetIsLandscape(data.ReadUint32());
    jobinfo.SetColorMode(data.ReadUint32());
    jobinfo.SetDuplexMode(data.ReadUint32());

    jobinfo.GetMargin().SetTop(data.ReadUint32());
    jobinfo.GetMargin().SetBottom(data.ReadUint32());
    jobinfo.GetMargin().SetLeft(data.ReadUint32());
    jobinfo.GetMargin().SetRight(data.ReadUint32());

    jobinfo.GetPreview().SetResult(data.ReadString());
    jobinfo.GetPreview().GetPreviewRange().SetStartPage(data.ReadUint32());
    jobinfo.GetPreview().GetPreviewRange().SetEndPage(data.ReadUint32());
    uint32_t previewPageLength = data.ReadUint32();

    for(uint32_t i = 0; i < previewPageLength; i++)
    {
         jobinfo.GetPreview().GetPreviewRange().SetPages(data.ReadUint32());
    }
    
    jobinfo.Dump();
    jobinfo.GetPageRange().Dump();
    jobinfo.GetPageSize().Dump();
    jobinfo.GetMargin().Dump();
    jobinfo.GetPreview().Dump();
    jobinfo.GetPreview().GetPreviewRange().Dump();

    bool result = StartPrintJob(jobinfo);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    return true;
}

bool PrintServiceStub::OnCancelPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
    PrintJob jobinfo;
    uint32_t fileLength = data.ReadUint32();

    for(uint32_t i = 0; i < fileLength; i++)
    {
        jobinfo.GetFiles().push_back(data.ReadString());
    }

    jobinfo.SetJobId(data.ReadUint32());
    jobinfo.SetPrintId(data.ReadUint32());
    jobinfo.SetJobState(data.ReadUint32());
    jobinfo.SetCopyNumber(data.ReadUint32()); 
    jobinfo.GetPageRange().SetStartPage(data.ReadUint32());
    jobinfo.GetPageRange().SetEndPage(data.ReadUint32());
    uint32_t pageLength = data.ReadUint32();

    for(uint32_t i = 0; i < pageLength; i++)
    {
         jobinfo.GetPageRange().SetPages(data.ReadUint32());
    }

    jobinfo.SetIsSequential(data.ReadUint32());
    jobinfo.GetPageSize().SetId(data.ReadUint32());
    jobinfo.GetPageSize().SetName(data.ReadString());
    jobinfo.GetPageSize().SetWidth(data.ReadUint32());
    jobinfo.GetPageSize().SetHeight(data.ReadUint32());
    jobinfo.SetIsLandscape(data.ReadUint32());
    jobinfo.SetColorMode(data.ReadUint32());
    jobinfo.SetDuplexMode(data.ReadUint32());
    jobinfo.GetMargin().SetTop(data.ReadUint32());
    jobinfo.GetMargin().SetBottom(data.ReadUint32());
    jobinfo.GetMargin().SetLeft(data.ReadUint32());
    jobinfo.GetMargin().SetRight(data.ReadUint32());
    jobinfo.GetPreview().SetResult(data.ReadString());
    jobinfo.GetPreview().GetPreviewRange().SetStartPage(data.ReadUint32());
    jobinfo.GetPreview().GetPreviewRange().SetEndPage(data.ReadUint32());
    uint32_t previewPageLength = data.ReadUint32();

    for(uint32_t i = 0; i < previewPageLength; i++)
    {
         jobinfo.GetPreview().GetPreviewRange().SetPages(data.ReadUint32());
    }
    
    jobinfo.Dump();
    jobinfo.GetPageRange().Dump();
    jobinfo.GetPageSize().Dump();
    jobinfo.GetMargin().Dump();
    jobinfo.GetPreview().Dump();
    jobinfo.GetPreview().GetPreviewRange().Dump();
    bool result = CancelPrintJob(jobinfo);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    return true;
}

bool PrintServiceStub::OnAddPrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
    std::vector<PrintInfo> arrayPrintInfo;
    uint32_t arrayPrintInfoLength = data.ReadUint32();
    PRINT_HILOGD("OnStartDiscoverPrinter arrayPrintInfoLength = %{public}d", arrayPrintInfoLength);

    for(uint32_t i = 0; i < arrayPrintInfoLength; i++)
    {
        PrintInfo printInfo;
        printInfo.SetPrinterId(data.ReadUint32());
        printInfo.SetPrinterName(data.ReadString());
        printInfo.SetPrinterIcon(data.ReadUint32());
        printInfo.SetPrinterState(data.ReadUint32());
        printInfo.SetDescription(data.ReadString());
        uint32_t pageSizeLength = data.ReadUint32();
        uint32_t resolutionLength = data.ReadUint32();
        PRINT_HILOGI("OnStartDiscoverPrinter pageSizeLength = %{public}d", pageSizeLength);
        PRINT_HILOGI("OnStartDiscoverPrinter resolutionLength = %{public}d", resolutionLength);
        printInfo.GetCapability().GetMinMargin().SetTop(data.ReadUint32());
        printInfo.GetCapability().GetMinMargin().SetBottom(data.ReadUint32());
        printInfo.GetCapability().GetMinMargin().SetLeft(data.ReadUint32());
        printInfo.GetCapability().GetMinMargin().SetRight(data.ReadUint32());
        
        for(uint32_t i = 0; i < pageSizeLength; i++)
        {   
            PrinterPageSize printerPageSize;
            printerPageSize.SetId(data.ReadUint32());
            printerPageSize.SetName(data.ReadString());
            printerPageSize.SetWidth(data.ReadUint32());
            printerPageSize.SetHeight(data.ReadUint32());
            printInfo.GetCapability().GetPageSize().push_back(printerPageSize);
            printerPageSize.Dump();
        }

        for(uint32_t i = 0; i < resolutionLength; i++)
        {
            PrinterResolution printerResolution;
            printerResolution.SetId(data.ReadUint32());
            printerResolution.SetHorizontalDpi(data.ReadUint32());
            printerResolution.SetVerticalDpi(data.ReadUint32());
            printInfo.GetCapability().GetResolution().push_back(printerResolution);
            printerResolution.Dump();
        }

        printInfo.GetCapability().SetColorMode(data.ReadUint32());
        printInfo.GetCapability().SetDuplexMode(data.ReadUint32());
        arrayPrintInfo.push_back(printInfo);
        arrayPrintInfo[i].Dump();
        arrayPrintInfo[i].GetCapability().GetMinMargin().Dump();
    }

    bool result = AddPrinters(arrayPrintInfo);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    return true;
}

bool PrintServiceStub::OnRemovePrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
    std::vector<PrintInfo> arrayPrintInfo;
    uint32_t arrayPrintInfoLength = data.ReadUint32();
    PRINT_HILOGD("OnStartDiscoverPrinter arrayPrintInfoLength = %{public}d", arrayPrintInfoLength);

    for(uint32_t i = 0; i < arrayPrintInfoLength; i++)
    {
        PrintInfo printInfo;
        printInfo.SetPrinterId(data.ReadUint32());
        printInfo.SetPrinterName(data.ReadString());
        printInfo.SetPrinterIcon(data.ReadUint32());
        printInfo.SetPrinterState(data.ReadUint32());
        printInfo.SetDescription(data.ReadString());
        uint32_t pageSizeLength = data.ReadUint32();
        uint32_t resolutionLength = data.ReadUint32();
        PRINT_HILOGI("OnStartDiscoverPrinter pageSizeLength = %{public}d", pageSizeLength);
        PRINT_HILOGI("OnStartDiscoverPrinter resolutionLength = %{public}d", resolutionLength);
        printInfo.GetCapability().GetMinMargin().SetTop(data.ReadUint32());
        printInfo.GetCapability().GetMinMargin().SetBottom(data.ReadUint32());
        printInfo.GetCapability().GetMinMargin().SetLeft(data.ReadUint32());
        printInfo.GetCapability().GetMinMargin().SetRight(data.ReadUint32()); 
        
        for(uint32_t i = 0; i < pageSizeLength; i++)
        {   
            PrinterPageSize printerPageSize;
            printerPageSize.SetId(data.ReadUint32());
            printerPageSize.SetName(data.ReadString());
            printerPageSize.SetWidth(data.ReadUint32());
            printerPageSize.SetHeight(data.ReadUint32());
            printInfo.GetCapability().GetPageSize().push_back(printerPageSize);

            printerPageSize.Dump();

        }

        for(uint32_t i = 0; i < resolutionLength; i++)
        {
            PrinterResolution printerResolution;
            printerResolution.SetId(data.ReadUint32());
            printerResolution.SetHorizontalDpi(data.ReadUint32());
            printerResolution.SetVerticalDpi(data.ReadUint32());
            printInfo.GetCapability().GetResolution().push_back(printerResolution);
            printerResolution.Dump();
        }

        printInfo.GetCapability().SetColorMode(data.ReadUint32());
        printInfo.GetCapability().SetDuplexMode(data.ReadUint32());
        arrayPrintInfo.push_back(printInfo);
        arrayPrintInfo[i].Dump();
        arrayPrintInfo[i].GetCapability().GetMinMargin().Dump();
    }

    bool result = RemovePrinters(arrayPrintInfo);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    return true;
}

bool PrintServiceStub::OnUpdatePrinterState(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
    uint32_t printerId = data.ReadUint32();
    uint32_t state = data.ReadUint32();
    PRINT_HILOGD("OnStartDiscoverPrinter printerId = %{public}d", printerId);
    PRINT_HILOGD("OnStartDiscoverPrinter state = %{public}d", state);
    bool result = UpdatePrinterState(printerId, state);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    return true;
}

bool PrintServiceStub::OnUpdatePrinterJobState(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
    uint32_t jobId = data.ReadUint32();
    uint32_t state = data.ReadUint32();
    PRINT_HILOGD("OnStartDiscoverPrinter printerId = %{public}d", jobId);
    PRINT_HILOGD("OnStartDiscoverPrinter state = %{public}d", state);
    bool result = UpdatePrinterJobState(jobId, state);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    return true;
}

bool PrintServiceStub::OnRequestPreview(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
	PrintJob jobinfo;
    uint32_t fileLength = data.ReadUint32();

    for(uint32_t i = 0; i < fileLength; i++)
    {
        jobinfo.GetFiles().push_back(data.ReadString());

    }

    jobinfo.SetJobId(data.ReadUint32());
    jobinfo.SetPrintId(data.ReadUint32());
    jobinfo.SetJobState(data.ReadUint32());
    jobinfo.SetCopyNumber(data.ReadUint32());
    jobinfo.GetPageRange().SetStartPage(data.ReadUint32());
    jobinfo.GetPageRange().SetEndPage(data.ReadUint32());
    uint32_t pageLength = data.ReadUint32();

    for(uint32_t i = 0; i < pageLength; i++)
    {
        jobinfo.GetPageRange().SetPages(data.ReadUint32());
    }

    jobinfo.SetIsSequential(data.ReadUint32());
    jobinfo.GetPageSize().SetId(data.ReadUint32());
    jobinfo.GetPageSize().SetName(data.ReadString());
    jobinfo.GetPageSize().SetWidth(data.ReadUint32());
    jobinfo.GetPageSize().SetHeight(data.ReadUint32());
    jobinfo.SetIsLandscape(data.ReadUint32());
    jobinfo.SetColorMode(data.ReadUint32());
    jobinfo.SetDuplexMode(data.ReadUint32());
    jobinfo.GetMargin().SetTop(data.ReadUint32());
    jobinfo.GetMargin().SetBottom(data.ReadUint32());
    jobinfo.GetMargin().SetLeft(data.ReadUint32());
    jobinfo.GetMargin().SetRight(data.ReadUint32());
    jobinfo.GetPreview().SetResult(data.ReadString());
    jobinfo.GetPreview().GetPreviewRange().SetStartPage(data.ReadUint32());
    jobinfo.GetPreview().GetPreviewRange().SetEndPage(data.ReadUint32());
    uint32_t previewPageLength = data.ReadUint32();

    for(uint32_t i = 0; i < previewPageLength; i++)
    {
        jobinfo.GetPreview().GetPreviewRange().SetPages(data.ReadUint32());
    }
    
    jobinfo.Dump();
    jobinfo.GetPageRange().Dump();
    jobinfo.GetPageSize().Dump();
    jobinfo.GetMargin().Dump();
    jobinfo.GetPreview().Dump();
    jobinfo.GetPreview().GetPreviewRange().Dump();
    std::string previewResult = "";
    bool result = RequestPreview(jobinfo, previewResult);
    reply.WriteString(previewResult);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
    return true;
}

bool PrintServiceStub::OnQueryPrinterCapability(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("Receive request");
    PrinterCapability printerCapability;
    bool result = QueryPrinterCapability(data.ReadUint32(), printerCapability);
    printerCapability.Dump();
    printerCapability.GetMinMargin().Dump();
    printerCapability.GetPageSize()[0].Dump();
    printerCapability.GetResolution()[0].Dump();
    uint32_t arraypageSizeLength = printerCapability.GetPageSize().size();
    reply.WriteUint32(arraypageSizeLength);
    uint32_t resolutionLength = printerCapability.GetResolution().size();
    reply.WriteUint32(resolutionLength);
    reply.WriteUint32(printerCapability.GetMinMargin().GetTop());
    reply.WriteUint32(printerCapability.GetMinMargin().GetBottom());
    reply.WriteUint32(printerCapability.GetMinMargin().GetLeft());
    reply.WriteUint32(printerCapability.GetMinMargin().GetRight());

    for(uint32_t i = 0; i < arraypageSizeLength; i++)
    {
        reply.WriteUint32(printerCapability.GetPageSize()[i].GetId());
        reply.WriteString(printerCapability.GetPageSize()[i].GetName());
        reply.WriteUint32(printerCapability.GetPageSize()[i].GetWidth());
        reply.WriteUint32(printerCapability.GetPageSize()[i].GetHeight());
    }
     
      for(uint32_t i = 0; i < resolutionLength; i++)
    {
        reply.WriteUint32(printerCapability.GetResolution()[i].GetId());
        reply.WriteUint32(printerCapability.GetResolution()[i].GetHorizontalDpi());
        reply.WriteUint32(printerCapability.GetResolution()[i].GetVerticalDpi());
    }

    reply.WriteUint32(printerCapability.GetColorMode());
    reply.WriteUint32(printerCapability.GetDuplexMode());
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("WriteBool failed");
        return false;
    }
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
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnEventOn remote is nullptr");
        if (!reply.WriteInt32(ERR_NONE)) {
            return false;
        }
        return true;
    }
    sptr<PrintNotifyInterface> listener = iface_cast<PrintNotifyInterface>(remote);
    if (listener.GetRefPtr() == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnEventOn listener is null");
        return false;
    }
    bool result = On(taskId, type, listener);
    if (!reply.WriteBool(result)) {
        PRINT_HILOGD("PrintServiceStub::OnEventOn 4444");
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnEventOn out");
    return true;
}

bool PrintServiceStub::OnEventOff(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnEventOff in");
    uint32_t taskId = data.ReadUint32();
    std::string type = data.ReadString();
    PRINT_HILOGD("PrintServiceStub::OnEventOff taskId = %{public}d type=%{public}s ", taskId, type.c_str());
    bool result = Off(taskId, type);
    if (!reply.WriteBool(result)) {
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnEventOff out");
    return true;
}
} // namespace OHOS::Print
