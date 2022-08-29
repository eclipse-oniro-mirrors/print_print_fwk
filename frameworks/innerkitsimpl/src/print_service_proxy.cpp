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
#include "print_service_proxy.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "print_info.h"
#include "iremote_broker.h"
#include "log.h"
#include "print_job.h"
#include "print_common.h"

namespace OHOS::Print {
using namespace OHOS::HiviewDFX;

PrintServiceProxy::PrintServiceProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<PrintServiceInterface>(object)
{
}

int32_t PrintServiceProxy::Dummy()
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("PrintServiceProxy Dummy started.");
    bool ret = Remote()->SendRequest(CMD_DUMMY, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("Dummy, ret = %{public}d", ret);
        return -1;
    }
    int32_t taskId = reply.ReadInt32();
    PRINT_HILOGD("PrintServiceProxy Dummy succeeded. TaskId = %{public}d", taskId);
    return taskId;
}

bool PrintServiceProxy::ConnectPrinter(uint32_t printerId)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    data.WriteUint32(printerId);
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_CONNECTPRINTER, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    PRINT_HILOGD("PrintServiceProxy ConnectPrinter succeeded.");
    return true;
}

bool PrintServiceProxy::DisconnectPrinter(uint32_t printerId)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    data.WriteUint32(printerId);
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_DISCONNECTPRINTER, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    PRINT_HILOGD("PrintServiceProxy DisconnectPrinter succeeded.");
    return true;
}

bool PrintServiceProxy::QueryAllExtension(std::vector<PrinterExtensionInfo> &arrayExtensionInfo)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    data.WriteUint32(5);
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_QUERYALLEXTENSION, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    uint32_t replyArrayLength = reply.ReadUint32();
    for(uint32_t i = 0; i < replyArrayLength; i++)
    {
        PrinterExtensionInfo printerExtensionInfo;
        printerExtensionInfo.SetExtensionId(reply.ReadUint32());
        printerExtensionInfo.SetVendorId(reply.ReadUint32());
        printerExtensionInfo.SetVendorName(reply.ReadString());
        printerExtensionInfo.SetVendorIcon(reply.ReadUint32());
        printerExtensionInfo.SetVersion(reply.ReadString());
        arrayExtensionInfo.push_back(printerExtensionInfo);
        arrayExtensionInfo[i].Dump();
    }
    return true;
}

bool PrintServiceProxy::StartDiscoverPrinter(std::vector<uint32_t> extensionList)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    data.WriteUint32(extensionList.size());
    PRINT_HILOGD("OnStartDiscoverPrinter extensionList.size() = %{public}lu", extensionList.size());
    for(uint32_t i = 0; i < extensionList.size(); i++)
    {
        data.WriteUint32(extensionList[i]);
    }
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_STARTDISCOVERPRINTER, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    PRINT_HILOGD("PrintServiceProxy StartDiscoverPrinter succeeded.");
    return true;
}

bool PrintServiceProxy::StopDiscoverPrinter()
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_STOPDISCOVERPRINTER, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    PRINT_HILOGD("PrintServiceProxy StopDiscoverPrinter succeeded.");
    return true;
}

bool PrintServiceProxy::StartPrintJob(PrintJob jobinfo)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    
    uint32_t fileLength = jobinfo.GetFiles().size();
    data.WriteUint32(fileLength);
    for(uint32_t i = 0; i < fileLength; i++)
    {
        data.WriteString(jobinfo.GetFiles()[i]);

    }
    data.WriteUint32(jobinfo.GetJobId());
    data.WriteUint32(jobinfo.GetPrinterId());
    data.WriteUint32(jobinfo.GetJobState());
    data.WriteUint32(jobinfo.GetCopyNumber());

    data.WriteUint32(jobinfo.GetPageRange().GetStartPage());
    data.WriteUint32(jobinfo.GetPageRange().GetEndPage());
    uint32_t pageLength = jobinfo.GetPageRange().GetPages().size();
    data.WriteUint32(pageLength);
    for(uint32_t i = 0; i < pageLength; i++)
    {
         data.WriteUint32(jobinfo.GetPageRange().GetPages()[i]);
    }

    data.WriteUint32(jobinfo.GetIsSequential());

    data.WriteUint32(jobinfo.GetPageSize().GetId());
    data.WriteString(jobinfo.GetPageSize().GetName());
    data.WriteUint32(jobinfo.GetPageSize().GetWidth());
    data.WriteUint32(jobinfo.GetPageSize().GetHeight());

    data.WriteUint32(jobinfo.GetIsLandscape());
    data.WriteUint32(jobinfo.GetColorMode());
    data.WriteUint32(jobinfo.GetDuplexMode());

    data.WriteUint32(jobinfo.GetMargin().GetTop());
    data.WriteUint32(jobinfo.GetMargin().GetBottom());
    data.WriteUint32(jobinfo.GetMargin().GetLeft());
    data.WriteUint32(jobinfo.GetMargin().GetRight());

    data.WriteString(jobinfo.GetPreview().GetResult());
    data.WriteUint32(jobinfo.GetPreview().GetPreviewRange().GetStartPage());
    data.WriteUint32(jobinfo.GetPreview().GetPreviewRange().GetEndPage());
    uint32_t previewPageLength = jobinfo.GetPreview().GetPreviewRange().GetPages().size();
    data.WriteUint32(previewPageLength);
    for(uint32_t i = 0; i < previewPageLength; i++)
    {
         data.WriteUint32(jobinfo.GetPreview().GetPreviewRange().GetPages()[i]);
    }
    
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_STARTPRINTJOB, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    PRINT_HILOGD("PrintServiceProxy StartPrintJob succeeded.");
    return true;
}

bool PrintServiceProxy::CancelPrintJob(PrintJob jobinfo) 
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    
    uint32_t fileLength = jobinfo.GetFiles().size();
    data.WriteUint32(fileLength);
    for(uint32_t i = 0; i < fileLength; i++)
    {
        data.WriteString(jobinfo.GetFiles()[i]);

    }
    data.WriteUint32(jobinfo.GetJobId());
    data.WriteUint32(jobinfo.GetPrinterId());
    data.WriteUint32(jobinfo.GetJobState());
    data.WriteUint32(jobinfo.GetCopyNumber());

    data.WriteUint32(jobinfo.GetPageRange().GetStartPage());
    data.WriteUint32(jobinfo.GetPageRange().GetEndPage());
    uint32_t pageLength = jobinfo.GetPageRange().GetPages().size();
    data.WriteUint32(pageLength);
    for(uint32_t i = 0; i < pageLength; i++)
    {
         data.WriteUint32(jobinfo.GetPageRange().GetPages()[i]);
    }

    data.WriteUint32(jobinfo.GetIsSequential());

    data.WriteUint32(jobinfo.GetPageSize().GetId());
    data.WriteString(jobinfo.GetPageSize().GetName());
    data.WriteUint32(jobinfo.GetPageSize().GetWidth());
    data.WriteUint32(jobinfo.GetPageSize().GetHeight());

    data.WriteUint32(jobinfo.GetIsLandscape());
    data.WriteUint32(jobinfo.GetColorMode());
    data.WriteUint32(jobinfo.GetDuplexMode());

    data.WriteUint32(jobinfo.GetMargin().GetTop());
    data.WriteUint32(jobinfo.GetMargin().GetBottom());
    data.WriteUint32(jobinfo.GetMargin().GetLeft());
    data.WriteUint32(jobinfo.GetMargin().GetRight());

    data.WriteString(jobinfo.GetPreview().GetResult());
    data.WriteUint32(jobinfo.GetPreview().GetPreviewRange().GetStartPage());
    data.WriteUint32(jobinfo.GetPreview().GetPreviewRange().GetEndPage());
    uint32_t previewPageLength = jobinfo.GetPreview().GetPreviewRange().GetPages().size();
    data.WriteUint32(previewPageLength);
    for(uint32_t i = 0; i < previewPageLength; i++)
    {
         data.WriteUint32(jobinfo.GetPreview().GetPreviewRange().GetPages()[i]);
    }
    
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_CANCELPRINTJOB, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    PRINT_HILOGD("PrintServiceProxy CancelPrintJob succeeded.");
    return true;
}

bool PrintServiceProxy::AddPrinters(std::vector<PrintInfo> arrayPrintInfo)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    data.WriteUint32(arrayPrintInfo.size());
    PRINT_HILOGD("OnStartDiscoverPrinter arrayPrintInfo.size() = %{public}lu", arrayPrintInfo.size());
    for(uint32_t i = 0; i < arrayPrintInfo.size(); i++)
    {
        data.WriteUint32(arrayPrintInfo[i].GetPrintId());
        data.WriteString(arrayPrintInfo[i].GetPrinterName());
        data.WriteUint32(arrayPrintInfo[i].GetPrinterIcon());
        data.WriteUint32(arrayPrintInfo[i].GetPrinterState());
        data.WriteString(arrayPrintInfo[i].GetDescription());
        arrayPrintInfo[i].Dump();
        uint32_t pageSizeLength = arrayPrintInfo[i].GetCapability().GetPageSize().size();
        uint32_t resolutionLength = arrayPrintInfo[i].GetCapability().GetResolution().size();
        data.WriteUint32(pageSizeLength);
        data.WriteUint32(resolutionLength);
        data.WriteUint32(arrayPrintInfo[i].GetCapability().GetMinMargin().GetTop());
        data.WriteUint32(arrayPrintInfo[i].GetCapability().GetMinMargin().GetBottom());
        data.WriteUint32(arrayPrintInfo[i].GetCapability().GetMinMargin().GetLeft());
        data.WriteUint32(arrayPrintInfo[i].GetCapability().GetMinMargin().GetRight()); 
        arrayPrintInfo[i].GetCapability().GetMinMargin().Dump();
        for(uint32_t i = 0; i < pageSizeLength; i++)
        {
            data.WriteUint32(arrayPrintInfo[i].GetCapability().GetPageSize()[i].GetId());
            data.WriteString(arrayPrintInfo[i].GetCapability().GetPageSize()[i].GetName());
            data.WriteUint32(arrayPrintInfo[i].GetCapability().GetPageSize()[i].GetWidth());
            data.WriteUint32(arrayPrintInfo[i].GetCapability().GetPageSize()[i].GetHeight());
            arrayPrintInfo[i].GetCapability().GetPageSize()[i].Dump();
        }     
        for(uint32_t i = 0; i < resolutionLength; i++)
        {
            data.WriteUint32(arrayPrintInfo[i].GetCapability().GetResolution()[i].GetId());
            data.WriteUint32(arrayPrintInfo[i].GetCapability().GetResolution()[i].GetHorizontalDpi());
            data.WriteUint32(arrayPrintInfo[i].GetCapability().GetResolution()[i].GetVerticalDpi());
            arrayPrintInfo[i].GetCapability().GetResolution()[i].Dump();
        }   
        data.WriteUint32(arrayPrintInfo[i].GetCapability().GetColorMode());
        data.WriteUint32(arrayPrintInfo[i].GetCapability().GetDuplexMode());
        arrayPrintInfo[i].GetCapability().Dump();
    }
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_ADDPRINTERS, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    PRINT_HILOGD("PrintServiceProxy AddPrinters succeeded.");
    return true;
}

bool PrintServiceProxy::RemovePrinters(std::vector<PrintInfo> arrayPrintInfo)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    data.WriteUint32(arrayPrintInfo.size());
    PRINT_HILOGD("OnStartDiscoverPrinter arrayPrintInfo.size() = %{public}lu", arrayPrintInfo.size());
    for(uint32_t i = 0; i < arrayPrintInfo.size(); i++)
    {
        data.WriteUint32(arrayPrintInfo[i].GetPrintId());
        data.WriteString(arrayPrintInfo[i].GetPrinterName());
        data.WriteUint32(arrayPrintInfo[i].GetPrinterIcon());
        data.WriteUint32(arrayPrintInfo[i].GetPrinterState());
        data.WriteString(arrayPrintInfo[i].GetDescription());
        arrayPrintInfo[i].Dump();
        uint32_t pageSizeLength = arrayPrintInfo[i].GetCapability().GetPageSize().size();
        uint32_t resolutionLength = arrayPrintInfo[i].GetCapability().GetResolution().size();
        data.WriteUint32(pageSizeLength);
        data.WriteUint32(resolutionLength);
        data.WriteUint32(arrayPrintInfo[i].GetCapability().GetMinMargin().GetTop());
        data.WriteUint32(arrayPrintInfo[i].GetCapability().GetMinMargin().GetBottom());
        data.WriteUint32(arrayPrintInfo[i].GetCapability().GetMinMargin().GetLeft());
        data.WriteUint32(arrayPrintInfo[i].GetCapability().GetMinMargin().GetRight()); 
        arrayPrintInfo[i].GetCapability().GetMinMargin().Dump();
        for(uint32_t i = 0; i < pageSizeLength; i++)
        {
            data.WriteUint32(arrayPrintInfo[i].GetCapability().GetPageSize()[i].GetId());
            data.WriteString(arrayPrintInfo[i].GetCapability().GetPageSize()[i].GetName());
            data.WriteUint32(arrayPrintInfo[i].GetCapability().GetPageSize()[i].GetWidth());
            data.WriteUint32(arrayPrintInfo[i].GetCapability().GetPageSize()[i].GetHeight());
            arrayPrintInfo[i].GetCapability().GetPageSize()[i].Dump();
        }     
        for(uint32_t i = 0; i < resolutionLength; i++)
        {
            data.WriteUint32(arrayPrintInfo[i].GetCapability().GetResolution()[i].GetId());
            data.WriteUint32(arrayPrintInfo[i].GetCapability().GetResolution()[i].GetHorizontalDpi());
            data.WriteUint32(arrayPrintInfo[i].GetCapability().GetResolution()[i].GetVerticalDpi());
            arrayPrintInfo[i].GetCapability().GetResolution()[i].Dump();
        }   
        data.WriteUint32(arrayPrintInfo[i].GetCapability().GetColorMode());
        data.WriteUint32(arrayPrintInfo[i].GetCapability().GetDuplexMode());
        arrayPrintInfo[i].GetCapability().Dump();
    }
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_REMOVEPRINTERS, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    PRINT_HILOGD("PrintServiceProxy RemovePrinters succeeded.");
    return true;
}

bool PrintServiceProxy::UpdatePrinterState(uint32_t printerId, uint32_t state)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    data.WriteUint32(printerId);
    data.WriteUint32(state);
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_UPDATEPRINTERSTATE, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    PRINT_HILOGD("PrintServiceProxy UpdatePrinterState succeeded.");
    return true;
}

bool PrintServiceProxy::UpdatePrinterJobState(uint32_t jobId, uint32_t state)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    data.WriteInt32(jobId);
    data.WriteUint32(state);
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_UPDATEPRINTERJOBSTATE, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    PRINT_HILOGD("PrintServiceProxy UpdatePrinterJobState succeeded.");
    return true;
}

bool PrintServiceProxy::RequestPreview(PrintJob jobinfo, std::string &previewResult)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    uint32_t fileLength = jobinfo.GetFiles().size();
    data.WriteUint32(fileLength);
    for(uint32_t i = 0; i < fileLength; i++)
    {
        data.WriteString(jobinfo.GetFiles()[i]);

    }
    data.WriteUint32(jobinfo.GetJobId());
    data.WriteUint32(jobinfo.GetPrinterId());
    data.WriteUint32(jobinfo.GetJobState());
    data.WriteUint32(jobinfo.GetCopyNumber());

    data.WriteUint32(jobinfo.GetPageRange().GetStartPage());
    data.WriteUint32(jobinfo.GetPageRange().GetEndPage());
    uint32_t pageLength = jobinfo.GetPageRange().GetPages().size();
    data.WriteUint32(pageLength);
    for(uint32_t i = 0; i < pageLength; i++)
    {
         data.WriteUint32(jobinfo.GetPageRange().GetPages()[i]);
    }

    data.WriteUint32(jobinfo.GetIsSequential());

    data.WriteUint32(jobinfo.GetPageSize().GetId());
    data.WriteString(jobinfo.GetPageSize().GetName());
    data.WriteUint32(jobinfo.GetPageSize().GetWidth());
    data.WriteUint32(jobinfo.GetPageSize().GetHeight());

    data.WriteUint32(jobinfo.GetIsLandscape());
    data.WriteUint32(jobinfo.GetColorMode());
    data.WriteUint32(jobinfo.GetDuplexMode());

    data.WriteUint32(jobinfo.GetMargin().GetTop());
    data.WriteUint32(jobinfo.GetMargin().GetBottom());
    data.WriteUint32(jobinfo.GetMargin().GetLeft());
    data.WriteUint32(jobinfo.GetMargin().GetRight());

    data.WriteString(jobinfo.GetPreview().GetResult());
    data.WriteUint32(jobinfo.GetPreview().GetPreviewRange().GetStartPage());
    data.WriteUint32(jobinfo.GetPreview().GetPreviewRange().GetEndPage());
    uint32_t previewPageLength = jobinfo.GetPreview().GetPreviewRange().GetPages().size();
    data.WriteUint32(previewPageLength);
    for(uint32_t i = 0; i < previewPageLength; i++)
    {
         data.WriteUint32(jobinfo.GetPreview().GetPreviewRange().GetPages()[i]);
    }

    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_REQUESTPREVIEW, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    previewResult = reply.ReadString();
    PRINT_HILOGD("PrintServiceProxy RequestPreview succeeded.");
    return true;
}

bool PrintServiceProxy::QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    data.WriteUint32(printerId);
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_QUERYPRINTERCAPABILITY, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    uint32_t arraypageSizeLength = reply.ReadUint32();
    uint32_t resolutionLength = reply.ReadUint32();
    PRINT_HILOGD("PrintServiceProxy, arraypageSizeLength = %{public}d", arraypageSizeLength);
    PRINT_HILOGD("PrintServiceProxy, resolutionLength = %{public}d", resolutionLength);
    printerCapability.GetMinMargin().SetTop(reply.ReadUint32());
    printerCapability.GetMinMargin().SetBottom(reply.ReadUint32());
    printerCapability.GetMinMargin().SetLeft(reply.ReadUint32());
    printerCapability.GetMinMargin().SetRight(reply.ReadUint32()); 
    printerCapability.GetMinMargin().Dump();
    for(uint32_t i = 0; i < arraypageSizeLength; i++)
    {
        PrinterPageSize printerPageSize;
        printerPageSize.SetId(reply.ReadUint32());
        printerPageSize.SetName(reply.ReadString());
        printerPageSize.SetWidth(reply.ReadUint32());
        printerPageSize.SetHeight(reply.ReadUint32());
        printerCapability.SetPageSize(printerPageSize);
        printerCapability.GetPageSize()[i].Dump();
    }
     
      for(uint32_t i = 0; i < resolutionLength; i++)
    {
        PrinterResolution printerResolution;
        printerResolution.SetId(reply.ReadUint32());
        printerResolution.SetHorizontalDpi(reply.ReadUint32());
        printerResolution.SetVerticalDpi(reply.ReadUint32());
        printerCapability.SetResolution(printerResolution);
        printerCapability.GetResolution()[i].Dump();
    }
    
    printerCapability.SetColorMode(reply.ReadUint32());
    printerCapability.SetDuplexMode(reply.ReadUint32());
    printerCapability.Dump();

    PRINT_HILOGD("PrintServiceProxy QueryPrinterCapability succeeded.");
    return true;
}

bool PrintServiceProxy::CheckPermission()
{
    PRINT_HILOGD("PrintServiceProxy::CheckPermission in");
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE(" Failed to write parcelable ");
        return false;
    }
    
    int32_t result = Remote()->SendRequest(CMD_CHECKPERMISSION, data, reply, option);
    if (result != ERR_NONE) {
        PRINT_HILOGE(" PrintServiceProxy::CheckPermission fail, ret = %{public}d ", result);
        return false;
    }
    bool ret = reply.ReadBool();
    PRINT_HILOGD("PrintServiceProxy::CheckPermission out [ret: %{public}d]", ret);
    return ret;
}

bool PrintServiceProxy::On(uint32_t taskId, const std::string &type, const sptr<PrintNotifyInterface> &listener)
{
    PRINT_HILOGD("PrintServiceProxy::On listener=%{public}p", listener.GetRefPtr());
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE(" Failed to write parcelable ");
        return false;
    }
    if (listener == nullptr) {
        PRINT_HILOGE("listener is nullptr");
        return false;
    }

    if (!data.WriteUint32(taskId)) {
        PRINT_HILOGE("write taskId=%{public}d fail", taskId);
        return false;
    }
    
    PRINT_HILOGD("PrintServiceProxy::On type=%{public}s", type.c_str());
    if (type.empty()) {
        PRINT_HILOGE("PrintServiceProxy::On type is null.");
        return false;
    }
    if (!data.WriteString(type)) {
        PRINT_HILOGE("write type failed.");
        return false;
    }
    if (!data.WriteRemoteObject(listener->AsObject().GetRefPtr())) {
        PRINT_HILOGE("write parcel failed.");
        return false;
    }
    int32_t result = Remote()->SendRequest(CMD_ON, data, reply, option);
    if (result != ERR_NONE) {
        PRINT_HILOGE(" PrintServiceProxy::On fail, result = %{public}d ", result);
        return false;
    }
    bool ret = reply.ReadBool();
    PRINT_HILOGD("PrintServiceProxy::On out [result: %{public}d]", ret);
    return ret;
}

bool PrintServiceProxy::Off(uint32_t taskId, const std::string &type)
{
    PRINT_HILOGD("PrintServiceProxy::Off in");
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE(" Failed to write parcelable ");
        return false;
    }
    
    if (!data.WriteUint32(taskId)) {
        PRINT_HILOGE("write taskId=%{public}d fail", taskId);
        return false;
    }
    
    if (!data.WriteString(type)) {
        PRINT_HILOGE("write type=%{public}s fail", type.c_str());
        return false;
    }
    int32_t result = Remote()->SendRequest(CMD_OFF, data, reply, option);
    if (result != ERR_NONE) {
        PRINT_HILOGE(" PrintServiceProxy::Off fail, ret = %{public}d ", result);
        return false;
    }
    bool ret = reply.ReadBool();
    PRINT_HILOGD("PrintServiceProxy::Off out [ret: %{public}d]", ret);
    return ret;
}
} // namespace OHOS::Print
