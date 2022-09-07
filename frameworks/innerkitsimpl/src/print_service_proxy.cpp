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
#include "print_service_proxy.h"
#include "napi_print_utils.h"
#include <sys/types.h>
#include <unistd.h>

#include "iremote_broker.h"
#include "print_common.h"
#include "print_job.h"
#include "print_log.h"
#include "printer_info.h"

namespace OHOS::Print {
using namespace OHOS::HiviewDFX;

PrintServiceProxy::PrintServiceProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IPrintService>(object) {}

int32_t PrintServiceProxy::StartPrint()
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("PrintServiceProxy StartPrint started.");
    bool ret = Remote()->SendRequest(CMD_START_PRINT, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("StartPrint, ret = %{public}d", ret);
        return -1;
    }
    int32_t taskId = reply.ReadInt32();
    PRINT_HILOGD("PrintServiceProxy StartPrint succeeded. TaskId = %{public}d", taskId);
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

bool PrintServiceProxy::QueryAllExtension(std::vector<PrintExtensionInfo> &arrayExtensionInfo)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    data.WriteUint32(NapiPrintUtil::ARGC_FIVE);
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_QUERYALLEXTENSION, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    uint32_t replyArrayLength = reply.ReadUint32();
    for (uint32_t i = 0; i < replyArrayLength; i++) {
        PrintExtensionInfo printeExtensionInfo;
        printeExtensionInfo.SetExtensionId(reply.ReadUint32());
        printeExtensionInfo.SetVendorId(reply.ReadUint32());
        printeExtensionInfo.SetVendorName(reply.ReadString());
        printeExtensionInfo.SetVendorIcon(reply.ReadUint32());
        printeExtensionInfo.SetVersion(reply.ReadString());
        arrayExtensionInfo.push_back(printeExtensionInfo);
        arrayExtensionInfo[i].Dump();
    }
    return true;
}

bool PrintServiceProxy::StartDiscoverPrinter(const std::vector<uint32_t> &extensionList)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    data.WriteUint32(extensionList.size());
    PRINT_HILOGD("OnStartDiscoverPrinter extensionList.size() = %{public}lu", extensionList.size());
    for (uint32_t i = 0; i < extensionList.size(); i++) {
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

bool PrintServiceProxy::StartPrintJob(const PrintJob &jobinfo)
{
    MessageParcel data, reply;
    MessageOption option;

    BuildParcelFromPrintJob(data, jobinfo);
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_STARTPRINTJOB, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    PRINT_HILOGD("PrintServiceProxy StartPrintJob succeeded.");
    return true;
}

bool PrintServiceProxy::CancelPrintJob(const PrintJob &jobinfo)
{
    MessageParcel data, reply;
    MessageOption option;

    BuildParcelFromPrintJob(data, jobinfo);
    PRINT_HILOGD("PrintServiceProxy ChangeTaskPriority started.");
    bool ret = Remote()->SendRequest(CMD_CANCELPRINTJOB, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGD("PrintServiceProxy, ret = %{public}d", ret);
        return false;
    }
    PRINT_HILOGD("PrintServiceProxy CancelPrintJob succeeded.");
    return true;
}

bool PrintServiceProxy::AddPrinters(const std::vector<PrinterInfo> &arrayPrintInfo)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    data.WriteUint32(arrayPrintInfo.size());
    PRINT_HILOGD("OnStartDiscoverPrinter arrayPrintInfo.size() = %{public}lu", arrayPrintInfo.size());
    for (uint32_t i = 0; i < arrayPrintInfo.size(); i++) {
        BuildParcelFromPrinterInfo(data, arrayPrintInfo[i]);
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

bool PrintServiceProxy::RemovePrinters(const std::vector<PrinterInfo> &arrayPrintInfo)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(PrintServiceProxy::GetDescriptor());
    data.WriteUint32(arrayPrintInfo.size());
    PRINT_HILOGD("OnStartDiscoverPrinter arrayPrintInfo.size() = %{public}lu", arrayPrintInfo.size());
    for (uint32_t i = 0; i < arrayPrintInfo.size(); i++) {
        BuildParcelFromPrinterInfo(data, arrayPrintInfo[i]);
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
    data.WriteUint32(jobId);
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

bool PrintServiceProxy::RequestPreview(const PrintJob &jobinfo, std::string &previewResult)
{
    MessageParcel data, reply;
    MessageOption option;
    BuildParcelFromPrintJob(data, jobinfo);
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

    PrintMargin margin;
    margin.SetTop(reply.ReadUint32());
    margin.SetBottom(reply.ReadUint32());
    margin.SetLeft(reply.ReadUint32());
    margin.SetRight(reply.ReadUint32());
    printerCapability.SetMinMargin(margin);

    if (arraypageSizeLength > 0) {
        std::vector<PrintPageSize> pageSizeList;
        for (uint32_t i = 0; i < arraypageSizeLength; i++) {
            PrintPageSize pageSize;
            pageSize.SetId(reply.ReadString());
            pageSize.SetName(reply.ReadString());
            pageSize.SetWidth(reply.ReadUint32());
            pageSize.SetHeight(reply.ReadUint32());
            pageSizeList.push_back(pageSize);
        }
        printerCapability.SetPageSize(pageSizeList);
    }

    if (resolutionLength > 0) {
        std::vector<PrintResolution> resolutionList;
        for (uint32_t i = 0; i < resolutionLength; i++) {
            PrintResolution res;
            res.SetId(reply.ReadUint32());
            res.SetHorizontalDpi(reply.ReadUint32());
            res.SetVerticalDpi(reply.ReadUint32());
            resolutionList.push_back(res);
        }
        printerCapability.SetResolution(resolutionList);
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

bool PrintServiceProxy::On(
    const std::string &type, uint32_t &state, PrinterInfo &info, const sptr<IPrintCallback> &listener)
{
    PRINT_HILOGD("PrintServiceProxy::On listener=%{public}p", listener.GetRefPtr());
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE(" Failed to write parcelable ");
        return false;
    }
    return true;
}

bool PrintServiceProxy::Off(const std::string &type)
{
    PRINT_HILOGD("PrintServiceProxy::Off in");
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE(" Failed to write parcelable ");
        return false;
    }
    return true;
}

bool PrintServiceProxy::RegisterExtCallback(uint32_t callbackId, const sptr<IPrintExtensionCallback> &listener)
{
    PRINT_HILOGD("PrintServiceProxy::RegisterExtCallback in");
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE("Failed to write parcelable");
        return false;
    }
    if (!data.WriteUint32(callbackId)) {
        PRINT_HILOGE("Failed to write callbackId=%{public}d", callbackId);
        return false;
    }
    if (!data.WriteRemoteObject(listener->AsObject().GetRefPtr())) {
        PRINT_HILOGE("write parcel failed.");
        return false;
    }

    int32_t result = Remote()->SendRequest(CMD_REG_EXT_CB, data, reply, option);
    if (result != ERR_NONE) {
        PRINT_HILOGE("PrintServiceProxy::RegisterExtCallback fail, ret = %{public}d", result);
        return false;
    }
    bool ret = reply.ReadBool();
    PRINT_HILOGD("PrintServiceProxy::RegisterExtCallback out [ret: %{public}d]", ret);
    return ret;
}

bool PrintServiceProxy::UnregisterAllExtCallback()
{
    PRINT_HILOGD("PrintServiceProxy::UnregisterAllExtCallback in");
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE(" Failed to write parcelable ");
        return false;
    }

    int32_t result = Remote()->SendRequest(CMD_UNREG_EXT_CB, data, reply, option);
    if (result != ERR_NONE) {
        PRINT_HILOGE(" PrintServiceProxy::UnregisterAllExtCallback fail, ret = %{public}d ", result);
        return false;
    }
    bool ret = reply.ReadBool();
    PRINT_HILOGD("PrintServiceProxy::UnregisterAllExtCallback out [ret: %{public}d]", ret);
    return ret;
}

void PrintServiceProxy::BuildParcelFromPrintJob(MessageParcel &data, const PrintJob &jobinfo)
{
    data.WriteInterfaceToken(GetDescriptor());

    std::vector<std::string> files;
    jobinfo.GetFiles(files);
    data.WriteUint32(files.size());
    for (uint32_t i = 0; i < files.size(); i++) {
        data.WriteString(files[i]);
    }
    data.WriteUint32(jobinfo.GetJobId());
    data.WriteUint32(jobinfo.GetPrinterId());
    data.WriteUint32(jobinfo.GetJobState());
    data.WriteUint32(jobinfo.GetCopyNumber());

    PrintRange range;
    jobinfo.GetPageRange(range);
    data.WriteUint32(range.GetStartPage());
    data.WriteUint32(range.GetEndPage());

    std::vector<uint32_t> pages;
    range.GetPages(pages);
    data.WriteUint32(pages.size());
    for (uint32_t i = 0; i < pageLength; i++) {
        data.WriteUint32(pages[i]);
    }

    data.WriteUint32(jobinfo.GetIsSequential());

    PrintPageSize pageSize;
    jobinfo.GetPageSize(pageSize);
    data.WriteString(pageSize.GetId());
    data.WriteString(pageSize.GetName());
    data.WriteUint32(pageSize.GetWidth());
    data.WriteUint32(pageSize.GetHeight());

    data.WriteUint32(jobinfo.GetIsLandscape());
    data.WriteUint32(jobinfo.GetColorMode());
    data.WriteUint32(jobinfo.GetDuplexMode());

    PrintMargin margin;
    jobinfo.GetMargin(margin);
    data.WriteUint32(margin.GetTop());
    data.WriteUint32(margin.GetBottom());
    data.WriteUint32(margin.GetLeft());
    data.WriteUint32(margin.GetRight());

    PreviewAttribute preview;
    jobinfo.GetPreview(preview);
    data.WriteString(preview.GetResult());

    range.Reset();
    preview.GetPreviewRange(range);
    data.WriteUint32(range.GetStartPage());
    data.WriteUint32(range.GetEndPage());

    range.GetPages(pages);
    data.WriteUint32(pages.size());
    for (uint32_t i = 0; i < pages.size(); i++) {
        data.WriteUint32(pages[i]);
    }
}

void PrintServiceProxy::BuildParcelFromPrinterInfo(MessageParcel &data, const PrinterInfo &printerInfo)
{
    data.WriteUint32(printerInfo.GetPrintId());
    data.WriteString(printerInfo.GetPrinterName());
    data.WriteUint32(printerInfo.GetPrinterIcon());
    data.WriteUint32(printerInfo.GetPrinterState());
    data.WriteString(printerInfo.GetDescription());

    PrinterCapability cap;
    printerInfo.GetCapability(cap);
    std::vector<PrintPageSize> pageSizeList;
    cap.GetPageSize(pageSizeList);

    std::vector<PrintResolution> resolutionList;
    cap.GetResolution(resolutionList);
    uint32_t pageSizeLength = pageSizeList.size();
    uint32_t resolutionLength = resolutionList.size();
    data.WriteUint32(pageSizeLength);
    data.WriteUint32(resolutionLength);

    PrintMargin margin;
    cap.GetMinMargin(margin);
    data.WriteUint32(margin.GetTop());
    data.WriteUint32(margin.GetBottom());
    data.WriteUint32(margin.GetLeft());
    data.WriteUint32(margin.GetRight());

    for (uint32_t i = 0; i < pageSizeLength; i++) {
        data.WriteString(pageSizeList[i].GetId());
        data.WriteString(pageSizeList[i].GetName());
        data.WriteUint32(pageSizeList[i].GetWidth());
        data.WriteUint32(pageSizeList[i].GetHeight());
    }
    for (uint32_t i = 0; i < resolutionLength; i++) {
        data.WriteUint32(resolutionList[i].GetId());
        data.WriteUint32(resolutionList[i].GetHorizontalDpi());
        data.WriteUint32(resolutionList[i].GetVerticalDpi());
    }
    data.WriteUint32(cap.GetColorMode());
    data.WriteUint32(cap.GetDuplexMode());
}
} // namespace OHOS::Print
