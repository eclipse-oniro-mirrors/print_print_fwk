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
#include "iremote_broker.h"
#include "print_constant.h"
#include "print_job.h"
#include "print_log.h"
#include "printer_info.h"

namespace OHOS::Print {
using namespace OHOS::HiviewDFX;

PrintServiceProxy::PrintServiceProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IPrintService>(object) {}

int32_t PrintServiceProxy::GetResult(int retCode, MessageParcel &reply)
{
    if (retCode != ERR_NONE) {
        PRINT_HILOGE("rpc error code = %{public}d", retCode);
        return E_PRINT_RPC_FAILURE;
    }

    retCode = reply.ReadInt32();
    PRINT_HILOGD("PrintServiceProxy out. ret = [%{public}d]", retCode);
    return retCode;
}

int32_t PrintServiceProxy::StartPrint(const std::vector<std::string> &fileList,
    const std::vector<uint32_t> &fdList, std::string &taskId)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("Current file is %{public}zd", fileList.size());
    for (auto file : fileList) {
        PRINT_HILOGD("file is %{private}s", file.c_str());
    }

    data.WriteBool(fileList.size() > 0);
    if (!fileList.empty()) {
        data.WriteStringVector(fileList);
    }

    data.WriteBool(fdList.size() > 0);
    if (!fdList.empty()) {
        data.WriteInt32(fdList.size());
        for (auto fd : fdList) {
            data.WriteFileDescriptor(fd);
        }
    }

    PRINT_HILOGD("PrintServiceProxy StartPrint started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_START_PRINT, data, reply, option);
    ret = GetResult(ret, reply);
    taskId = reply.ReadString();
    PRINT_HILOGD("PrintServiceProxy StartPrint ret = [%{public}d] TaskId = %{public}s", ret, taskId.c_str());
    return ret;
}

int32_t PrintServiceProxy::StartPrint(const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList,
    std::string &taskId, const sptr<IRemoteObject> &token)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("Current file is %{public}zd", fileList.size());
    for (auto file : fileList) {
        PRINT_HILOGD("file is %{private}s", file.c_str());
    }

    data.WriteBool(fileList.size() > 0);
    if (!fileList.empty()) {
        data.WriteStringVector(fileList);
    }

    data.WriteBool(fdList.size() > 0);
    if (!fdList.empty()) {
        data.WriteInt32(fdList.size());
        for (auto fd : fdList) {
            data.WriteFileDescriptor(fd);
        }
    }

    if (token == nullptr || !data.WriteRemoteObject(token)) {
        PRINT_HILOGE("StartPrint, Failed to write remote object.");
        return E_PRINT_INVALID_PARAMETER;
    }
    PRINT_HILOGD("PrintServiceProxy StartPrint started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_START_PRINT, data, reply, option);
    ret = GetResult(ret, reply);
    taskId = reply.ReadString();
    PRINT_HILOGD("PrintServiceProxy StartPrint ret = [%{public}d] TaskId = %{public}s", ret, taskId.c_str());
    return ret;
}

int32_t PrintServiceProxy::StopPrint(const std::string &taskId)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(taskId);
    PRINT_HILOGD("PrintServiceProxy StopPrint started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_STOP_PRINT, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy StopPrint out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::ConnectPrinter(const std::string &printerId)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    PRINT_HILOGD("PrintServiceProxy ConnectPrinter started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_CONNECTPRINTER, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy ConnectPrinter out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::DisconnectPrinter(const std::string &printerId)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    PRINT_HILOGD("PrintServiceProxy DisconnectPrinter started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_DISCONNECTPRINTER, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy DisconnectPrinter out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("PrintServiceProxy QueryAllExtension started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLEXTENSION, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGD("PrintServiceProxy QueryAllExtension Failed.");
        return ret;
    }

    uint32_t len = reply.ReadUint32();
    for (uint32_t i = 0; i < len; i++) {
        auto infoPtr = PrintExtensionInfo::Unmarshalling(reply);
        if (infoPtr == nullptr) {
            PRINT_HILOGE("wrong information from data");
            return E_PRINT_GENERIC_FAILURE;
        }
        extensionInfos.emplace_back(*infoPtr);
    }
    PRINT_HILOGD("PrintServiceProxy QueryAllExtension succeeded.");
    return E_PRINT_NONE;
}

int32_t PrintServiceProxy::StartDiscoverPrinter(const std::vector<std::string> &extensionList)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteStringVector(extensionList);
    PRINT_HILOGD("PrintServiceProxy StartDiscoverPrinter started.");
    int32_t ret = Remote()->SendRequest(
        OHOS::Print::IPrintInterfaceCode::CMD_STARTDISCOVERPRINTER, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy StartDiscoverPrinter out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::StopDiscoverPrinter()
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("PrintServiceProxy StopDiscoverPrinter started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_STOPDISCOVERPRINTER, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy StopDiscoverPrinter out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::StartPrintJob(const PrintJob &jobinfo)
{
    MessageParcel data, reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    jobinfo.Marshalling(data);
    PRINT_HILOGD("PrintServiceProxy StartPrintJob started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_STARTPRINTJOB, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy StartPrintJob out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::CancelPrintJob(const std::string &jobId)
{
    MessageParcel data, reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(jobId);
    PRINT_HILOGD("PrintServiceProxy CancelPrintJob started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_CANCELPRINTJOB, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy CancelPrintJob out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::AddPrinters(const std::vector<PrinterInfo> &printerInfos)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteUint32(printerInfos.size());
    PRINT_HILOGD("AddPrinters printerInfos.size() = %{public}zu", printerInfos.size());
    for (uint32_t i = 0; i < printerInfos.size(); i++) {
        printerInfos[i].Marshalling(data);
    }
    PRINT_HILOGD("PrintServiceProxy AddPrinters started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_ADDPRINTERS, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy AddPrinters out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::RemovePrinters(const std::vector<std::string> &printerIds)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteStringVector(printerIds);

    PRINT_HILOGD("PrintServiceProxy RemovePrinters started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_REMOVEPRINTERS, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy RemovePrinters out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::UpdatePrinters(const std::vector<PrinterInfo> &printerInfos)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteUint32(printerInfos.size());
    PRINT_HILOGD("UpdatePrinters printerInfos.size() = %{public}zu", printerInfos.size());
    for (uint32_t i = 0; i < printerInfos.size(); i++) {
        printerInfos[i].Marshalling(data);
    }
    PRINT_HILOGD("PrintServiceProxy UpdatePrinters started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERS, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy UpdatePrinters out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::UpdatePrinterState(const std::string &printerId, uint32_t state)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    data.WriteUint32(state);
    PRINT_HILOGD("PrintServiceProxy UpdatePrinterState started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERSTATE, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy UpdatePrinterState out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::UpdatePrintJobState(const std::string &jobId, uint32_t state, uint32_t subState)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(jobId);
    data.WriteUint32(state);
    data.WriteUint32(subState);
    PRINT_HILOGD("PrintServiceProxy UpdatePrintJobState started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTJOBSTATE, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy UpdatePrintJobState out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::UpdateExtensionInfo(const std::string &extInfo)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(extInfo);
    PRINT_HILOGD("PrintServiceProxy UpdateExtensionInfo started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_UPDATEEXTENSIONINFO, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy UpdateExtensionInfo out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::RequestPreview(const PrintJob &jobinfo, std::string &previewResult)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    jobinfo.Marshalling(data);
    PRINT_HILOGD("PrintServiceProxy RequestPreview started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_REQUESTPREVIEW, data, reply, option);
    ret = GetResult(ret, reply);
    previewResult = reply.ReadString();
    PRINT_HILOGD("PrintServiceProxy RequestPreview ret = [%{public}d] previewResult = %{public}s",
        ret, previewResult.c_str());
    return ret;
}

int32_t PrintServiceProxy::QueryPrinterCapability(const std::string &printerId)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    PRINT_HILOGD("PrintServiceProxy QueryPrinterCapability started.");
    int32_t ret = Remote()->SendRequest(
        OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERCAPABILITY, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy QueryPrinterCapability out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::QueryAllPrintJob(std::vector<PrintJob> &printJobs)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("PrintServiceProxy QueryAllPrintJob started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLPRINTJOB, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGD("PrintServiceProxy QueryAllPrintJob Failed.");
        return ret;
    }

    uint32_t len = reply.ReadUint32();
    for (uint32_t i = 0; i < len; i++) {
        auto jobPtr = PrintJob::Unmarshalling(reply);
        if (jobPtr == nullptr) {
            PRINT_HILOGE("wrong printJob from data");
            return E_PRINT_GENERIC_FAILURE;
        }
        printJobs.emplace_back(*jobPtr);
    }
    PRINT_HILOGD("PrintServiceProxy QueryAllPrintJob succeeded.");
    return E_PRINT_NONE;
}

int32_t PrintServiceProxy::QueryPrintJobById(std::string &printJobId, PrintJob &printJob)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printJobId);
    PRINT_HILOGD("PrintServiceProxy QueryAllPrintJob started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTJOBBYID, data, reply, option);
    ret = GetResult(ret, reply);
    auto printJobPtr = PrintJob::Unmarshalling(reply);
    if (printJobPtr == nullptr) {
        PRINT_HILOGE("wrong printJob from data");
        return E_PRINT_GENERIC_FAILURE;
    }
    printJob = *printJobPtr;
    PRINT_HILOGD("[QueryPrintJobById] printerId : %{public}s", printJob.GetJobId().c_str());
    PRINT_HILOGD("PrintServiceProxy QueryPrintJobById succeeded.");
    return ret;
}

int32_t PrintServiceProxy::AddPrinterToCups(const std::string &printerUri, const std::string &printerName,
    const std::string &printerMake)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerUri);
    data.WriteString(printerName);
    data.WriteString(printerMake);
    PRINT_HILOGD("PrintServiceProxy AddPrinterToCups started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy AddPrinterToCups remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_ADDPRINTERTOCUPS, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy AddPrinterToCups succeeded.");
    return ret;
}

int32_t PrintServiceProxy::QueryPrinterCapabilityByUri(const std::string &printerUri, const std::string &printerId,
    PrinterCapability &printerCaps)
{
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerUri);
    data.WriteString(printerId);
    PRINT_HILOGD("PrintServiceProxy QueryPrinterCapabilityByUri started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy AddPrinterToCups remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERCAPABILITYBYURI,
        data, reply, option);
    ret = GetResult(ret, reply);
    auto printerCapsPtr = PrinterCapability::Unmarshalling(reply);
    printerCaps = *printerCapsPtr;
    PRINT_HILOGD("PrintServiceProxy QueryPrinterCapabilityByUri succeeded.");
    return ret;
}

int32_t PrintServiceProxy::On(const std::string taskId, const std::string &type, const sptr<IPrintCallback> &listener)
{
    if (listener == nullptr) {
        PRINT_HILOGE("listener is nullptr");
        return E_PRINT_INVALID_PARAMETER;
    }

    if (type.empty()) {
        PRINT_HILOGE("PrintServiceProxy::On type is null.");
        return E_PRINT_INVALID_PARAMETER;
    }

    MessageParcel data, reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(taskId);
    data.WriteString(type);
    data.WriteRemoteObject(listener->AsObject().GetRefPtr());
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_ON, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy On out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::Off(const std::string taskId, const std::string &type)
{
    PRINT_HILOGD("PrintServiceProxy::Off in");
    if (type.empty()) {
        PRINT_HILOGE("PrintServiceProxy::On type is null.");
        return E_PRINT_INVALID_PARAMETER;
    }

    MessageParcel data, reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(taskId);
    data.WriteString(type);
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_OFF, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy Off out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::RegisterExtCallback(const std::string &extensionCID,
    const sptr<IPrintExtensionCallback> &listener)
{
    PRINT_HILOGD("PrintServiceProxy::RegisterExtCallback in: %{public}s", extensionCID.c_str());
    MessageParcel data, reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(extensionCID);
    data.WriteRemoteObject(listener->AsObject().GetRefPtr());

    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_REG_EXT_CB, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy RegisterExtCallback out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::PrintByAdapter(const std::string printJobName, const PrintAttributes &printAttributes,
    std::string &taskId, const sptr<IRemoteObject> &token)
{
    PRINT_HILOGI("PrintServiceProxy PrintByAdapter start.");
    MessageParcel data, reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printJobName);
    printAttributes.Marshalling(data);
    data.WriteRemoteObject(token);
    PRINT_HILOGD("PrintServiceProxy PrintByAdapter started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_STARTPRINTJOB_BY_ADAPTER,
        data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("PrintByAdapter, rpc error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }
    ret = GetResult(ret, reply);
    taskId = reply.ReadString();
    PRINT_HILOGD("PrintServiceProxy PrintByAdapter out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::StartGetPrintFile(const std::string &jobId, const PrintAttributes &printAttributes,
    const uint32_t fd)
{
    MessageParcel data, reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(jobId);
    printAttributes.Marshalling(data);
    data.WriteFileDescriptor(fd);
    PRINT_HILOGI("PrintServiceProxy StartGetPrintFile started.");
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_START_GET_FILE, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("StartGetPrintFile, rpc error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }

    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy StartGetPrintFile out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::NotifyPrintService(const std::string &jobId, const std::string &type)
{
    PRINT_HILOGD("PrintServiceProxy::NotifyPrintService in");
    MessageParcel data, reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(jobId);
    data.WriteString(type);
    int32_t ret = Remote()->SendRequest(
        OHOS::Print::IPrintInterfaceCode::CMD_NOTIFY_PRINT_SERVICE, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy NotifyPrintService out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::UnregisterAllExtCallback(const std::string &extensionId)
{
    PRINT_HILOGD("PrintServiceProxy::UnregisterAllExtCallback in");
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(extensionId);
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_UNREG_EXT_CB, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy UnregisterAllExtCallback out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::LoadExtSuccess(const std::string &extensionId)
{
    PRINT_HILOGD("PrintServiceProxy::LoadExtSuccess in");
    MessageParcel data, reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(extensionId);
    int32_t ret = Remote()->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_LOAD_EXT, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy LoadExtSuccess out. ret = [%{public}d]", ret);
    return ret;
}
} // namespace OHOS::Print
