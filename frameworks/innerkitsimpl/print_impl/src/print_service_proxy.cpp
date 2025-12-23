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
#include "print_util.h"

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

int32_t PrintServiceProxy::StartService()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    const std::string ndkInfo = "nativePrint";
    data.WriteString(ndkInfo);
    PRINT_HILOGI("nativePrint PrintServiceProxy StartService started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy StartService remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_START_SERVICE, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy CMD_START_SERVICE ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::StartPrint(const std::vector<std::string> &fileList,
    const std::vector<uint32_t> &fdList, std::string &taskId)
{
    MessageParcel data;
    MessageParcel reply;
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

    data.WriteString(taskId);

    PRINT_HILOGD("PrintServiceProxy StartPrint started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy StartPrint remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_START_PRINT, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy StartPrint ret = [%{public}d] TaskId = %{public}s", ret, taskId.c_str());
    return ret;
}

int32_t PrintServiceProxy::ConnectPrinter(const std::string &printerId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    PRINT_HILOGD("PrintServiceProxy ConnectPrinter started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy ConnectPrinter remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_CONNECTPRINTER, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy ConnectPrinter out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::DisconnectPrinter(const std::string &printerId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    PRINT_HILOGD("PrintServiceProxy DisconnectPrinter started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy DisconnectPrinter remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_DISCONNECTPRINTER, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy DisconnectPrinter out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::AddRawPrinter(PrinterInfo &info)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    info.Marshalling(data);
    PRINT_HILOGI("PrintServiceProxy AddRawPrinter started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy AddRawPrinter remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_ADD_RAW_PRINTER, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy AddRawPrinter out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("PrintServiceProxy QueryAllExtension started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy QueryAllExtension remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLEXTENSION, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGD("PrintServiceProxy QueryAllExtension Failed.");
        return ret;
    }

    uint32_t len = reply.ReadUint32();
    if (len > PRINT_MAX_PRINT_COUNT) {
        PRINT_HILOGE("len is out of range.");
        return E_PRINT_INVALID_PARAMETER;
    }
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
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteStringVector(extensionList);
    PRINT_HILOGD("PrintServiceProxy StartDiscoverPrinter started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy StartDiscoverPrinter remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(
        OHOS::Print::IPrintInterfaceCode::CMD_STARTDISCOVERPRINTER, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy StartDiscoverPrinter out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::StopDiscoverPrinter()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("PrintServiceProxy StopDiscoverPrinter started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy StopDiscoverPrinter remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_STOPDISCOVERPRINTER, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy StopDiscoverPrinter out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::StartPrintJob(PrintJob &jobinfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    jobinfo.Marshalling(data);
    PRINT_HILOGD("PrintServiceProxy StartPrintJob started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy StartPrintJob remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_STARTPRINTJOB, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy StartPrintJob out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::CancelPrintJob(const std::string &jobId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(jobId);
    PRINT_HILOGD("PrintServiceProxy CancelPrintJob started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy CancelPrintJob remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_CANCELPRINTJOB, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy CancelPrintJob out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::AddPrinters(const std::vector<PrinterInfo> &printerInfos)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteUint32(printerInfos.size());
    PRINT_HILOGD("AddPrinters printerInfos.size() = %{public}zu", printerInfos.size());
    for (uint32_t i = 0; i < printerInfos.size(); i++) {
        printerInfos[i].Marshalling(data);
    }
    PRINT_HILOGD("PrintServiceProxy AddPrinters started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy AddPrinters remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_ADDPRINTERS, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy AddPrinters out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::RemovePrinters(const std::vector<std::string> &printerIds)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteStringVector(printerIds);

    PRINT_HILOGD("PrintServiceProxy RemovePrinters started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy RemovePrinters remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_REMOVEPRINTERS, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy RemovePrinters out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::UpdatePrinters(const std::vector<PrinterInfo> &printerInfos)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteUint32(printerInfos.size());
    PRINT_HILOGD("UpdatePrinters printerInfos.size() = %{public}zu", printerInfos.size());
    for (uint32_t i = 0; i < printerInfos.size(); i++) {
        printerInfos[i].Marshalling(data);
    }
    PRINT_HILOGD("PrintServiceProxy UpdatePrinters started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy UpdatePrinters remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERS, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy UpdatePrinters out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::UpdatePrinterState(const std::string &printerId, uint32_t state)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    data.WriteUint32(state);
    PRINT_HILOGD("PrintServiceProxy UpdatePrinterState started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy UpdatePrinterState remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERSTATE, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy UpdatePrinterState out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::UpdatePrintJobStateForNormalApp(
    const std::string &jobId, uint32_t state, uint32_t subState)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(jobId);
    data.WriteUint32(state);
    data.WriteUint32(subState);
    PRINT_HILOGI("PrintServiceProxy UpdatePrintJobStateForNormalApp started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy UpdatePrintJobStateForNormalApp remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(
        OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTJOBSTATE_FORNORMALAPP, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGI("PrintServiceProxy UpdatePrintJobStateForNormalApp out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::UpdatePrintJobStateOnlyForSystemApp(
    const std::string &jobId, uint32_t state, uint32_t subState)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(jobId);
    data.WriteUint32(state);
    data.WriteUint32(subState);
    PRINT_HILOGD("PrintServiceProxy UpdatePrintJobStateOnlyForSystemApp started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy UpdatePrintJobStateOnlyForSystemApp remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(
        OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTJOBSTATE_FORSYSTEMAPP, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy UpdatePrintJobStateOnlyForSystemApp out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::UpdateExtensionInfo(const std::string &extInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(extInfo);
    PRINT_HILOGD("PrintServiceProxy UpdateExtensionInfo started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy UpdateExtensionInfo remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_UPDATEEXTENSIONINFO, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy UpdateExtensionInfo out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::RequestPreview(const PrintJob &jobinfo, std::string &previewResult)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    jobinfo.Marshalling(data);
    PRINT_HILOGD("PrintServiceProxy RequestPreview started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy RequestPreview remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_REQUESTPREVIEW, data, reply, option);
    ret = GetResult(ret, reply);
    previewResult = reply.ReadString();
    PRINT_HILOGD("PrintServiceProxy RequestPreview ret = [%{public}d] previewResult = %{public}s",
        ret, previewResult.c_str());
    return ret;
}

int32_t PrintServiceProxy::QueryPrinterCapability(const std::string &printerId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    PRINT_HILOGD("PrintServiceProxy QueryPrinterCapability started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy QueryPrinterCapability remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(
        OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERCAPABILITY, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy QueryPrinterCapability out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::QueryPrinterInfoByPrinterId(const std::string &printerId, PrinterInfo &info)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    info.Marshalling(data);
    PRINT_HILOGD("PrintServiceProxy QueryPrinterInfoByPrinterId started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy QueryPrinterInfoByPrinterId remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(
        OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERINFOBYPRINTERID, data, reply, option);
    ret = GetResult(ret, reply);
    auto printerInfoPtr = PrinterInfo::Unmarshalling(reply);
    if (printerInfoPtr == nullptr) {
        PRINT_HILOGE("wrong printJob from data");
        return E_PRINT_GENERIC_FAILURE;
    }
    info = *printerInfoPtr;
    PRINT_HILOGD("PrintServiceProxy QueryPrinterInfoByPrinterId out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::QueryAddedPrinter(std::vector<std::string> &printerNameList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("PrintServiceProxy QueryAddedPrinter started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy QueryAddedPrinter remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYADDEDPRINTER, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy QueryAddedPrinter out. ret = [%{public}d]", ret);
    reply.ReadStringVector(&printerNameList);
    PRINT_HILOGD("PrintServiceProxy QueryAddedPrinter printerNameList size %{public}zu.", printerNameList.size());
    return ret;
}

int32_t PrintServiceProxy::QueryRawAddedPrinter(std::vector<std::string> &printerNameList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("PrintServiceProxy QueryRawAddedPrinter started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy QueryRawAddedPrinter remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYRAWADDEDPRINTER, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy QueryRawAddedPrinter out. ret = [%{public}d]", ret);
    reply.ReadStringVector(&printerNameList);
    PRINT_HILOGD("PrintServiceProxy QueryRawAddedPrinter printerNameList size %{public}zu.", printerNameList.size());
    return ret;
}

int32_t PrintServiceProxy::QueryPrinterProperties(const std::string &printerId,
    const std::vector<std::string> &keyList, std::vector<std::string> &valueList)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    data.WriteStringVector(keyList);
    PRINT_HILOGD("PrintServiceProxy QueryPrinterProperties started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy QueryPrinterProperties remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERPROPERTIES, data, reply,
        option);
    ret = GetResult(ret, reply);
    reply.ReadStringVector(&valueList);
    PRINT_HILOGD("PrintServiceProxy QueryPrinterProperties out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::StartNativePrintJob(PrintJob &printJob)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    printJob.Marshalling(data);
    PRINT_HILOGD("PrintServiceProxy StartNativePrintJob started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy StartNativePrintJob remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_STARTNATIVEPRINTJOB, data, reply,
        option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy StartNativePrintJob out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::SetPrinterPreference(
    const std::string &printerId, const PrinterPreferences &printerPreference)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    printerPreference.Marshalling(data);
    PRINT_HILOGI("PrintServiceProxy SetPrinterPreference started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy SetPrinterPreference remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_SET_PRINTER_PREFERENCE,
        data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGI("PrintServiceProxy SetPrinterPreference ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::QueryAllPrintJob(std::vector<PrintJob> &printJobs)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("PrintServiceProxy QueryAllPrintJob started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy QueryAllPrintJob remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLPRINTJOB, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGD("PrintServiceProxy QueryAllPrintJob Failed.");
        return ret;
    }

    uint32_t len = reply.ReadUint32();
    if (len > PRINT_MAX_PRINT_COUNT) {
        PRINT_HILOGE("len is out of range.");
        return E_PRINT_INVALID_PARAMETER;
    }
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

int32_t PrintServiceProxy::QueryAllActivePrintJob(std::vector<PrintJob> &printJobs)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("PrintServiceProxy QueryAllActivePrintJob started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy QueryAllActivePrintJob remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLACTIVEPRINTJOB,
        data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGD("PrintServiceProxy QueryAllActivePrintJob Failed.");
        return ret;
    }

    uint32_t len = reply.ReadUint32();
    if (len > PRINT_MAX_PRINT_COUNT) {
        PRINT_HILOGE("len is out of range.");
        return E_PRINT_INVALID_PARAMETER;
    }
    for (uint32_t i = 0; i < len; i++) {
        auto jobPtr = PrintJob::Unmarshalling(reply);
        if (jobPtr == nullptr) {
            PRINT_HILOGE("wrong printJob from data");
            return E_PRINT_GENERIC_FAILURE;
        }
        printJobs.emplace_back(*jobPtr);
    }
    PRINT_HILOGD("PrintServiceProxy QueryAllActivePrintJob succeeded.");
    return E_PRINT_NONE;
}

int32_t PrintServiceProxy::QueryPrintJobById(std::string &printJobId, PrintJob &printJob)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printJobId);
    PRINT_HILOGD("PrintServiceProxy QueryPrintJobById started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy QueryPrintJobById remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTJOBBYID, data, reply, option);
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
    MessageParcel data;
    MessageParcel reply;
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
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerUri);
    data.WriteString(printerId);
    PRINT_HILOGD("PrintServiceProxy QueryPrinterCapabilityByUri started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy QueryPrinterCapabilityByUri remote is null");
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

int32_t PrintServiceProxy::NotifyPrintServiceEvent(std::string &jobId, uint32_t event)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(jobId);
    data.WriteUint32(event);
    PRINT_HILOGD("PrintServiceProxy NotifyPrintServiceEvent started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy NotifyPrintServiceEvent remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(
        OHOS::Print::IPrintInterfaceCode::CMD_NOTIFY_PRINT_SERVICE_EVENT, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy NotifyPrintServiceEvent out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::SetDefaultPrinter(const std::string &printerId, uint32_t type)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    data.WriteUint32(type);
    PRINT_HILOGD("PrintServiceProxy SetDefaultPrinter started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy SetDefaultPrinter remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(
        OHOS::Print::IPrintInterfaceCode::CMD_SET_DEFAULT_PRINTERID, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy SetDefaultPrinter out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::DeletePrinterFromCups(const std::string &printerName)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerName);
    PRINT_HILOGD("PrintServiceProxy DeletePrinterFromCups started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy DeletePrinterFromCups remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(
        OHOS::Print::IPrintInterfaceCode::CMD_DELETE_PRINTER_FROM_CUPS, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy DeletePrinterFromCups out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::DiscoverUsbPrinters(std::vector<PrinterInfo> &printers)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    PRINT_HILOGD("PrintServiceProxy DiscoverUsbPrinters started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy DiscoverUsbPrinters remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->
        SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_DISCOVER_USB_PRINTERS, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGD("PrintServiceProxy DiscoverUsbPrinters Failed.");
        return ret;
    }

    uint32_t len = reply.ReadUint32();
    if (len > PRINT_MAX_PRINT_COUNT) {
        PRINT_HILOGE("len is out of range.");
        return E_PRINT_INVALID_PARAMETER;
    }
    for (uint32_t i = 0; i < len; i++) {
        auto infoPtr = PrinterInfo::Unmarshalling(reply);
        if (infoPtr == nullptr) {
            PRINT_HILOGE("wrong printerInfo from data");
            return E_PRINT_GENERIC_FAILURE;
        }
        printers.emplace_back(*infoPtr);
    }
    PRINT_HILOGD("PrintServiceProxy DiscoverUsbPrinters succeeded.");
    return E_PRINT_NONE;
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

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(taskId);
    data.WriteString(type);
    data.WriteRemoteObject(listener->AsObject().GetRefPtr());
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy On remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_ON, data, reply, option);
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

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(taskId);
    data.WriteString(type);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy Off remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_OFF, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy Off out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::RegisterPrinterCallback(const std::string &type, const sptr<IPrintCallback> &listener)
{
    if (listener == nullptr) {
        PRINT_HILOGE("listener is nullptr");
        return E_PRINT_INVALID_PARAMETER;
    }

    if (type.empty()) {
        PRINT_HILOGE("PrintServiceProxy:: type is empty.");
        return E_PRINT_INVALID_PARAMETER;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(type);
    data.WriteRemoteObject(listener->AsObject().GetRefPtr());
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy RegisterPrinterCallback remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_REG_PRINTER_CB, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy RegisterPrinterCallback out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::UnregisterPrinterCallback(const std::string &type)
{
    PRINT_HILOGD("PrintServiceProxy::UnregisterPrinterCallback in");
    if (type.empty()) {
        PRINT_HILOGE("PrintServiceProxy::type is empty.");
        return E_PRINT_INVALID_PARAMETER;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(type);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy UnregisterPrinterCallback remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_UNREG_PRINTER_CB, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy UnregisterPrinterCallback out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::RegisterExtCallback(const std::string &extensionCID,
    const sptr<IPrintExtensionCallback> &listener)
{
    if (listener == nullptr) {
        PRINT_HILOGE("listener is nullptr");
        return E_PRINT_INVALID_PARAMETER;
    }

    PRINT_HILOGD("PrintServiceProxy::RegisterExtCallback in: %{public}s", extensionCID.c_str());
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(extensionCID);
    data.WriteRemoteObject(listener->AsObject().GetRefPtr());

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy RegisterExtCallback remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_REG_EXT_CB, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy RegisterExtCallback out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::PrintByAdapter(const std::string printJobName, const PrintAttributes &printAttributes,
    std::string &taskId)
{
    PRINT_HILOGI("PrintServiceProxy PrintByAdapter start.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printJobName);
    printAttributes.Marshalling(data);
    data.WriteString(taskId);
    PRINT_HILOGD("PrintServiceProxy PrintByAdapter started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy PrintByAdapter remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_STARTPRINTJOB_BY_ADAPTER,
        data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("PrintByAdapter, rpc error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy PrintByAdapter out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::StartGetPrintFile(const std::string &jobId, const PrintAttributes &printAttributes,
    const uint32_t fd)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(jobId);
    printAttributes.Marshalling(data);
    data.WriteFileDescriptor(fd);
    PRINT_HILOGI("PrintServiceProxy StartGetPrintFile started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy StartGetPrintFile remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_START_GET_FILE, data, reply, option);
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
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(jobId);
    data.WriteString(type);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy NotifyPrintService remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(
        OHOS::Print::IPrintInterfaceCode::CMD_NOTIFY_PRINT_SERVICE, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy NotifyPrintService out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::AddPrinterToDiscovery(const PrinterInfo &printerInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    printerInfo.Marshalling(data);
    PRINT_HILOGD("PrintServiceProxy AddPrinterToDiscovery started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy AddPrinterToDiscovery remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_ADDPRINTERTODISCOVERY,
        data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy AddPrinterToDiscovery out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::UpdatePrinterInDiscovery(const PrinterInfo& printerInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    printerInfo.Marshalling(data);
    PRINT_HILOGD("PrintServiceProxy UpdatePrinterInDiscovery started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy UpdatePrinterInDiscovery remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERINDISCOVERY,
        data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy UpdatePrinterInDiscovery out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::RemovePrinterFromDiscovery(const std::string &printerId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    PRINT_HILOGD("PrintServiceProxy RemovePrinterFromDiscovery started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy RemovePrinterFromDiscovery remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_REMOVEPRINTERFROMDISCOVERY,
        data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy RemovePrinterFromDiscovery out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::UpdatePrinterInSystem(const PrinterInfo& printerInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    printerInfo.Marshalling(data);
    PRINT_HILOGD("PrintServiceProxy UpdatePrinterInSystem started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy UpdatePrinterInSystem remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERINSYSTEM,
        data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy UpdatePrinterInSystem out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::AnalyzePrintEvents(const std::string &printerId, const std::string &type,
    std::string &detail)
{
    PRINT_HILOGD("PrintServiceProxy AnalyzePrintEvents started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy AnalyzePrintEvents remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    data.WriteString(type);
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_ANALYZEPRINTEVENTS,
        data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("AnalyzePrintEvents, error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }
    ret = GetResult(ret, reply);
    detail = reply.ReadString();
    PRINT_HILOGD("PrintServiceProxy AnalyzePrintEvents out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::LoadExtSuccess(const std::string &extensionId)
{
    PRINT_HILOGD("PrintServiceProxy::LoadExtSuccess in");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(extensionId);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy LoadExtSuccess remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_LOAD_EXT, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy LoadExtSuccess out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::RestartPrintJob(const std::string &jobId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(jobId);
    PRINT_HILOGD("PrintServiceProxy RestartPrintJob started.");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy RestartPrintJob remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_RESTARTPRINTJOB, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGD("PrintServiceProxy RestartPrintJob out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::AuthPrintJob(const std::string &jobId, const std::string &userName, char *userPasswd)
{
    PRINT_HILOGI("PrintServiceProxy AuthPrintJob started.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(jobId);
    data.WriteString(userName);

    if (userPasswd == nullptr) {
        PRINT_HILOGE("PrintServiceProxy AuthPrintJob parameter is null");
        return E_PRINT_INVALID_PARAMETER;
    }
    data.WriteBuffer(static_cast<void*>(userPasswd), MAX_AUTH_LENGTH_SIZE);

    PrintUtil::SafeDeleteAuthInfo(userPasswd);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy AuthPrintJob remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_AUTHPRINTJOB, data, reply, option);
    ret = GetResult(ret, reply);
    PRINT_HILOGI("PrintServiceProxy AuthPrintJob out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::QueryAllPrinterPpds(std::vector<PpdInfo> &ppdInfos)
{
    PRINT_HILOGI("PrintServiceProxy QueryAllPrinterPpds started.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy QueryAllPrinterPpds remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLPPDS, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("QueryAllPrinterPpds Failed, error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }
    ret = GetResult(ret, reply);
    if (ret == ERR_NONE) {
        uint32_t len = reply.ReadUint32();
        if (len > PRINT_MAX_PPD_COUNT) {
            PRINT_HILOGE("len is out of range.");
            return E_PRINT_INVALID_PARAMETER;
        }
        for (uint32_t i = 0; i < len; ++i) {
            auto infoPtr = PpdInfo::Unmarshalling(reply);
            if (infoPtr == nullptr) {
                PRINT_HILOGE("wrong ppdInfo from data.");
                return E_PRINT_GENERIC_FAILURE;
            }
            ppdInfos.emplace_back(*infoPtr);
        }
    }
    PRINT_HILOGI("PrintServiceProxy QueryAllPrinterPpds out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::QueryPrinterInfoByIp(const std::string &printerIp)
{
    PRINT_HILOGI("PrintServiceProxy QueryPrinterInfoByIp started.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerIp);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy QueryPrinterInfoByIp remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYIPINFO, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("QueryPrinterInfoByIp Failed, error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }
    ret = GetResult(ret, reply);
    PRINT_HILOGI("PrintServiceProxy QueryPrinterInfoByIp out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::ConnectPrinterByIpAndPpd(const std::string &printerIp, const std::string &protocol,
    const std::string &ppdName)
{
    PRINT_HILOGI("PrintServiceProxy ConnectPrinterByIpAndPpd started.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerIp);
    data.WriteString(protocol);
    data.WriteString(ppdName);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy ConnectPrinterByIpAndPpd remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_CONNECTPRINTERBYIPANDPPD,
        data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("ConnectPrinterByIpAndPpd Failed, error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }
    ret = GetResult(ret, reply);
    PRINT_HILOGI("PrintServiceProxy ConnectPrinterByIpAndPpd out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::SavePdfFileJob(const std::string &jobId, uint32_t fd)
{
    PRINT_HILOGI("PrintServiceProxy SavePdfFileJob started.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(jobId);
    data.WriteFileDescriptor(fd);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy SavePdfFileJob remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_SAVEPDFFILEJOB, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("SavePdfFileJob Failed, error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }
    ret = GetResult(ret, reply);
    PRINT_HILOGI("PrintServiceProxy SavePdfFileJob out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::QueryRecommendDriversById(const std::string &printerId, std::vector<PpdInfo> &ppds)
{
    PRINT_HILOGI("PrintServiceProxy QueryRecommendDriversById started.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy QueryRecommendDriversById remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_QUERYRECOMMENDDRVIERSBYID,
        data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("QueryRecommendDriversById Failed, error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }
    ret = GetResult(ret, reply);
    if (ret == ERR_NONE) {
        uint32_t len = reply.ReadUint32();
        if (len > PRINT_MAX_PPD_COUNT) {
            PRINT_HILOGE("len is out of range.");
            return E_PRINT_INVALID_PARAMETER;
        }
        for (uint32_t i = 0; i < len; ++i) {
            auto infoPtr = PpdInfo::Unmarshalling(reply);
            if (infoPtr == nullptr) {
                PRINT_HILOGE("wrong ppdInfo from data.");
                return E_PRINT_GENERIC_FAILURE;
            }
            ppds.emplace_back(*infoPtr);
        }
    }
    PRINT_HILOGI("PrintServiceProxy QueryRecommendDriversById out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::ConnectPrinterByIdAndPpd(const std::string &printerId, const std::string &protocol,
    const std::string &ppdName)
{
    PRINT_HILOGI("PrintServiceProxy ConnectPrinterByIdAndPpd started.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    data.WriteString(protocol);
    data.WriteString(ppdName);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy ConnectPrinterByIdAndPpd remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_CONNECTPRINTERBYIDANDPPD,
        data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("ConnectPrinterByIdAndPpd Failed, error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }
    ret = GetResult(ret, reply);
    PRINT_HILOGI("PrintServiceProxy ConnectPrinterByIdAndPpd out. ret = [%{public}d]", ret);
    return ret;
}

int32_t PrintServiceProxy::CheckPreferencesConflicts(const std::string &printerId, const std::string &changedType,
    const PrinterPreferences &printerPreference, std::vector<std::string> &conflictingOptions)
{
    PRINT_HILOGI("PrintServiceProxy CheckPreferencesConflicts started.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);
    data.WriteString(changedType);
    printerPreference.Marshalling(data);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy CheckPreferencesConflicts remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_CHECKPREFERENCESCONFLICTS,
        data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("CheckPreferencesConflicts failed, error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }
    ret = reply.ReadInt32();
    reply.ReadStringVector(&conflictingOptions);
    PRINT_HILOGD("CheckPreferencesConflicts conflictingOptions ret:%{public}d size:%{public}zu",
        ret, conflictingOptions.size());
    return ret;
}

int32_t PrintServiceProxy::CheckPrintJobConflicts(const std::string &changedType,
    const PrintJob &printJob, std::vector<std::string> &conflictingOptions)
{
    PRINT_HILOGI("PrintServiceProxy CheckPrintJobConflicts started.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(changedType);
    printJob.Marshalling(data);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy CheckPrintJobConflicts remote is null");
        return E_PRINT_RPC_FAILURE;
    }

    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_CHECKPRINTJOBCONFLICTS,
        data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("CheckPrintJobConflicts failed, error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }

    ret = reply.ReadInt32();
    reply.ReadStringVector(&conflictingOptions);
    PRINT_HILOGD("CheckPrintJobConflicts conflictingOptions ret:%{public}d size:%{public}zu",
        ret, conflictingOptions.size());
    return ret;
}

int32_t PrintServiceProxy::GetPrinterDefaultPreferences(
    const std::string &printerId, PrinterPreferences &defaultPreferences)
{
    PRINT_HILOGI("PrintServiceProxy GetPrinterDefaultPreferences started.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    data.WriteString(printerId);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy GetPrinterDefaultPreferences remote is null");
        return E_PRINT_RPC_FAILURE;
    }

    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_GETPRINTERDEFAULTPREFERENCES,
        data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("GetPrinterDefaultPreferences failed, error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }

    ret = GetResult(ret, reply);
    auto preferencesPtr = PrinterPreferences::Unmarshalling(reply);
    if (preferencesPtr == nullptr) {
        PRINT_HILOGE("wrong preferences from data");
        return E_PRINT_GENERIC_FAILURE;
    }
    defaultPreferences = *preferencesPtr;
    PRINT_HILOGD("GetPrinterDefaultPreferences out.");
    return ret;
}

int32_t PrintServiceProxy::GetSharedHosts(std::vector<PrintSharedHost> &sharedHosts)
{
    PRINT_HILOGI("PrintServiceProxy GetSharedHosts started.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy GetSharedHosts remote is null");
        return E_PRINT_RPC_FAILURE;
    }

    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_GET_SHAREDHOSTS,
        data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("GetSharedHosts failed, error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }
    ret = GetResult(ret, reply);
    if (ret == ERR_NONE) {
        int32_t len = reply.ReadInt32();
        if (len > PRINT_MAX_PRINT_COUNT) {
            PRINT_HILOGE("len is out of range.");
            return E_PRINT_INVALID_PARAMETER;
        }
        for (int32_t i = 0; i < len; ++i) {
            auto sharedHostPtr = PrintSharedHost::Unmarshalling(reply);
            if (sharedHostPtr == nullptr) {
                PRINT_HILOGE("wrong sharedHost from data.");
                return E_PRINT_GENERIC_FAILURE;
            }
            sharedHosts.emplace_back(*sharedHostPtr);
        }
    }
    return ret;
}

int32_t PrintServiceProxy::AuthSmbDevice(const PrintSharedHost &sharedHost, const std::string &userName,
    char *userPasswd, std::vector<PrinterInfo>& printerInfos)
{
    PRINT_HILOGI("PrintServiceProxy AuthSmbDevice started.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(GetDescriptor());
    sharedHost.Marshalling(data);
    data.WriteString(userName);
    if (userPasswd) {
        data.WriteBuffer(static_cast<void*>(userPasswd), MAX_AUTH_LENGTH_SIZE);
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceProxy AuthSmbDevice remote is null");
        return E_PRINT_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(OHOS::Print::IPrintInterfaceCode::CMD_AUTH_SMB_DEVICE, data, reply, option);
    if (ret != ERR_NONE) {
        PRINT_HILOGE("AuthSmbDevice failed, error code = %{public}d", ret);
        return E_PRINT_RPC_FAILURE;
    }
    ret = GetResult(ret, reply);
    if (ret == ERR_NONE) {
        uint32_t len = reply.ReadInt32();
        if (len > PRINT_MAX_PRINT_COUNT) {
            PRINT_HILOGE("len is out of range.");
            return E_PRINT_INVALID_PARAMETER;
        }
        for (uint32_t i = 0; i < len; ++i) {
            auto printerInfoPtr = PrinterInfo::Unmarshalling(reply);
            if (printerInfoPtr == nullptr) {
                PRINT_HILOGE("wrong printerInfo from data.");
                return E_PRINT_GENERIC_FAILURE;
            }
            printerInfos.emplace_back(*printerInfoPtr);
        }
    }
    PRINT_HILOGI("PrintServiceProxy AuthSmbDevice out. ret = [%{public}d]", ret);
    return ret;
}

} // namespace OHOS::Print
