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
#include "print_constant.h"
#include "print_extension_info.h"
#include "print_job.h"
#include "print_log.h"

namespace OHOS::Print {
using namespace OHOS::HiviewDFX;

PrintServiceStub::PrintServiceStub()
{
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_START_PRINT] = &PrintServiceStub::OnStartPrint;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_STOP_PRINT] = &PrintServiceStub::OnStopPrint;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_CONNECTPRINTER] = &PrintServiceStub::OnConnectPrinter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_DISCONNECTPRINTER] = &PrintServiceStub::OnDisconnectPrinter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_STARTDISCOVERPRINTER] = &PrintServiceStub::OnStartDiscoverPrinter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_STOPDISCOVERPRINTER] = &PrintServiceStub::OnStopDiscoverPrint;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLEXTENSION] = &PrintServiceStub::OnQueryAllExtension;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_STARTPRINTJOB] = &PrintServiceStub::OnStartPrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_CANCELPRINTJOB] = &PrintServiceStub::OnCancelPrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ADDPRINTERS] = &PrintServiceStub::OnAddPrinters;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REMOVEPRINTERS] = &PrintServiceStub::OnRemovePrinters;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERS] = &PrintServiceStub::OnUpdatePrinters;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERSTATE] = &PrintServiceStub::OnUpdatePrinterState;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTJOBSTATE] = &PrintServiceStub::OnUpdatePrintJobState;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEEXTENSIONINFO] = &PrintServiceStub::OnUpdateExtensionInfo;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REQUESTPREVIEW] = &PrintServiceStub::OnRequestPreview;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERCAPABILITY] = &PrintServiceStub::OnQueryPrinterCapability;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ON] = &PrintServiceStub::OnEventOn;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_OFF] = &PrintServiceStub::OnEventOff;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REG_EXT_CB] = &PrintServiceStub::OnRegisterExtCallback;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UNREG_EXT_CB] = &PrintServiceStub::OnUnregisterAllExtCallback;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_LOAD_EXT] = &PrintServiceStub::OnLoadExtSuccess;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLPRINTJOB] = &PrintServiceStub::OnQueryAllPrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTJOBBYID] = &PrintServiceStub::OnQueryPrintJobById;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ADDPRINTERTOCUPS] = &PrintServiceStub::OnAddPrinterToCups;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERCAPABILITYBYURI] =
        &PrintServiceStub::OnQueryPrinterCapabilityByUri;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_STARTPRINTJOB_BY_ADAPTER] = &PrintServiceStub::OnPrintByAdapter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_START_GET_FILE] = &PrintServiceStub::OnStartGetPrintFile;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_NOTIFY_PRINT_SERVICE] = &PrintServiceStub::OnNotifyPrintService;
}

int32_t PrintServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PRINT_HILOGD("OnRemoteRequest started, code = %{public}d", code);
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        PRINT_HILOGE("Remote descriptor not the same as local descriptor.");
        return E_PRINT_RPC_FAILURE;
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
    std::vector<std::string> fileList;
    std::vector<uint32_t> fdList;
    std::string result = "";

    if (data.ReadBool()) {
        data.ReadStringVector(&fileList);
        PRINT_HILOGD("Current file is %{public}zd", fileList.size());
        CHECK_IS_EXCEED_PRINT_RANGE_BOOL(fileList.size());
        for (auto file : fileList) {
            PRINT_HILOGD("file is %{private}s", file.c_str());
        }
    }

    if (data.ReadBool()) {
        int32_t len = data.ReadInt32();
        CHECK_IS_EXCEED_PRINT_RANGE_BOOL(len);
        for (int32_t index = 0; index < len; index++) {
            uint32_t fd = static_cast<uint32_t>(data.ReadFileDescriptor());
            PRINT_HILOGD("fdList[%{public}d] = %{public}d", index, fd);
            fdList.emplace_back(fd);
        }
    }

    sptr<IRemoteObject> token = data.ReadRemoteObject();
    PRINT_HILOGI("OnStartPrint read token %{public}s", token != nullptr ? "success" : "failed");
    int32_t ret = E_PRINT_NONE;
    if (token == nullptr) {
        ret = StartPrint(fileList, fdList, result);
    } else {
        ret = StartPrint(fileList, fdList, result, token);
    }
    reply.WriteInt32(ret);
    reply.WriteString(result);
    PRINT_HILOGD("PrintServiceStub::OnStartPrint out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStopPrint(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStopPrint in");
    std::string taskId = data.ReadString();
    int32_t ret = StopPrint(taskId);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStopPrint out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnConnectPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnConnectPrinter in");
    int32_t ret = ConnectPrinter(data.ReadString());
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnConnectPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnDisconnectPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnDisconnectPrinter in");
    int32_t ret = DisconnectPrinter(data.ReadString());
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnDisconnectPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStartDiscoverPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStartDiscoverPrinter in");
    std::vector<std::string> extensionList;
    data.ReadStringVector(&extensionList);
    int32_t ret = StartDiscoverPrinter(extensionList);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStartDiscoverPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStopDiscoverPrint(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStopDiscoverPrint in");
    int32_t ret = StopDiscoverPrinter();
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStopDiscoverPrint out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryAllExtension(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryAllExtension in");
    std::vector<PrintExtensionInfo> printerInfo;
    int32_t ret = QueryAllExtension(printerInfo);
    reply.WriteInt32(ret);
    if (ret == E_PRINT_NONE) {
        uint32_t size = static_cast<uint32_t>(printerInfo.size());
        reply.WriteUint32(size);
        for (uint32_t index = 0; index < size; index++) {
            printerInfo[index].Marshalling(reply);
        }
    }
    PRINT_HILOGD("PrintServiceStub::OnQueryAllExtension out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStartPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStartPrintJob in");
    int32_t ret = E_PRINT_RPC_FAILURE;
    auto jobInfoPtr = PrintJob::Unmarshalling(data);
    if (jobInfoPtr != nullptr) {
        jobInfoPtr->Dump();
        ret = StartPrintJob(*jobInfoPtr);
    }
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStartPrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnCancelPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnCancelPrintJob in");
    int32_t ret = CancelPrintJob(data.ReadString());
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStartPrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnAddPrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnAddPrinters in");
    std::vector<PrinterInfo> printerInfos;
    uint32_t len = data.ReadUint32();
    PRINT_HILOGD("OnStartDiscoverPrinter len = %{public}d", len);

    CHECK_IS_EXCEED_PRINT_RANGE_BOOL(len);
    for (uint32_t i = 0; i < len; i++) {
        auto infoPtr = PrinterInfo::Unmarshalling(data);
        if (infoPtr == nullptr) {
            PRINT_HILOGW("invalid printer object");
            continue;
        }
        infoPtr->Dump();
        printerInfos.emplace_back(*infoPtr);
    }
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (printerInfos.size() > 0) {
        ret = AddPrinters(printerInfos);
    }
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnAddPrinters out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRemovePrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRemovePrinters in");
    std::vector<std::string> printerIds;
    data.ReadStringVector(&printerIds);
    PRINT_HILOGD("OnStartDiscoverPrinter len = %{public}zd", printerIds.size());

    CHECK_IS_EXCEED_PRINT_RANGE_BOOL(printerIds.size());
    int32_t ret = RemovePrinters(printerIds);
    reply.WriteInt32(ret);

    PRINT_HILOGD("PrintServiceStub::OnRemovePrinters out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdatePrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinters in");
    std::vector<PrinterInfo> printerInfos;
    uint32_t len = data.ReadUint32();
    PRINT_HILOGD("OnStartDiscoverPrinter len = %{public}d", len);

    CHECK_IS_EXCEED_PRINT_RANGE_BOOL(len);
    for (uint32_t i = 0; i < len; i++) {
        auto infoPtr = PrinterInfo::Unmarshalling(data);
        if (infoPtr == nullptr) {
            PRINT_HILOGW("invalid printer object");
            continue;
        }
        infoPtr->Dump();
        printerInfos.emplace_back(*infoPtr);
    }
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (printerInfos.size() > 0) {
        ret = UpdatePrinters(printerInfos);
    }
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinters out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdatePrinterState(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterState in");
    std::string printerId = data.ReadString();
    uint32_t state = data.ReadUint32();
    int32_t ret = UpdatePrinterState(printerId, state);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterState out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdatePrintJobState(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrintJobState in");
    std::string jobId = data.ReadString();
    uint32_t state = data.ReadUint32();
    uint32_t subState = data.ReadUint32();
    PRINT_HILOGD("OnUpdatePrintJobState jobId = %{public}s", jobId.c_str());
    PRINT_HILOGD("OnUpdatePrintJobState state = %{public}d", state);
    PRINT_HILOGD("OnUpdatePrintJobState subState = %{public}d", subState);

    int32_t ret = UpdatePrintJobState(jobId, state, subState);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrintJobState out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdateExtensionInfo(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdateExtensionInfo in");
    std::string extInfo = data.ReadString();
    PRINT_HILOGD("OnUpdateExtensionInfo extInfo = %{public}s", extInfo.c_str());

    int32_t ret = UpdateExtensionInfo(extInfo);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUpdateExtensionInfo out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRequestPreview(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRequestPreview in");
    int32_t ret = E_PRINT_RPC_FAILURE;
    std::string previewResult = "";
    auto jobInfoPtr = PrintJob::Unmarshalling(data);
    if (jobInfoPtr != nullptr) {
        jobInfoPtr->Dump();
        ret = RequestPreview(*jobInfoPtr, previewResult);
    }
    reply.WriteInt32(ret);
    reply.WriteString(previewResult);
    PRINT_HILOGD("PrintServiceStub::OnRequestPreview out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryPrinterCapability(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapability in");
    std::string printerId = data.ReadString();
    PRINT_HILOGD("printerId : %{private}s", printerId.c_str());
    int32_t ret = QueryPrinterCapability(printerId);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapability out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryAllPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryAllPrintJob in");
    std::vector<PrintJob> printJob;
    printJob.clear();
    int32_t ret = QueryAllPrintJob(printJob);
    reply.WriteInt32(ret);
    if (ret == E_PRINT_NONE) {
        uint32_t size = static_cast<uint32_t>(printJob.size());
        reply.WriteUint32(size);
        for (uint32_t index = 0; index < size; index++) {
            printJob[index].Marshalling(reply);
        }
    }
    PRINT_HILOGD("PrintServiceStub::OnQueryAllPrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryPrintJobById(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryPrintJobById in");
    PrintJob printJob;
    std::string printJobId = data.ReadString();
    int32_t ret = QueryPrintJobById(printJobId, printJob);
    reply.WriteInt32(ret);
    printJob.Marshalling(reply);
    PRINT_HILOGD("PrintServiceStub::OnQueryPrintJobById out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnAddPrinterToCups(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnAddPrinterToCups in");
    std::string printerUri = data.ReadString();
    std::string printerName = data.ReadString();
    std::string printerMake = data.ReadString();
    int32_t ret = AddPrinterToCups(printerUri, printerName, printerMake);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnAddPrinterToCups out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryPrinterCapabilityByUri(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapabilityByUri in");
    PrinterCapability printerCaps;
    std::string printerUri = data.ReadString();
    std::string printerId = data.ReadString();
    int32_t ret = QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
    reply.WriteInt32(ret);
    printerCaps.Marshalling(reply);
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapabilityByUri out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnEventOn(MessageParcel &data, MessageParcel &reply)
{
    std::string taskId = data.ReadString();
    std::string type = data.ReadString();
    PRINT_HILOGD("PrintServiceStub::OnEventOn type=%{public}s ", type.c_str());
    if (type.empty()) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn type is null.");
        reply.WriteInt32(E_PRINT_RPC_FAILURE);
        return false;
    }
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn remote is nullptr");
        reply.WriteInt32(E_PRINT_RPC_FAILURE);
        return false;
    }
    sptr<IPrintCallback> listener = iface_cast<IPrintCallback>(remote);
    if (listener.GetRefPtr() == nullptr) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn listener is null");
        reply.WriteInt32(E_PRINT_RPC_FAILURE);
        return false;
    }
    int32_t ret = On(taskId, type, listener);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnEventOn out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnEventOff(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnEventOff in");
    std::string taskId = data.ReadString();
    std::string type = data.ReadString();
    PRINT_HILOGD("PrintServiceStub::OnEventOff type=%{public}s ", type.c_str());
    int32_t ret = Off(taskId, type);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnEventOff out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRegisterExtCallback(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback in");
    std::string extensionCID = data.ReadString();
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback remote is nullptr");
        reply.WriteInt32(E_PRINT_RPC_FAILURE);
        return false;
    }
    sptr<IPrintExtensionCallback> listener = iface_cast<IPrintExtensionCallback>(remote);
    if (listener.GetRefPtr() == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback listener is null");
        reply.WriteInt32(E_PRINT_RPC_FAILURE);
        return false;
    }

    int32_t ret = RegisterExtCallback(extensionCID, listener);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUnregisterAllExtCallback(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUnregisterAllExtCallback in");
    std::string extensionId = data.ReadString();
    int32_t ret = UnregisterAllExtCallback(extensionId);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUnregisterAllExtCallback out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnLoadExtSuccess(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnLoadExtSuccess in");
    std::string extensionId = data.ReadString();
    int32_t ret = LoadExtSuccess(extensionId);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnLoadExtSuccess out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnPrintByAdapter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnPrintByAdapter in");
    std::string resultTaskId = "";
    int32_t ret = E_PRINT_RPC_FAILURE;
    std::string jobName = data.ReadString();
    auto attrs = PrintAttributes::Unmarshalling(data);
    sptr<IRemoteObject> token = data.ReadRemoteObject();
    if (attrs != nullptr) {
        attrs->Dump();
        ret = PrintByAdapter(jobName, *attrs, resultTaskId, token);
    }
    reply.WriteInt32(ret);
    reply.WriteString(resultTaskId);
    PRINT_HILOGI("PrintServiceStub::OnPrintByAdapter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStartGetPrintFile(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnStartGetPrintFile in");
    int32_t ret = E_PRINT_RPC_FAILURE;
    std::string jobId = data.ReadString();
    auto attrs = PrintAttributes::Unmarshalling(data);
    uint32_t fd = static_cast<uint32_t>(data.ReadFileDescriptor());
    ret = StartGetPrintFile(jobId, *attrs, fd);
    reply.WriteInt32(ret);
    PRINT_HILOGI("PrintServiceStub::OnStartGetPrintFile out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnNotifyPrintService(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnNotifyPrintService in");
    std::string jobId = data.ReadString();
    std::string type = data.ReadString();
    PRINT_HILOGD(
        "PrintServiceStub::OnNotifyPrintService jobId=%{public}s type=%{public}s ", jobId.c_str(), type.c_str());
    int32_t ret = NotifyPrintService(jobId, type);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnNotifyPrintService out");
    return ret == E_PRINT_NONE;
}
} // namespace OHOS::Print
