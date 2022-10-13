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
    cmdMap_[CMD_START_PRINT] = &PrintServiceStub::OnStartPrint;
    cmdMap_[CMD_STOP_PRINT] = &PrintServiceStub::OnStopPrint;    
    cmdMap_[CMD_CONNECTPRINTER] = &PrintServiceStub::OnConnectPrinter;
    cmdMap_[CMD_DISCONNECTPRINTER] = &PrintServiceStub::OnDisconnectPrinter;
    cmdMap_[CMD_STARTDISCOVERPRINTER] = &PrintServiceStub::OnStartDiscoverPrinter;
    cmdMap_[CMD_STOPDISCOVERPRINTER] = &PrintServiceStub::OnStopDiscoverPrint;
    cmdMap_[CMD_QUERYALLEXTENSION] = &PrintServiceStub::OnQueryAllExtension;
    cmdMap_[CMD_STARTPRINTJOB] = &PrintServiceStub::OnStartPrintJob;
    cmdMap_[CMD_CANCELPRINTJOB] = &PrintServiceStub::OnCancelPrintJob;
    cmdMap_[CMD_ADDPRINTERS] = &PrintServiceStub::OnAddPrinters;
    cmdMap_[CMD_REMOVEPRINTERS] = &PrintServiceStub::OnRemovePrinters;
    cmdMap_[CMD_UPDATEPRINTERS] = &PrintServiceStub::OnUpdatePrinters;
    cmdMap_[CMD_UPDATEPRINTERSTATE] = &PrintServiceStub::OnUpdatePrinterState;
    cmdMap_[CMD_UPDATEPRINTJOBSTATE] = &PrintServiceStub::OnUpdatePrintJobState;
    cmdMap_[CMD_UPDATEEXTENSIONINFO] = &PrintServiceStub::OnUpdateExtensionInfo;    
    cmdMap_[CMD_REQUESTPREVIEW] = &PrintServiceStub::OnRequestPreview;
    cmdMap_[CMD_QUERYPRINTERCAPABILITY] = &PrintServiceStub::OnQueryPrinterCapability;
    cmdMap_[CMD_ON] = &PrintServiceStub::OnEventOn;
    cmdMap_[CMD_OFF] = &PrintServiceStub::OnEventOff;
    cmdMap_[CMD_REG_EXT_CB] = &PrintServiceStub::OnRegisterExtCallback;
    cmdMap_[CMD_UNREG_EXT_CB] = &PrintServiceStub::OnUnregisterAllExtCallback;
    cmdMap_[CMD_READ_DATA] = &PrintServiceStub::OnRead;
}

int32_t PrintServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PRINT_HILOGD("OnRemoteRequest started, code = %{public}d", code);
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        PRINT_HILOGE("Remote descriptor not the same as local descriptor.");
        return ERROR_RPC_FAIL;
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
    reply.ReadStringVector(&fileList);
    std::string result = "";
    int32_t ret = StartPrint(fileList, result);
    reply.WriteInt32(ret);
    reply.WriteString(result);
    PRINT_HILOGD("PrintServiceStub::OnStartPrint out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnStopPrint(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStopPrint in");
    std::string taskId = reply.ReadString();
    int32_t ret = StopPrint(taskId);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStopPrint out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnConnectPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnConnectPrinter in");
    int32_t ret = ConnectPrinter(data.ReadString());
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnConnectPrinter out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnDisconnectPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnDisconnectPrinter in");
    int32_t ret = DisconnectPrinter(data.ReadString());
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnDisconnectPrinter out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnStartDiscoverPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStartDiscoverPrinter in");
    std::vector<std::string> extensionList;
    data.ReadStringVector(&extensionList);
    int32_t ret = StartDiscoverPrinter(extensionList);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStartDiscoverPrinter out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnStopDiscoverPrint(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStopDiscoverPrint in");
    int32_t ret = StopDiscoverPrinter();
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStopDiscoverPrint out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnQueryAllExtension(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryAllExtension in");
    std::vector<PrintExtensionInfo> printerInfo;
    int32_t ret = QueryAllExtension(printerInfo);
    reply.WriteInt32(ret);
    if (ret == ERROR_NONE) {
        uint32_t size = static_cast<uint32_t>(printerInfo.size());
        reply.WriteUint32(size);
        for (uint32_t index = 0; index < size; index++) {
            printerInfo[index].Marshalling(reply);
        }
    }
    PRINT_HILOGD("PrintServiceStub::OnQueryAllExtension out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnStartPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStartPrintJob in");
    int32_t ret = ERROR_RPC_FAIL;
    auto jobInfoPtr = PrintJob::Unmarshalling(data);
    if (jobInfoPtr != nullptr) {
        jobInfoPtr->Dump();
        ret = StartPrintJob(*jobInfoPtr);
    }
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStartPrintJob out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnCancelPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnCancelPrintJob in");
    int32_t ret = ERROR_RPC_FAIL;
    auto jobInfoPtr = PrintJob::Unmarshalling(data);
    if (jobInfoPtr != nullptr) {
        jobInfoPtr->Dump();
        ret = CancelPrintJob(*jobInfoPtr);
    }
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStartPrintJob out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnAddPrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnAddPrinters in");
    std::vector<PrinterInfo> printerInfos;
    uint32_t len = data.ReadUint32();
    PRINT_HILOGD("OnStartDiscoverPrinter len = %{public}d", len);

    for (uint32_t i = 0; i < len; i++) {
        auto infoPtr = PrinterInfo::Unmarshalling(data);
        if (infoPtr == nullptr) {
            PRINT_HILOGW("invalid printer object");
            continue;
        }
        infoPtr->Dump();
        printerInfos.emplace_back(*infoPtr);
    }
    int32_t ret = ERROR_RPC_FAIL;
    if (printerInfos.size() > 0) {
        ret = AddPrinters(printerInfos);
    }
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnAddPrinters out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnRemovePrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRemovePrinters in");   
    std::vector<std::string> printerIds;
    data.ReadStringVector(&printerIds);
    PRINT_HILOGD("OnStartDiscoverPrinter len = %{public}zd", printerIds.size());
    int32_t ret = RemovePrinters(printerIds);
    reply.WriteInt32(ret);

    PRINT_HILOGD("PrintServiceStub::OnRemovePrinters out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnUpdatePrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinters in");  
    std::vector<PrinterInfo> printerInfos;
    uint32_t len = data.ReadUint32();
    PRINT_HILOGD("OnStartDiscoverPrinter len = %{public}d", len);

    for (uint32_t i = 0; i < len; i++) {
        auto infoPtr = PrinterInfo::Unmarshalling(data);
        if (infoPtr == nullptr) {
            PRINT_HILOGW("invalid printer object");
            continue;
        }
        infoPtr->Dump();
        printerInfos.emplace_back(*infoPtr);
    }
    int32_t ret = ERROR_RPC_FAIL;
    if (printerInfos.size() > 0) {
        ret = UpdatePrinters(printerInfos);
    }
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinters out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnUpdatePrinterState(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterState in");
    std::string printerId = data.ReadString();
    uint32_t state = data.ReadUint32();
    int32_t ret = UpdatePrinterState(printerId, state);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterState out");
    return ret == ERROR_NONE;
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
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnUpdateExtensionInfo(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdateExtensionInfo in");
    std::string extensionId = data.ReadString();
    std::string extInfo = data.ReadString();
    PRINT_HILOGD("OnUpdateExtensionInfo extensionId = %{public}s", extensionId.c_str());
    PRINT_HILOGD("OnUpdateExtensionInfo extInfo = %{public}s", extInfo.c_str());

    int32_t ret = UpdateExtensionInfo(extensionId, extInfo);
    reply.WriteInt32(ret);    
    PRINT_HILOGD("PrintServiceStub::OnUpdateExtensionInfo out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnRequestPreview(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRequestPreview in");
    int32_t ret = ERROR_RPC_FAIL;
    std::string previewResult = "";
    auto jobInfoPtr = PrintJob::Unmarshalling(data);
    if (jobInfoPtr != nullptr) {
        jobInfoPtr->Dump();
        ret = RequestPreview(*jobInfoPtr, previewResult);
    }
    reply.WriteInt32(ret);
    reply.WriteString(previewResult);
    PRINT_HILOGD("PrintServiceStub::OnRequestPreview out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnQueryPrinterCapability(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapability in");
    std::string printerId = data.ReadString();
    PRINT_HILOGD("printerId : %{public}s", printerId.c_str());
    PrinterCapability printerCapability;
    int32_t ret = QueryPrinterCapability(printerId, printerCapability);
    reply.WriteInt32(ret);    
    printerCapability.Marshalling(reply);
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapability out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnEventOn(MessageParcel &data, MessageParcel &reply)
{
    std::string type = data.ReadString();
    PRINT_HILOGD("PrintServiceStub::OnEventOn type=%{public}s ", type.c_str());
    if (type.empty()) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn type is null.");
        reply.WriteInt32(ERROR_RPC_FAIL);
        return false;
    }
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn remote is nullptr");
        reply.WriteInt32(ERROR_RPC_FAIL);
        return false;
    }
    sptr<IPrintCallback> listener = iface_cast<IPrintCallback>(remote);
    if (listener.GetRefPtr() == nullptr) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn listener is null");
        reply.WriteInt32(ERROR_RPC_FAIL);
        return false;
    }
    int32_t ret = On(type, listener);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnEventOn out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnEventOff(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnEventOff in");
    std::string type = data.ReadString();
    PRINT_HILOGD("PrintServiceStub::OnEventOff type=%{public}s ", type.c_str());
    int32_t ret = Off(type);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnEventOff out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnRegisterExtCallback(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback in");
    std::string extensionCID = data.ReadString();
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback remote is nullptr");
        reply.WriteInt32(ERROR_RPC_FAIL);
        return false;
    }
    sptr<IPrintExtensionCallback> listener = iface_cast<IPrintExtensionCallback>(remote);
    if (listener.GetRefPtr() == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback listener is null");
        reply.WriteInt32(ERROR_RPC_FAIL);
        return false;
    }

    int32_t ret = RegisterExtCallback(extensionCID, listener);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnUnregisterAllExtCallback(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback in");
    std::string extensionId = data.ReadString();    
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnUnregisterAllExtCallback remote is nullptr");
        reply.WriteInt32(ERROR_RPC_FAIL);
        return true;
    }
    sptr<IPrintExtensionCallback> listener = iface_cast<IPrintExtensionCallback>(remote);
    if (listener.GetRefPtr() == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnUnregisterAllExtCallback listener is null");
        reply.WriteInt32(ERROR_RPC_FAIL);
        return false;
    }

    int32_t ret = UnregisterAllExtCallback(extensionId);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUnregisterAllExtCallback out");
    return ret == ERROR_NONE;
}

bool PrintServiceStub::OnRead(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRead in");
    std::string fileUrl = data.ReadString();
    uint32_t offset = data.ReadUint32();
    uint32_t max = data.ReadUint32();

    FILE *file = fopen(fileUrl.c_str(), "rb");
    if (file == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnRead no permission");
        if (!reply.WriteBool(false)) {
            return false;
        }
        return true;
    }
    fseek(file, 0, SEEK_END);
    uint32_t totalSize = static_cast<uint32_t>(ftell(file));
    uint32_t size = totalSize - offset;
    if (size > max) {
        size = max;
    }

    std::vector<uint8_t> fileRead;
    fileRead.resize(size);
    fread(&fileRead[0], 1, size, file);

    if (!reply.WriteBool(true)) {
        PRINT_HILOGD("PrintServiceStub::OnRead failed to write response");
        return false;
    }
    reply.WriteUInt8Vector(fileRead);
    PRINT_HILOGD("PrintServiceStub::OnRead out");
    return true;    
}
} // namespace OHOS::Print
