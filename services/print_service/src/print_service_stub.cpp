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
#include "print_util.h"
#include <securec.h>

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
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTJOBSTATE_FORNORMALAPP] =
        &PrintServiceStub::OnUpdatePrintJobStateForNormalApp;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTJOBSTATE_FORSYSTEMAPP] =
        &PrintServiceStub::OnUpdatePrintJobStateOnlyForSystemApp;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEEXTENSIONINFO] = &PrintServiceStub::OnUpdateExtensionInfo;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REQUESTPREVIEW] = &PrintServiceStub::OnRequestPreview;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERCAPABILITY] =
        &PrintServiceStub::OnQueryPrinterCapability;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ON] = &PrintServiceStub::OnEventOn;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_OFF] = &PrintServiceStub::OnEventOff;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REG_EXT_CB] = &PrintServiceStub::OnRegisterExtCallback;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UNREG_EXT_CB] = &PrintServiceStub::OnUnregisterAllExtCallback;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_LOAD_EXT] = &PrintServiceStub::OnLoadExtSuccess;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLACTIVEPRINTJOB] = &PrintServiceStub::OnQueryAllActivePrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLPRINTJOB] =
        &PrintServiceStub::OnQueryAllPrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTJOBBYID] = &PrintServiceStub::OnQueryPrintJobById;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ADDPRINTERTOCUPS] = &PrintServiceStub::OnAddPrinterToCups;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERCAPABILITYBYURI] =
        &PrintServiceStub::OnQueryPrinterCapabilityByUri;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_STARTPRINTJOB_BY_ADAPTER] = &PrintServiceStub::OnPrintByAdapter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_START_GET_FILE] = &PrintServiceStub::OnStartGetPrintFile;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_NOTIFY_PRINT_SERVICE] = &PrintServiceStub::OnNotifyPrintService;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_START_SERVICE] = &PrintServiceStub::OnStartService;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REG_PRINTER_CB] = &PrintServiceStub::OnRegisterPrinterCallback;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UNREG_PRINTER_CB] = &PrintServiceStub::OnUnregisterPrinterCallback;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERINFOBYPRINTERID] =
        &PrintServiceStub::OnQueryPrinterInfoByPrinterId;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYADDEDPRINTER] = &PrintServiceStub::OnQueryAddedPrinter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERPROPERTIES] =
        &PrintServiceStub::OnQueryPrinterProperties;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_STARTNATIVEPRINTJOB] = &PrintServiceStub::OnStartNativePrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_NOTIFY_PRINT_SERVICE_EVENT] =
        &PrintServiceStub::OnNotifyPrintServiceEvent;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_SET_PRINTER_PREFERENCE] =
        &PrintServiceStub::OnSetPrinterPreference;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_SET_DEFAULT_PRINTERID] = &PrintServiceStub::OnSetDefaultPrinter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_DELETE_PRINTER_FROM_CUPS] =
        &PrintServiceStub::OnDeletePrinterFromCups;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_DISCOVER_USB_PRINTERS] = &PrintServiceStub::OnDiscoverUsbPrinters;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ADDPRINTERTODISCOVERY] = &PrintServiceStub::OnAddPrinterToDiscovery;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERINDISCOVERY] =
        &PrintServiceStub::OnUpdatePrinterInDiscovery;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REMOVEPRINTERFROMDISCOVERY] =
        &PrintServiceStub::OnRemovePrinterFromDiscovery;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERINSYSTEM] =
        &PrintServiceStub::OnUpdatePrinterInSystem;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_RESTARTPRINTJOB] = &PrintServiceStub::OnRestartPrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ANALYZEPRINTEVENTS] = &PrintServiceStub::OnAnalyzePrintEvents;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_AUTHPRINTJOB] = &PrintServiceStub::OnAuthPrintJob;
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
            bool result = (this->*requestFunc)(data, reply);
            return result ? E_PRINT_NONE : E_PRINT_GENERIC_FAILURE;
        }
    }
    PRINT_HILOGW("default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool PrintServiceStub::OnStartService(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("nativePrint PrintServiceStub::OnStartService in");
    int32_t ret = E_PRINT_INVALID_PARAMETER;
    if (data.ReadString() == "nativePrint") {
        ret = StartService();
        reply.WriteInt32(ret);
        PRINT_HILOGI("nativePrint PrintServiceStub::OnStartService out:%{public}d", ret);
    }
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStartPrint(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnStartPrint in");
    std::vector<std::string> fileList;
    std::vector<uint32_t> fdList;

    if (data.ReadBool()) {
        data.ReadStringVector(&fileList);
        PRINT_HILOGD("Current file is %{public}zd", fileList.size());
        if (fileList.size() > PRINT_MAX_PRINT_COUNT) {
            PRINT_HILOGE("fileList'size is out of range.");
            reply.WriteInt32(E_PRINT_INVALID_PARAMETER);
            return false;
        }
    }

    if (data.ReadBool()) {
        int32_t len = data.ReadInt32();
        if (len > PRINT_MAX_PRINT_COUNT) {
            PRINT_HILOGE("len is out of range.");
            reply.WriteInt32(E_PRINT_INVALID_PARAMETER);
            return false;
        }
        for (int32_t index = 0; index < len; index++) {
            int fdTemp = data.ReadFileDescriptor();
            if (fdTemp >= 0) {
                uint32_t fd = static_cast<uint32_t>(fdTemp);
                PRINT_HILOGD("fdList[%{public}d] = %{public}d", index, fd);
                fdList.emplace_back(fd);
                continue;
            }
            PRINT_HILOGE("invalid fd");
            for (auto fd : fdList) {
                fdsan_close_with_tag(fd, PRINT_LOG_DOMAIN);
            }
            fdList.clear();
            reply.WriteInt32(E_PRINT_INVALID_PARAMETER);
            return false;
        }
    }
    std::string taskId = data.ReadString();
    int32_t ret = StartPrint(fileList, fdList, taskId);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStartPrint out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStopPrint(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnStopPrint in");
    std::string taskId = data.ReadString();
    int32_t ret = StopPrint(taskId);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStopPrint out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnConnectPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnConnectPrinter in");
    int32_t ret = ConnectPrinter(data.ReadString());
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnConnectPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnDisconnectPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnDisconnectPrinter in");
    int32_t ret = DisconnectPrinter(data.ReadString());
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnDisconnectPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStartDiscoverPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnStartDiscoverPrinter in");
    std::vector<std::string> extensionList;
    data.ReadStringVector(&extensionList);
    int32_t ret = StartDiscoverPrinter(extensionList);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStartDiscoverPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStopDiscoverPrint(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnStopDiscoverPrint in");
    int32_t ret = StopDiscoverPrinter();
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStopDiscoverPrint out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryAllExtension(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnQueryAllExtension in");
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
    PRINT_HILOGI("PrintServiceStub::OnStartPrintJob in");
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
    PRINT_HILOGI("PrintServiceStub::OnCancelPrintJob in");
    int32_t ret = CancelPrintJob(data.ReadString());
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnCancelPrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnAddPrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnAddPrinters in");
    std::vector<PrinterInfo> printerInfos;
    uint32_t len = 0;
    if (!data.ReadUint32(len)) {
        PRINT_HILOGE("read data len failed.");
        return false;
    }
    PRINT_HILOGD("OnStartDiscoverPrinter len = %{public}d", len);

    if (len > PRINT_MAX_PRINT_COUNT) {
        PRINT_HILOGE("len is out of range.");
        reply.WriteInt32(E_PRINT_INVALID_PARAMETER);
        return false;
    }
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

bool PrintServiceStub::OnQueryPrinterInfoByPrinterId(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnQueryPrinterInfoByPrinterId in");
    std::string printerId = data.ReadString();
    PrinterInfo info;
    int32_t ret = QueryPrinterInfoByPrinterId(printerId, info);
    reply.WriteInt32(ret);
    PRINT_HILOGI("PrintServiceStub::OnQueryPrinterInfoByPrinterId out %{private}s", info.GetPrinterName().c_str());
    info.Marshalling(reply);
    PRINT_HILOGI("PrintServiceStub::OnQueryPrinterInfoByPrinterId out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnSetPrinterPreference(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnSetPrinterPreference in");
    std::string printerId = data.ReadString();
    auto preferencesPtr = PrinterPreferences::Unmarshalling(data);
    if (preferencesPtr == nullptr) {
        PRINT_HILOGE("Failed to unmarshall printer preferences");
        reply.WriteInt32(E_PRINT_RPC_FAILURE);
        return false;
    }

    int32_t ret = SetPrinterPreference(printerId, *preferencesPtr);
    reply.WriteInt32(ret);
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryAddedPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnQueryAddedPrinter in");
    std::vector<std::string> printerNameList;
    
    int32_t ret = QueryAddedPrinter(printerNameList);
    reply.WriteInt32(ret);
    reply.WriteStringVector(printerNameList);
    
    PRINT_HILOGI("PrintServiceStub::OnQueryAddedPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryPrinterProperties(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnQueryAddedPrinter in");
    std::string printerId = data.ReadString();
    std::vector<std::string> keyList;
    data.ReadStringVector(&keyList);
    std::vector<std::string> valueList;
    int32_t ret = QueryPrinterProperties(printerId, keyList, valueList);
    reply.WriteInt32(ret);
    reply.WriteStringVector(valueList);
    PRINT_HILOGI("PrintServiceStub::OnQueryAddedPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStartNativePrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnStartNativePrintJob in");
    int32_t ret = E_PRINT_RPC_FAILURE;
    auto printJobPtr = PrintJob::Unmarshalling(data);
    if (printJobPtr != nullptr) {
        printJobPtr->Dump();
        ret = StartNativePrintJob(*printJobPtr);
    }
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnStartPrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRemovePrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnRemovePrinters in");
    std::vector<std::string> printerIds;
    data.ReadStringVector(&printerIds);
    PRINT_HILOGD("OnStartDiscoverPrinter len = %{public}zd", printerIds.size());

    if (printerIds.size() > PRINT_MAX_PRINT_COUNT) {
        PRINT_HILOGE("printerIds'size is out of range.");
        reply.WriteInt32(E_PRINT_INVALID_PARAMETER);
        return false;
    }
    int32_t ret = RemovePrinters(printerIds);
    reply.WriteInt32(ret);

    PRINT_HILOGD("PrintServiceStub::OnRemovePrinters out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdatePrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnUpdatePrinters in");
    std::vector<PrinterInfo> printerInfos;
    uint32_t len = 0;
    if (!data.ReadUint32(len)) {
        PRINT_HILOGE("read data len failed.");
        return false;
    }
    PRINT_HILOGD("OnUpdatePrinters len = %{public}d", len);

    if (len > PRINT_MAX_PRINT_COUNT) {
        PRINT_HILOGE("len is out of range.");
        reply.WriteInt32(E_PRINT_INVALID_PARAMETER);
        return false;
    }
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
    PRINT_HILOGI("PrintServiceStub::OnUpdatePrinterState in");
    std::string printerId = data.ReadString();
    uint32_t state = data.ReadUint32();
    int32_t ret = UpdatePrinterState(printerId, state);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterState out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdatePrintJobStateForNormalApp(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnUpdatePrintJobStateForNormalApp in");
    std::string jobId = data.ReadString();
    uint32_t state = data.ReadUint32();
    uint32_t subState = data.ReadUint32();
    PRINT_HILOGD("jobId = %{public}s; state = %{public}d; subState = %{public}d",
        jobId.c_str(), state, subState);
    int32_t ret = UpdatePrintJobStateForNormalApp(jobId, state, subState);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrintJobStateForNormalApp out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdatePrintJobStateOnlyForSystemApp(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnUpdatePrintJobStateOnlyForSystemApp in");
    std::string jobId = data.ReadString();
    uint32_t state = data.ReadUint32();
    uint32_t subState = data.ReadUint32();
    PRINT_HILOGD("OnUpdatePrintJobStateOnlyForSystemApp jobId = %{public}s", jobId.c_str());
    PRINT_HILOGD("OnUpdatePrintJobStateOnlyForSystemApp state = %{public}d", state);
    PRINT_HILOGD("OnUpdatePrintJobStateOnlyForSystemApp subState = %{public}d", subState);

    int32_t ret = UpdatePrintJobStateOnlyForSystemApp(jobId, state, subState);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrintJobStateOnlyForSystemApp out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdateExtensionInfo(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnUpdateExtensionInfo in");
    std::string extInfo = data.ReadString();
    PRINT_HILOGD("OnUpdateExtensionInfo extInfo = %{public}s", extInfo.c_str());

    int32_t ret = UpdateExtensionInfo(extInfo);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUpdateExtensionInfo out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRequestPreview(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnRequestPreview in");
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
    PRINT_HILOGI("PrintServiceStub::OnQueryPrinterCapability in");
    std::string printerId = data.ReadString();
    PRINT_HILOGD("printerId : %{private}s", printerId.c_str());
    int32_t ret = QueryPrinterCapability(printerId);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapability out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryAllActivePrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnQueryAllActivePrintJob in");
    std::vector<PrintJob> printJob;
    printJob.clear();
    int32_t ret = QueryAllActivePrintJob(printJob);
    reply.WriteInt32(ret);
    if (ret == E_PRINT_NONE) {
        uint32_t size = static_cast<uint32_t>(printJob.size());
        reply.WriteUint32(size);
        for (uint32_t index = 0; index < size; index++) {
            printJob[index].Marshalling(reply);
        }
    }
    PRINT_HILOGD("PrintServiceStub::OnQueryAllActivePrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryAllPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnQueryAllPrintJob in");
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
    PRINT_HILOGI("PrintServiceStub::OnQueryPrintJobById in");
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
    PRINT_HILOGI("PrintServiceStub::OnAddPrinterToCups in");
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
    PRINT_HILOGI("PrintServiceStub::OnQueryPrinterCapabilityByUri in");
    PrinterCapability printerCaps;
    std::string printerUri = data.ReadString();
    std::string printerId = data.ReadString();
    int32_t ret = QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
    reply.WriteInt32(ret);
    printerCaps.Marshalling(reply);
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapabilityByUri out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnNotifyPrintServiceEvent(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnNotifyPrintServiceEvent in");
    std::string jobId = data.ReadString();
    uint32_t event = data.ReadUint32();
    PRINT_HILOGD("OnNotifyPrintServiceEvent jobId = %{public}s, event = %{public}d", jobId.c_str(), event);
    int32_t ret = NotifyPrintServiceEvent(jobId, event);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnNotifyPrintServiceEvent out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnSetDefaultPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnSetDefaultPrinter in");
    std::string printerId = data.ReadString();
    uint32_t type = data.ReadUint32();
    int32_t ret = SetDefaultPrinter(printerId, type);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnSetDefaultPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnDeletePrinterFromCups(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnDeletePrinterFromCups in");
    std::string printerName = data.ReadString();
    int32_t ret = DeletePrinterFromCups(printerName);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnDeletePrinterFromCups out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnDiscoverUsbPrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnDiscoverUsbPrinters in");
    std::vector<PrinterInfo> printers;
    int32_t ret = DiscoverUsbPrinters(printers);
    reply.WriteInt32(ret);
    if (ret == E_PRINT_NONE) {
        uint32_t size = static_cast<uint32_t>(printers.size());
        reply.WriteUint32(size);
        for (uint32_t index = 0; index < size; index++) {
            printers[index].Marshalling(reply);
        }
    }
    PRINT_HILOGD("PrintServiceStub::OnDiscoverUsbPrinters out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnEventOn(MessageParcel &data, MessageParcel &reply)
{
    std::string taskId = data.ReadString();
    std::string type = data.ReadString();
    PRINT_HILOGI("PrintServiceStub::OnEventOn type=%{public}s ", type.c_str());
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
    PRINT_HILOGI("PrintServiceStub::OnEventOff type=%{public}s ", type.c_str());
    int32_t ret = Off(taskId, type);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnEventOff out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRegisterPrinterCallback(MessageParcel &data, MessageParcel &reply)
{
    std::string type = data.ReadString();
    if (type.empty()) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn type is null.");
        reply.WriteInt32(E_PRINT_RPC_FAILURE);
        return false;
    }
    PRINT_HILOGI("PrintServiceStub::OnRegisterPrinterCallback type=%{public}s ", type.c_str());
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
    int32_t ret = RegisterPrinterCallback(type, listener);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnRegisterPrinterCallback out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUnregisterPrinterCallback(MessageParcel &data, MessageParcel &reply)
{
    std::string type = data.ReadString();
    if (type.empty()) {
        reply.WriteInt32(E_PRINT_RPC_FAILURE);
        return false;
    }
    PRINT_HILOGI("PrintServiceStub::OnUnregisterPrinterCallback type=%{public}s ", type.c_str());
    int32_t ret = UnregisterPrinterCallback(type);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUnregisterPrinterCallback out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRegisterExtCallback(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnRegisterExtCallback in");
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
    PRINT_HILOGI("PrintServiceStub::OnUnregisterAllExtCallback in");
    std::string extensionId = data.ReadString();
    int32_t ret = UnregisterAllExtCallback(extensionId);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnUnregisterAllExtCallback out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnLoadExtSuccess(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnLoadExtSuccess in");
    std::string extensionId = data.ReadString();
    int32_t ret = LoadExtSuccess(extensionId);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnLoadExtSuccess out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnPrintByAdapter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnPrintByAdapter in");
    int32_t ret = E_PRINT_RPC_FAILURE;
    std::string jobName = data.ReadString();
    auto attrs = PrintAttributes::Unmarshalling(data);
    std::string taskId = data.ReadString();
    if (attrs != nullptr) {
        attrs->Dump();
        ret = PrintByAdapter(jobName, *attrs, taskId);
    }
    reply.WriteInt32(ret);
    PRINT_HILOGI("PrintServiceStub::OnPrintByAdapter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStartGetPrintFile(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnStartGetPrintFile in");
    int32_t ret = E_PRINT_RPC_FAILURE;
    std::string jobId = data.ReadString();
    auto attrs = PrintAttributes::Unmarshalling(data);
    int32_t fd = data.ReadFileDescriptor();
    if (fd >= 0 && attrs != nullptr) {
        ret = StartGetPrintFile(jobId, *attrs, static_cast<uint32_t>(fd));
        close(fd);
    }
    reply.WriteInt32(ret);
    PRINT_HILOGI("PrintServiceStub::OnStartGetPrintFile out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnNotifyPrintService(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnNotifyPrintService in");
    std::string jobId = data.ReadString();
    std::string type = data.ReadString();
    PRINT_HILOGD(
        "PrintServiceStub::OnNotifyPrintService jobId=%{public}s type=%{public}s ", jobId.c_str(), type.c_str());
    int32_t ret = NotifyPrintService(jobId, type);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnNotifyPrintService out");
    return ret == E_PRINT_NONE;
}


bool PrintServiceStub::OnAddPrinterToDiscovery(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnAddPrinterToDiscovery in");
    auto infoPtr = PrinterInfo::Unmarshalling(data);
    if (infoPtr == nullptr) {
        PRINT_HILOGW("invalid printer object");
        reply.WriteInt32(E_PRINT_RPC_FAILURE);
        PRINT_HILOGD("PrintServiceStub::OnAddPrinterToDiscovery out with failure");
        return false;
    }
    infoPtr->Dump();
    int32_t ret = AddPrinterToDiscovery(*infoPtr);
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::OnAddPrinterToDiscovery out with ret = %{public}d", ret);
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdatePrinterInDiscovery(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnUpdatePrinterInDiscovery in");

    auto infoPtr = PrinterInfo::Unmarshalling(data);
    if (infoPtr == nullptr) {
        PRINT_HILOGE("Failed to unmarshall printer info");
        reply.WriteInt32(E_PRINT_RPC_FAILURE);
        return false;
    }

    infoPtr->Dump();
    int32_t ret = UpdatePrinterInDiscovery(*infoPtr);
    reply.WriteInt32(ret);

    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterInDiscovery out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRemovePrinterFromDiscovery(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnRemovePrinterFromDiscovery in");

    std::string printerId = data.ReadString();

    int32_t ret = RemovePrinterFromDiscovery(printerId);
    reply.WriteInt32(ret);

    PRINT_HILOGD("PrintServiceStub::OnRemovePrinterFromDiscovery out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdatePrinterInSystem(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnUpdatePrinterInSystem in");

    auto infoPtr = PrinterInfo::Unmarshalling(data);
    if (infoPtr == nullptr) {
        PRINT_HILOGE("Failed to unmarshall printer info");
        reply.WriteInt32(E_PRINT_RPC_FAILURE);
        return false;
    }

    infoPtr->Dump();
    int32_t ret = UpdatePrinterInSystem(*infoPtr);
    reply.WriteInt32(ret);

    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterInSystem out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRestartPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::RestartPrintJob in");
    int32_t ret = RestartPrintJob(data.ReadString());
    reply.WriteInt32(ret);
    PRINT_HILOGD("PrintServiceStub::RestartPrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnAnalyzePrintEvents(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::AnalyzePrintEvents in");
    std::string printerId = data.ReadString();
    std::string eventType = data.ReadString();
    std::string detail;
    int32_t ret = AnalyzePrintEvents(printerId, eventType, detail);
    reply.WriteInt32(ret);
    reply.WriteString(detail);
    PRINT_HILOGD("PrintServiceStub::AnalyzePrintEvents out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnAuthPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::AuthPrintJob in");
    std::string jobId = data.ReadString();
    std::string userName = data.ReadString();
    uint32_t userPasswdLength = data.ReadUint32();
    if (userPasswdLength == 0 || userPasswdLength > MAX_BUFFER_SIZE) {
        PRINT_HILOGE("userPasswdLength acquire fail.");
        return false;
    }
    const uint8_t *outData = data.ReadBuffer(userPasswdLength);

    char* userPasswd = new (std::nothrow) char[userPasswdLength];
    if (userPasswd == nullptr) {
        PRINT_HILOGE("Allocate Password fail.");
        return false;
    }

    auto memcpyRet = memcpy_s(userPasswd, userPasswdLength, outData, userPasswdLength);
    if (memcpyRet != E_PRINT_NONE) {
        PrintUtil::SafeDeleteAuthInfo(userPasswd);
        PRINT_HILOGE("memcpy_s failed, errorCode:[%{public}d]", memcpyRet);
        return false;
    }

    int32_t ret = AuthPrintJob(jobId, userName, userPasswd);
    reply.WriteInt32(ret);

    PrintUtil::SafeDeleteAuthInfo(userPasswd);

    PRINT_HILOGD("PrintServiceStub::AuthPrintJob out");
    return ret == E_PRINT_NONE;
}

} // namespace OHOS::Print
